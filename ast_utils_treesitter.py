import os
import textwrap
import tree_sitter as ts
import tree_sitter_python as tsp
import tree_sitter_javascript as tsjs

# ---------------------------------------------------------------------------
# Language Setup
# ---------------------------------------------------------------------------
PY_LANGUAGE = ts.Language(tsp.language())
JS_LANGUAGE = ts.Language(tsjs.language())


def _get_language(file_path: str) -> ts.Language:
    """Return the appropriate tree-sitter Language based on file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ('.py',):
        return PY_LANGUAGE
    elif ext in ('.js', '.mjs', '.cjs'):
        return JS_LANGUAGE
    else:
        raise ValueError(f"Unsupported file extension: {ext}")


def _parse_file(file_path: str):
    """Read and parse a file, returning (tree, code_bytes, code_lines)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code_lines = f.readlines()
    code_bytes = "".join(code_lines).encode('utf-8')

    lang = _get_language(file_path)
    parser = ts.Parser(lang)
    tree = parser.parse(code_bytes)
    return tree, code_bytes, code_lines


# ===========================================================================
#  PYTHON helpers
# ===========================================================================

def _find_python_node(root_node, line_number: int):
    """
    Walk the Python AST to find a function_definition or the
    `if __name__ == "__main__":` block that contains `line_number`.
    Returns (name, node) or (None, None).

    Handles plain functions, async functions, and decorated definitions
    (e.g. @app.route decorated Flask handlers).
    """
    for child in root_node.children:
        # Lines are 0-indexed in tree-sitter, our line_number is 1-indexed
        start = child.start_point[0] + 1
        end = child.end_point[0] + 1

        if not (start <= line_number <= end):
            continue

        # Check function / async function (undecorated)
        if child.type == 'function_definition':
            name_node = child.child_by_field_name('name')
            return (name_node.text.decode('utf-8') if name_node else None, child)

        # decorated_definition wraps @decorator + function_definition
        if child.type == 'decorated_definition':
            func_node = _first_child_of_type(child, 'function_definition')
            if func_node:
                name_node = func_node.child_by_field_name('name')
                return (name_node.text.decode('utf-8') if name_node else None, child)

        # Check `if __name__ == "__main__":` block
        if child.type == 'if_statement':
            if _is_python_main_block(child):
                return ('__main_block__', child)

    return None, None


def _is_python_main_block(node) -> bool:
    """Return True if this if_statement is `if __name__ == "__main__":`."""
    # The condition is a comparison_operator child
    for child in node.children:
        if child.type == 'comparison_operator':
            text = child.text.decode('utf-8')
            if '__name__' in text and '__main__' in text:
                return True
    return False


# ===========================================================================
#  JAVASCRIPT helpers
# ===========================================================================

def _find_js_node(root_node, line_number: int, code_bytes: bytes):
    """
    Walk the JS AST to find the enclosing construct around `line_number`.
    Supports:
      - function_declaration         → name from identifier
      - variable assignment of arrow / function expression  → name from var
      - Express-style route handlers (app.get / app.post …) → name = "METHOD /path"
    Returns (name, node) or (None, None).
    """
    for child in root_node.children:
        start = child.start_point[0] + 1
        end = child.end_point[0] + 1

        if not (start <= line_number <= end):
            continue

        # 1) function_declaration  →  function foo() { ... }
        if child.type == 'function_declaration':
            name_node = child.child_by_field_name('name')
            name = name_node.text.decode('utf-8') if name_node else '<anonymous>'
            return name, child

        # 2) lexical_declaration / variable_declaration  →  const foo = (...) => { ... }
        if child.type in ('lexical_declaration', 'variable_declaration'):
            declarator = _first_child_of_type(child, 'variable_declarator')
            if declarator:
                name_node = declarator.child_by_field_name('name')
                name = name_node.text.decode('utf-8') if name_node else '<anonymous>'
                return name, child

        # 3) expression_statement containing a call like app.get('/path', handler)
        if child.type == 'expression_statement':
            call = _first_child_of_type(child, 'call_expression')
            if call is None:
                # Could also be assignment_expression wrapping a call
                assignment = _first_child_of_type(child, 'assignment_expression')
                if assignment:
                    name_node = assignment.child_by_field_name('left')
                    name = name_node.text.decode('utf-8') if name_node else '<anonymous>'
                    return name, child
                continue

            member = _first_child_of_type(call, 'member_expression')
            if member:
                route_name = _extract_express_route_name(call, member)
                if route_name:
                    return route_name, child

                # Fallback: use the full member expression text
                return member.text.decode('utf-8'), child

            # Plain call expression  → use function name
            func_node = call.child_by_field_name('function')
            if func_node:
                return func_node.text.decode('utf-8'), child

    return None, None


def _first_child_of_type(node, type_name: str):
    """Return the first direct child of the given type, or None."""
    for c in node.children:
        if c.type == type_name:
            return c
    return None


def _extract_express_route_name(call_node, member_node) -> str | None:
    """
    If `call_node` looks like  app.get('/path', handler)  return "GET /path".
    Otherwise return None.
    """
    obj = _first_child_of_type(member_node, 'identifier')
    prop = _first_child_of_type(member_node, 'property_identifier')
    if not obj or not prop:
        return None

    method = prop.text.decode('utf-8')
    http_methods = {'get', 'post', 'put', 'delete', 'patch', 'use', 'all'}
    if method not in http_methods:
        return None

    # The first string argument is the route path
    args = _first_child_of_type(call_node, 'arguments')
    if args:
        for arg_child in args.children:
            if arg_child.type == 'string':
                # Strip the quotes from the path
                path = arg_child.text.decode('utf-8').strip("'\"")
                return f"{method.upper()} {path}"

    return f"{method.upper()} <unknown>"


# ===========================================================================
#  Public API  — drop-in replacements for ast_utils functions
# ===========================================================================

def extract_function_code(file_path: str, line_number: int):
    """
    Given a file path and a 1-indexed line number, return (name, source_code)
    of the enclosing function / block.  Works for both Python and JavaScript.

    Returns (None, None) if nothing suitable is found.
    """
    if not os.path.exists(file_path):
        return None, None

    try:
        tree, code_bytes, code_lines = _parse_file(file_path)
    except (ValueError, UnicodeDecodeError):
        return None, None

    ext = os.path.splitext(file_path)[1].lower()

    if ext in ('.py',):
        name, node = _find_python_node(tree.root_node, line_number)
    elif ext in ('.js', '.mjs', '.cjs'):
        name, node = _find_js_node(tree.root_node, line_number, code_bytes)
    else:
        return None, None

    if node is None:
        return None, None

    # Extract source lines (tree-sitter lines are 0-indexed)
    start = node.start_point[0]  # 0-indexed
    end = node.end_point[0] + 1  # exclusive
    return name, "".join(code_lines[start:end])


def apply_patch_to_file(file_path: str, function_name: str, new_code: str) -> bool:
    """
    Replace the source of the function/block identified by `function_name`
    with `new_code`.  Works for both Python and JavaScript.

    For Python:
      - function_name == "__main_block__" targets `if __name__ == "__main__":`.
      - Otherwise targets a `def / async def` with that name.

    For JavaScript:
      - Matches function declarations, const/let assignments, or Express
        route handler labels (e.g. "POST /login").

    Returns True on success, False on failure.
    """
    try:
        tree, code_bytes, code_lines = _parse_file(file_path)
    except (ValueError, UnicodeDecodeError, FileNotFoundError):
        print(f"Error: Could not parse {file_path}")
        return False

    ext = os.path.splitext(file_path)[1].lower()
    target_node = None

    if ext in ('.py',):
        target_node = _find_python_node_by_name(tree.root_node, function_name)
    elif ext in ('.js', '.mjs', '.cjs'):
        target_node = _find_js_node_by_name(tree.root_node, function_name, code_bytes)

    if target_node is None:
        print(f"Error: Target '{function_name}' not found in {file_path}")
        return False

    # --- Indentation handling (same logic as original ast_utils) ---
    start_line_idx = target_node.start_point[0]  # 0-indexed
    original_line = code_lines[start_line_idx]
    original_indent = original_line[:len(original_line) - len(original_line.lstrip())]

    dedented_code = textwrap.dedent(new_code).strip()
    new_code_lines = dedented_code.split('\n')
    final_code_lines = [original_indent + line + '\n' for line in new_code_lines]

    # --- Reconstruct file ---
    pre_content = code_lines[:target_node.start_point[0]]
    post_content = code_lines[target_node.end_point[0] + 1:]

    full_content = pre_content + final_code_lines + post_content

    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(full_content)

    return True


# ---------------------------------------------------------------------------
#  Node-by-name finders (used by apply_patch_to_file)
# ---------------------------------------------------------------------------

def _find_python_node_by_name(root_node, function_name: str):
    """Find a Python node by its function name (or __main_block__)."""
    for child in root_node.children:
        if function_name == '__main_block__':
            if child.type == 'if_statement' and _is_python_main_block(child):
                return child
        elif child.type == 'function_definition':
            name_node = child.child_by_field_name('name')
            if name_node and name_node.text.decode('utf-8') == function_name:
                return child
        elif child.type == 'decorated_definition':
            func_node = _first_child_of_type(child, 'function_definition')
            if func_node:
                name_node = func_node.child_by_field_name('name')
                if name_node and name_node.text.decode('utf-8') == function_name:
                    return child
    return None


def _find_js_node_by_name(root_node, function_name: str, code_bytes: bytes):
    """
    Find a JS node by its derived name.
    Supports the same naming scheme as _find_js_node:
      - Regular function declarations  (e.g. "regularFunc")
      - Variable-assigned functions     (e.g. "arrowFunc")
      - Express route labels            (e.g. "POST /login")
    """
    for child in root_node.children:
        # 1) function_declaration
        if child.type == 'function_declaration':
            name_node = child.child_by_field_name('name')
            if name_node and name_node.text.decode('utf-8') == function_name:
                return child

        # 2) lexical / variable declaration
        if child.type in ('lexical_declaration', 'variable_declaration'):
            declarator = _first_child_of_type(child, 'variable_declarator')
            if declarator:
                name_node = declarator.child_by_field_name('name')
                if name_node and name_node.text.decode('utf-8') == function_name:
                    return child

        # 3) expression_statement  → Express route or assignment
        if child.type == 'expression_statement':
            call = _first_child_of_type(child, 'call_expression')
            if call:
                member = _first_child_of_type(call, 'member_expression')
                if member:
                    route_name = _extract_express_route_name(call, member)
                    if route_name == function_name:
                        return child
                    # Also check full member text
                    if member.text.decode('utf-8') == function_name:
                        return child

            # assignment_expression
            assignment = _first_child_of_type(child, 'assignment_expression')
            if assignment:
                left = assignment.child_by_field_name('left')
                if left and left.text.decode('utf-8') == function_name:
                    return child

    return None

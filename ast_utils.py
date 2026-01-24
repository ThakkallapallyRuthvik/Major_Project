import ast
import os
import textwrap  # <--- NEW: To clean up AI indentation

def extract_function_code(file_path: str, line_number: int):
    # (This function allows us to find the code to send to the LLM)
    if not os.path.exists(file_path):
        return None, None

    with open(file_path, 'r', encoding='utf-8') as f:
        code_lines = f.readlines()
    
    code_string = "".join(code_lines)
    
    try:
        tree = ast.parse(code_string)
    except SyntaxError:
        return None, None

    target_node = None
    node_type = "function"

    for node in ast.walk(tree):
        # Check for standard functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                if node.lineno <= line_number <= node.end_lineno:
                    target_node = node
                    break
        
        # Check for 'if __name__ == "__main__":' blocks
        elif isinstance(node, ast.If):
            try:
                if (isinstance(node.test, ast.Compare) and 
                    isinstance(node.test.left, ast.Name) and 
                    node.test.left.id == "__name__" and 
                    node.test.comparators[0].value == "__main__"):
                    
                    if node.lineno <= line_number <= node.end_lineno:
                        target_node = node
                        node_type = "main_block"
                        break
            except AttributeError:
                continue

    if target_node:
        start = target_node.lineno - 1
        end = target_node.end_lineno
        name = target_node.name if node_type == "function" else "__main_block__"
        return name, "".join(code_lines[start:end])
        
    return None, None

def apply_patch_to_file(file_path: str, function_name: str, new_code: str) -> bool:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        tree = ast.parse("".join(lines))
        target_node = None
        
        # Search for the node to replace
        for node in ast.walk(tree):
            if function_name == "__main_block__":
                if (isinstance(node, ast.If) and 
                    isinstance(node.test, ast.Compare) and 
                    isinstance(node.test.left, ast.Name) and 
                    node.test.left.id == "__name__" and 
                    node.test.comparators[0].value == "__main__"):
                    target_node = node
                    break
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == function_name:
                    target_node = node
                    break
        
        if not target_node:
            print(f"Error: Target '{function_name}' not found in {file_path}")
            return False

        # 1. Get Original Indentation
        start_line_idx = target_node.lineno - 1
        original_indent = lines[start_line_idx][:len(lines[start_line_idx]) - len(lines[start_line_idx].lstrip())]
        
        # 2. Strip AI's random indentation (Dedent)
        dedented_code = textwrap.dedent(new_code).strip()
        
        # 3. Apply the CORRECT indentation
        new_code_lines = dedented_code.split('\n')
        final_code_lines = [original_indent + line + '\n' for line in new_code_lines]
        
        # 4. Reconstruction
        pre_content = lines[:target_node.lineno - 1]
        post_content = lines[target_node.end_lineno:]
        
        full_content = pre_content + final_code_lines + post_content
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(full_content)
            
        return True

    except Exception as e:
        print(f"Failed to patch file: {e}")
        return False
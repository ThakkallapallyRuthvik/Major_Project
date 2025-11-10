import ast
import inspect
from typing import Optional, Tuple

def extract_function_code(file_path: str, line_number: int) -> Optional[Tuple[str, str]]:
    """
    Reads a Python file, identifies the function definition containing the target line number,
    and returns the function name and its complete source code.
    
    Args:
        file_path: Path to the Python file (e.g., /tmp/temp_app.py).
        line_number: The line number where the vulnerability was found.
        
    Returns:
        A tuple (function_name, function_code) or None if no function is found.
    """
    try:
        with open(file_path, 'r') as f:
            code_lines = f.readlines()
            code_string = "".join(code_lines)
            tree = ast.parse(code_string)
            
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None
    except Exception as e:
        print(f"Error parsing file: {e}")
        return None

    target_node = None
    
    # 1. Traverse the AST to find the function node containing the line number
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Check if the target line is within the function's start and end line
            # ast lines are 1-based, like the line_number input
            if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                if node.lineno <= line_number <= node.end_lineno:
                    target_node = node
                    break
                    
    if target_node:
        # 2. Extract the code lines for the function
        start_line = target_node.lineno - 1 # Convert to 0-based index
        end_line = target_node.end_lineno # This is inclusive in AST (1-based), so slice goes up to this index
        
        function_code_lines = code_lines[start_line:end_line]
        
        # --- MODIFIED: REMOVE INDENTATION STRIPPING ---
        # We now return the code exactly as it is in the file.
        # This preserves the function signature and any imports required inside it.
        function_code = "".join(function_code_lines)

        return target_node.name, function_code.strip()
    
    return None
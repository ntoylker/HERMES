"""Utility functions for network operations, process management, and shell command execution."""

import json
import re
import subprocess
from typing import Any


def execute_shell_command(command: str, timeout: int = 30) -> dict[str, Any]:
    """Execute a shell command and return structured output.
    
    Args:
        command: The shell command to execute.
        timeout: Maximum time in seconds before the process is killed.
        
    Returns:
        A dictionary containing stdout, stderr, return code, and success status.
        
    Raises:
        subprocess.TimeoutExpired: If the command exceeds the timeout.
        subprocess.CalledProcessError: If the command returns a non-zero exit code.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "return_code": -1,
            "success": False,
        }


def parse_socket_address(address: str) -> dict[str, Any]:
    """Parse a socket address string into host and port components.
    
    Supports formats: 'host:port', '[ipv6]:port', 'host:port/path'.
    
    Args:
        address: A string representing a socket address (e.g., '192.168.1.1:443').
        
    Returns:
        A dictionary with keys: host, port, protocol, path.
        
    Raises:
        ValueError: If the address format is invalid.
    """
    if not isinstance(address, str):
        raise ValueError(f"Address must be a string, got {type(address).__name__}")
    
    address = address.strip()
    
    # Handle IPv6 addresses in brackets [::1]:8080
    ipv6_match = re.match(r"\[([^\]]+)\]:(\d+)(?:/(\S+))?", address)
    if ipv6_match:
        return {
            "host": ipv6_match.group(1),
            "port": int(ipv6_match.group(2)),
            "protocol": None,
            "path": ipv6_match.group(3) or "",
        }
    
    # Handle IPv4/hostname with optional protocol prefix (tcp://, udp://)
    protocol = ""
    if address.startswith("tcp://"):
        address = address[5:]
        protocol = "tcp"
    elif address.startswith("udp://"):
        address = address[5:]
        protocol = "udp"
    
    # Handle IPv4/hostname:port/path
    parts = address.split("/")
    host_port = parts[0]
    path = parts[1] if len(parts) > 1 else ""
    
    # Split host and port
    colon_idx = host_port.rfind(":")
    if colon_idx == -1:
        raise ValueError(f"Invalid socket address format: '{address}'")
    
    host = host_port[:colon_idx]
    try:
        port = int(host_port[colon_idx + 1:])
    except ValueError as e:
        raise ValueError(
            f"Invalid port number in address '{address}': {e}"
        ) from e
    
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "path": path,
    }


def format_response(data: Any) -> str:
    """Format data as a JSON string with proper indentation.
    
    Args:
        data: The data to serialize to JSON.
        
    Returns:
        A formatted JSON string.
        
    Raises:
        TypeError: If the input is not serializable.
    """
    try:
        return json.dumps(data, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Failed to serialize data: {e}") from e


def safe_eval(expression: str) -> Any:
    """Safely evaluate a shell output expression without arbitrary code execution.
    
    Uses a restricted set of builtins and operators to prevent injection attacks.
    Only allows numeric operations, string concatenation, and basic comparisons.
    
    Args:
        expression: A string representing an arithmetic or comparison expression.
        
    Returns:
        The evaluated result as the appropriate Python type.
        
    Raises:
        ValueError: If the expression is not valid or cannot be safely evaluated.
    """
    if not isinstance(expression, str):
        raise TypeError(f"Expression must be a string, got {type(expression).__name__}")
    
    # Define allowed builtins (minimal safe set)
    allowed_builtins = {
        "len": len,
        "str": str,
        "int": int,
        "float": float,
        "bool": bool,
        "repr": repr,
        "type": type,
        "isinstance": isinstance,
    }
    
    # Define allowed operators and functions via regex pattern
    safe_pattern = r"""
        (?:
            [a-zA-Z_][a-zA-Z0-9_]*           # identifier
            | \d+                            # integer literal
            | \d+\.\d+                       # float literal
            | ".*?"                         # double-quoted string
            | '.{1,2}'                      # single-quoted string (escape handling)
            | True|False|None               # literals
        )
    """
    
    # Tokenize the expression
    tokens = []
    i = 0
    while i < len(expression):
        if expression[i].isspace():
            i += 1
            continue
        
        # Check for operators
        op = ""
        while i < len(expression) and expression[i] in "+-*/%<>=!&|~":
            op += expression[i]
            i += 1
        if op:
            tokens.append(("OP", op))
            continue
        
        # Check for parentheses
        if expression[i] == "(":
            tokens.append(("LPAREN", "("))
            i += 1
        elif expression[i] == ")":
            tokens.append(("RPAREN", ")"))
            i += 1
        else:
            # Parse identifier or number
            start = i
            while i < len(expression) and (expression[i].isalnum() or expression[i] in "_"):
                i += 1
            token_str = expression[start:i]
            
            if token_str.isdigit():
                tokens.append(("NUM", int(token_str)))
            elif "." in token_str:
                tokens.append(("FLOAT", float(token_str)))
            else:
                tokens.append(("NAME", token_str))
    
    # Build AST using a simple recursive descent parser
    def parse_expr(tokens: list[tuple[str, Any]]) -> tuple[str, Any]:
        """Parse expression with precedence: * / % > + -."""
        return parse_additive(tokens)
    
    def parse_additive(tokens: list[tuple[str, Any]]) -> tuple[str, Any]:
        result = parse_multiplicative(tokens)
        while tokens and tokens[0][0] == "OP" and tokens[0][1] in ("+", "-"):
            op = tokens.pop(0)[1]
            right = parse_multiplicative(tokens)
            if op == "+":
                result = ("ADD", result, right)
            else:
                result = ("SUB", result, right)
        return result

    def parse_multiplicative(tokens: list[tuple[str, Any]]) -> tuple[str, Any]:
        result = parse_primary(tokens)
        while tokens and tokens[0][0] == "OP" and tokens[0][1] in ("*", "/", "%"):
            op = tokens.pop(0)[1]
            right = parse_primary(tokens)
            if op == "*":
                result = ("MUL", result, right)
            elif op == "/":
                result = ("DIV", result, right)
            else:
                result = ("MOD", result, right)
        return result
    
    def parse_primary(tokens: list[tuple[str, Any]]) -> tuple[str, Any]:
        if not tokens:
            raise ValueError("Unexpected end of expression")
        
        token_type, value = tokens.pop(0)
        
        if token_type == "NUM":
            return ("NUM", value)
        elif token_type == "FLOAT":
            return ("FLOAT", value)
        elif token_type == "NAME":
            # Check if it's a keyword or identifier
            keywords = {"and", "or", "not", "in", "is"}
            if value in keywords:
                raise ValueError(f"Keyword '{value}' not supported")
            return ("NAME", value)
        elif token_type == "LPAREN":
            result = parse_expr(tokens)
            if tokens and tokens[0][0] == "RPAREN":
                tokens.pop(0)  # consume ')'
            return result
    
    try:
        ast = parse_expr(tokens)
    except (ValueError, IndexError) as e:
        raise ValueError(f"Failed to evaluate expression '{expression}': {e}") from e
    
    # Evaluate the AST safely
    def eval_ast(ast_node: tuple[str, Any]) -> Any:
        # Unary nodes are 2-tuples (type, value); binary-op nodes are 3-tuples
        # (type, left_node, right_node) — don't assume a uniform 2-tuple shape.
        node_type = ast_node[0]

        if node_type == "NUM":
            return ast_node[1]
        elif node_type == "FLOAT":
            return ast_node[1]
        elif node_type == "NAME":
            value = ast_node[1]
            # Only allow names that are in allowed_builtins or are numeric identifiers
            if value in allowed_builtins:
                return allowed_builtins[value]
            try:
                return int(value)
            except ValueError:
                raise ValueError(
                    f"Unknown identifier '{value}' not found in safe context"
                ) from None
        elif node_type == "ADD":
            left, right = eval_ast(ast_node[1]), eval_ast(ast_node[2])
            return left + right
        elif node_type == "SUB":
            left, right = eval_ast(ast_node[1]), eval_ast(ast_node[2])
            return left - right
        elif node_type == "MUL":
            left, right = eval_ast(ast_node[1]), eval_ast(ast_node[2])
            return left * right
        elif node_type == "DIV":
            left, right = eval_ast(ast_node[1]), eval_ast(ast_node[2])
            if right == 0:
                raise ZeroDivisionError("Division by zero")
            return left / right
        elif node_type == "MOD":
            left, right = eval_ast(ast_node[1]), eval_ast(ast_node[2])
            if right == 0:
                raise ZeroDivisionError("Modulo by zero")
            return left % right
    
    result = eval_ast(ast)
    
    # Ensure the result is a simple type (no objects/functions returned)
    if isinstance(result, (dict, list, tuple)):
        raise ValueError(
            f"Expression '{expression}' evaluated to complex object: {type(result).__name__}"
        )
    
    return result


if __name__ == "__main__":
    # Demo usage
    print("=== execute_shell_command ===")
    result = execute_shell_command("echo 'Hello, World!' | wc -w")
    print(f"stdout: {result['stdout']}")
    print(f"return_code: {result['return_code']}")
    
    print("\n=== parse_socket_address ===")
    addr = "192.168.1.100:443/tcp"
    parsed = parse_socket_address(addr)
    print(f"Parsed '{addr}': {parsed}")
    
    addr_v6 = "[::1]:8080/path/to/service"
    parsed_v6 = parse_socket_address(addr_v6)
    print(f"Parsed '{addr_v6}': {parsed_v6}")
    
    print("\n=== format_response ===")
    data = {"status": "ok", "count": 42, "items": [1, 2, 3]}
    formatted = format_response(data)
    print(formatted)
    
    print("\n=== safe_eval ===")
    expr = "(5 + 3) * (10 - 2)"
    result = safe_eval(expr)
    print(f"'{expr}' = {result}")
    
    expr_str = "len('hello') + str(42)"
    result_str = safe_eval(expr_str)
    print(f"'{expr_str}' = '{result_str}'")

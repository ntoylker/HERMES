import subprocess
import socket
import json
import ast
from typing import Optional, Tuple


class ExecutionResult:
    """Container for shell command execution results."""
    
    def __init__(self, success: bool, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
    
    def to_dict(self) -> dict[str, object]:
        """Convert execution result to dictionary for JSON serialization."""
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "returncode": self.returncode
        }


def execute_shell_command(command: str, timeout: int = 30) -> ExecutionResult:
    """Execute a shell command and capture output.
    
    Args:
        command: The shell command to execute.
        timeout: Maximum time in seconds before killing the process (default: 30).
        
    Returns:
        ExecutionResult containing stdout, stderr, returncode, and success flag.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return ExecutionResult(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(success=False, stdout="", stderr="Command timed out", returncode=-1)
    except FileNotFoundError as e:
        return ExecutionResult(success=False, stdout="", stderr=str(e), returncode=127)
    except Exception as e:
        return ExecutionResult(success=False, stdout="", stderr=f"Execution error: {e}", returncode=-1)


def parse_socket_address(address: str) -> Tuple[str, int]:
    """Parse a socket address string into host and port components.
    
    Handles both IPv4 (host:port) and IPv6 ([host]:port) formats.
    
    Args:
        address: Socket address in format 'host:port' or '[ipv6_host]:port'.
        
    Returns:
        Tuple of (host, port) where host is a string and port is an integer.
        
    Raises:
        ValueError: If the address format is invalid.
    """
    if not address:
        raise ValueError("Empty address provided")
    
    # Handle IPv6 format [host]:port
    if address.startswith('['):
        bracket_end = address.rfind(']')
        if bracket_end == -1:
            raise ValueError(f"Invalid IPv6 address format: {address}")
        host = address[1:bracket_end]
        port_str = address[bracket_end + 1:]
    else:
        # Handle IPv4 or hostname:port
        colon_index = address.rfind(':')
        if colon_index == -1:
            raise ValueError(f"Invalid address format (missing port): {address}")
        host = address[:colon_index]
        port_str = address[colon_index + 1:]
    
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port number: {port_str}")
    
    if not (0 <= port <= 65535):
        raise ValueError(f"Port out of range: {port}")
    
    return host, port


def format_response(data: dict[str, object]) -> str:
    """Format a dictionary as a JSON string for wire transmission.
    
    Args:
        data: Dictionary to serialize.
        
    Returns:
        JSON-formatted string with consistent formatting (2-space indent).
    """
    return json.dumps(data, indent=2, ensure_ascii=False)


def safe_eval(expression: str) -> object:
    """Safely evaluate a string expression using ast.literal_eval.
    
    Only allows literals (strings, numbers, tuples, lists, dicts, booleans, None).
    Prevents arbitrary code execution unlike eval().
    
    Args:
        expression: String to parse and convert to Python object.
        
    Returns:
        The evaluated Python object.
        
    Raises:
        ValueError: If the expression cannot be safely parsed.
    """
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Failed to parse expression '{expression}': {e}")


__all__ = [
    "ExecutionResult",
    "execute_shell_command",
    "parse_socket_address",
    "format_response",
    "safe_eval"
]

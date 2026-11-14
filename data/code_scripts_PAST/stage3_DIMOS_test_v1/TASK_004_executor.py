"""Shell command executor for handling incoming client commands via Unix Shell."""
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecutionResult:
    """Structured result of a shell command execution.
    
    Attributes:
        command: The original command that was executed.
        stdout: Standard output from the spawned process.
        stderr: Standard error from the spawned process.
        return_code: Exit code returned by the process.
        success: Boolean indicating if the command succeeded (return_code == 0).
        timed_out: Boolean indicating if the execution exceeded the timeout.
    """
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    success: bool = False
    timed_out: bool = False


class CommandExecutor:
    """Executes shell commands from connected clients via Unix Shell using subprocess.Popen.
    
    Implements a timeout mechanism (30s default) and captures stdout/stderr
    from spawned processes, returning structured ExecutionResult objects.
    
    ATT&CK Technique: T1059.004 - Command and Scripting Interpreter: Unix Shell
    
    Attributes:
        timeout_seconds: Default timeout in seconds for command execution.
    """

    DEFAULT_TIMEOUT = 30

    def __init__(self, timeout_seconds: int = 30):
        self.timeout_seconds = timeout_seconds

    def execute(self, command: str) -> ExecutionResult:
        """Execute a shell command and return structured results.
        
        Args:
            command: The shell command to execute.
            
        Returns:
            An ExecutionResult object containing stdout, stderr, return code,
            success status, and timeout information.
            
        Raises:
            subprocess.TimeoutExpired: If the command exceeds the timeout.
            subprocess.CalledProcessError: If the command returns a non-zero exit code.
        """
        result = ExecutionResult(command=command)

        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            stdout, stderr = proc.communicate(timeout=self.timeout_seconds)
            result.stdout = stdout.strip() if stdout else ""
            result.stderr = stderr.strip() if stderr else ""
            result.return_code = proc.returncode
            
        except subprocess.TimeoutExpired as e:
            result.timed_out = True
            result.return_code = -1
            # Try to get partial output before timeout
            try:
                stdout, stderr = proc.communicate(timeout=2)
                result.stdout = stdout.strip() if stdout else ""
                result.stderr = stderr.strip() if stderr else ""
            except Exception:
                pass
            
        except subprocess.CalledProcessError as e:
            result.return_code = e.returncode
            result.success = False
            
        except FileNotFoundError as e:
            result.stderr = f"Command not found: {e}"
            result.return_code = 127
            result.success = False
            
        except Exception as e:
            result.stderr = str(e)
            result.return_code = -1
            result.success = False

        result.success = (result.return_code == 0 and not result.timed_out)
        
        return result

    def execute_with_timeout(self, command: str, timeout: int | None = None) -> ExecutionResult:
        """Execute a shell command with a custom or default timeout.
        
        Args:
            command: The shell command to execute.
            timeout: Optional custom timeout in seconds. Defaults to DEFAULT_TIMEOUT.
            
        Returns:
            An ExecutionResult object.
        """
        effective_timeout = timeout if timeout is not None else self.timeout_seconds
        return self.execute(command)

    def parse_socket_address(self, address: str) -> dict[str, Any]:
        """Parse a socket address string into host and port components.
        
        Supports formats: 'host:port', '[ipv6]:port', 'host:port/path'.
        
        Args:
            address: A string representing a socket address (e.g., '192.168.1.1:443').
            
        Returns:
            A dictionary with keys: host, port, protocol, path.
            
        Raises:
            ValueError: If the address format is invalid.
        """
        # Import from TASK_002_utils as specified in the task
        from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import parse_socket_address as _parse
        
        return _parse(address)

    def execute_shell_command(self, command: str, timeout: int = 30) -> dict[str, Any]:
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
        # Import from TASK_002_utils as specified in the task
        from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import execute_shell_command as _execute
        
        return _execute(command, timeout)

    def format_response(self, data: Any) -> str:
        """Format data as a JSON string with proper indentation.
        
        Args:
            data: The data to serialize to JSON.
            
        Returns:
            A formatted JSON string.
            
        Raises:
            TypeError: If the input is not serializable.
        """
        # Import from TASK_002_utils as specified in the task
        from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import format_response as _format
        
        return _format(data)

    def safe_eval(self, expression: str) -> Any:
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
        # Import from TASK_002_utils as specified in the task
        from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import safe_eval as _safe_eval
        
        return _safe_eval(expression)


def main() -> None:
    """Demonstrate CommandExecutor functionality."""
    executor = CommandExecutor(timeout_seconds=30)

    # Test basic command execution
    result = executor.execute("echo 'Hello, World!' | wc -w")
    print(f"Command: {result.command}")
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
    print(f"return_code: {result.return_code}")
    print(f"success: {result.success}")
    print()

    # Test timeout scenario
    result = executor.execute("sleep 10")
    print(f"Timed out: {result.timed_out}")
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
    print()

    # Test parse_socket_address
    addr = '192.168.1.100:443/tcp'
    parsed = executor.parse_socket_address(addr)
    print(f"Parsed '{addr}': {parsed}")
    
    addr_v6 = '[::1]:8080/path/to/service'
    parsed_v6 = executor.parse_socket_address(addr_v6)
    print(f"Parsed '{addr_v6}': {parsed_v6}")
    print()

    # Test format_response
    data = {'status': 'ok', 'count': 42, 'items': [1, 2, 3]}
    formatted = executor.format_response(data)
    print(f"Formatted: {formatted}")
    print()

    # Test safe_eval
    expr = '(5 + 3) * (10 - 2)'
    result = executor.safe_eval(expr)
    print(f"'{expr}' = {result}")
    
    expr_str = "len('hello') + str(42)"
    result_str = executor.safe_eval(expr_str)
    print(f"'{expr_str}' = '{result_str}'")


if __name__ == '__main__':
    main()

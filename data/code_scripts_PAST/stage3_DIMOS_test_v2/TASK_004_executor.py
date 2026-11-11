import subprocess
from typing import Optional


from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_002_utils import ExecutionResult, execute_shell_command, parse_socket_address


class CommandExecutor:
    """Executes shell commands on the target system via Unix Shell (T1059.004).
    
    Handles incoming shell commands from connected clients and executes them
    using subprocess.Popen with proper stream capture and timeout handling.
    """

    DEFAULT_TIMEOUT = 30

    def __init__(self, host: str = "localhost", port: int = 22):
        """Initialize the command executor.
        
        Args:
            host: Target system hostname or IP address.
            port: SSH connection port (default 22).
        """
        self.host = host
        self.port = port

    def execute(self, command: str) -> ExecutionResult:
        """Execute a shell command on the target system.
        
        Args:
            command: The shell command to execute.
            
        Returns:
            ExecutionResult containing stdout, stderr, returncode, and success flag.
        """
        result = execute_shell_command(command, timeout=self.DEFAULT_TIMEOUT)
        return result

    def execute_with_timeout(self, command: str, timeout: int = 30) -> ExecutionResult:
        """Execute a shell command with custom timeout.
        
        Args:
            command: The shell command to execute.
            timeout: Maximum time in seconds before killing the process (default: 30).
            
        Returns:
            ExecutionResult containing stdout, stderr, returncode, and success flag.
        """
        result = execute_shell_command(command, timeout=timeout)
        return result

    def run_interactive(self, command: str) -> Optional[ExecutionResult]:
        """Run a command interactively with stream capture.
        
        Args:
            command: The shell command to execute.
            
        Returns:
            ExecutionResult or None if interactive mode is not supported.
        """
        return self.execute(command)

    def run_with_parsing(self, command: str) -> Optional[ExecutionResult]:
        """Execute a command and parse the result for structured output.
        
        Args:
            command: The shell command to execute.
            
        Returns:
            ExecutionResult or None if parsing fails.
        """
        try:
            result = self.execute(command)
            return result
        except Exception as e:
            error_result = ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                returncode=-1
            )
            return error_result


def execute_command(host: str, port: int, command: str, timeout: int = 30) -> ExecutionResult:
    """Execute a shell command on a remote target system.
    
    Args:
        host: Target system hostname or IP address.
        port: SSH connection port (default 22).
        command: The shell command to execute.
        timeout: Maximum time in seconds before killing the process (default: 30).
        
    Returns:
        ExecutionResult containing stdout, stderr, returncode, and success flag.
    """
    executor = CommandExecutor(host=host, port=port)
    return executor.execute(command)


def execute_command_with_timeout(
    host: str,
    port: int,
    command: str,
    timeout: int = 30
) -> ExecutionResult:
    """Execute a shell command with custom timeout on remote target.
    
    Args:
        host: Target system hostname or IP address.
        port: SSH connection port (default 22).
        command: The shell command to execute.
        timeout: Maximum time in seconds before killing the process (default: 30).
        
    Returns:
        ExecutionResult containing stdout, stderr, returncode, and success flag.
    """
    executor = CommandExecutor(host=host, port=port)
    return executor.execute_with_timeout(command, timeout=timeout)


def run_command(
    host: str,
    port: int,
    command: str,
    timeout: Optional[int] = None
) -> ExecutionResult:
    """Run a shell command on the target system.
    
    Args:
        host: Target system hostname or IP address.
        port: SSH connection port (default 22).
        command: The shell command to execute.
        timeout: Maximum time in seconds before killing the process (default: 30).
        
    Returns:
        ExecutionResult containing stdout, stderr, returncode, and success flag.
    """
    if timeout is None:
        timeout = CommandExecutor.DEFAULT_TIMEOUT
    
    executor = CommandExecutor(host=host, port=port)
    return executor.execute_with_timeout(command, timeout=timeout)


def execute_shell_command_on_target(
    host: str,
    port: int,
    command: str,
    timeout: Optional[int] = None
) -> ExecutionResult:
    """Execute a shell command on the target system via Unix Shell.
    
    Args:
        host: Target system hostname or IP address.
        port: SSH connection port (default 22).
        command: The shell command to execute.
        timeout: Maximum time in seconds before killing the process (default: 30).
        
    Returns:
        ExecutionResult containing stdout, stderr, returncode, and success flag.
    """
    if timeout is None:
        timeout = CommandExecutor.DEFAULT_TIMEOUT
    
    executor = CommandExecutor(host=host, port=port)
    result = executor.execute_with_timeout(command, timeout=timeout)
    return result


__all__ = [
    'CommandExecutor',
    'ExecutionResult',
    'execute_command',
    'execute_command_with_timeout',
    'run_command',
    'execute_shell_command_on_target'
]

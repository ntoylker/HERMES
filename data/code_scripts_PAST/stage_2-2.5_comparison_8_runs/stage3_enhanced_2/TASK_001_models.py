"""Data models for the reverse shell system."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResult:
    """Represents the result of executing a command in the reverse shell context.
    
    Attributes:
        stdout: Text output from standard output stream.
        stderr: Text output from standard error stream.
        exit_code: Integer exit code returned by the executed process.
        error_message: String describing any errors encountered during execution.
    """
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error_message: str = ""


@dataclass(frozen=True)
class ReverseShellConfig:
    """Configuration parameters for the reverse shell listener.
    
    Attributes:
        host: The IP address or hostname to bind the listener to.
        port: The TCP port on which to listen for incoming connections.
        timeout: Connection timeout in seconds before closing idle sockets.
        shell_type: The type of shell to spawn (e.g., 'bash' or 'cmd.exe').
    """
    host: str = "0.0.0.0"
    port: int = 5522
    timeout: float = 30.0
    shell_type: str = "bash"


__all__ = ["ExecutionResult", "ReverseShellConfig"]

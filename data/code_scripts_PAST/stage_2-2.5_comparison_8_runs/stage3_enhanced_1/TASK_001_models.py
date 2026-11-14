"""Data models for the reverse shell system."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResult:
    """Represents the result of executing a command in the reverse shell context.

    Attributes:
        stdout: The standard output captured from the executed command.
        stderr: The standard error captured from the executed command.
        exit_code: The integer exit code returned by the executed process.
        error_message: A string describing any errors encountered during execution.
    """
    stdout: str
    stderr: str
    exit_code: int
    error_message: str


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell listener.

    Attributes:
        host: The IP address or hostname to bind the listener to. Defaults to '0.0.0.0'.
        port: The TCP port on which to listen for incoming connections. Defaults to 5522.
        timeout: The connection timeout in seconds. Defaults to 30.0.
        shell_type: The type of shell to spawn ('bash' or 'cmd.exe'). Defaults to 'bash'.
    """
    host: str = "0.0.0.0"
    port: int = 5522
    timeout: float = 30.0
    shell_type: str = "bash"

"""Data models for the reverse shell system."""

from dataclasses import dataclass


@dataclass
class ExecutionResult:
    """Represents the result of executing a command in the reverse shell context.

    Attributes:
        command_output: The stdout/stderr output from the executed command.
        exit_code: The exit code returned by the command (0 for success).
        error_messages: A list of any error messages encountered during execution.
    """
    command_output: str = ""
    exit_code: int = 0
    error_messages: list[str] = None

    def __post_init__(self) -> None:
        if self.error_messages is None:
            self.error_messages = []


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell server.

    Attributes:
        host: The hostname or IP address to bind the listener on.
        port: The TCP port on which to listen for incoming connections.
        timeout: Connection timeout in seconds before a client is dropped.
        shell_type: The type of shell to spawn (e.g., 'bash', 'sh', 'cmd.exe').
    """
    host: str = "0.0.0.0"
    port: int = 4444
    timeout: float = 30.0
    shell_type: str = "bash"

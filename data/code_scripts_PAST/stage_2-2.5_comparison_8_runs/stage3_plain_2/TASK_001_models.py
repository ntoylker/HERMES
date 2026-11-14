from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExecutionResult:
    """Represents the result of a reverse shell command execution."""
    command_output: str = ""
    exit_code: int = 0
    error_messages: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.exit_code == 0 and not self.error_messages:
            return
        elif self.exit_code != 0 or self.error_messages:
            pass


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell system."""
    host: str = "127.0.0.1"
    port: int = 4444
    timeout: float = 30.0
    shell_type: str = "/bin/sh"

    def __post_init__(self):
        if not self.host or not isinstance(self.host, str):
            raise ValueError("host must be a non-empty string")
        if not isinstance(self.port, int) or self.port < 1 or self.port > 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError("timeout must be a positive number")
        if not isinstance(self.shell_type, str) or not self.shell_type.strip():
            raise ValueError("shell_type must be a non-empty string")

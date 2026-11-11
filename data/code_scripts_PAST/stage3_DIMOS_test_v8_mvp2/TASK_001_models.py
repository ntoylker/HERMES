from dataclasses import dataclass, field
from typing import List


@dataclass
class ExecutionResult:
    """Represents the result of a reverse shell command execution."""
    command_output: str = ""
    exit_code: int = 0
    error_messages: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (f"ExecutionResult(exit_code={self.exit_code}, "
                f"output='{self.command_output[:50]}...', "
                f"errors={len(self.error_messages)})")


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell system."""
    host: str = "127.0.0.1"
    port: int = 4444
    timeout: float = 30.0
    shell_type: str = "bash"

    def __repr__(self) -> str:
        return (f"ReverseShellConfig(host={self.host}, "
                f"port={self.port}, timeout={self.timeout}s, "
                f"shell_type='{self.shell_type}')")


__all__ = ["ExecutionResult", "ReverseShellConfig"]

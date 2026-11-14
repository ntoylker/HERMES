import dataclasses
import sys


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    """Represents the result of a command execution in the reverse shell system.
    
    Captures stdout, stderr, exit code, and any error messages from a completed
    subprocess or shell session. This is an immutable snapshot of execution state.
    """
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error_message: str = ""


@dataclasses.dataclass(frozen=True)
class ReverseShellConfig:
    """Configuration parameters for the reverse shell listener/server.
    
    Defines how the reverse shell binds and operates on the network layer.
    Defaults are set to Unix conventions; shell_type adapts based on platform.
    """
    host: str = "0.0.0.0"
    port: int = 5522
    timeout: float = 30.0
    shell_type: str = dataclasses.field(
        default_factory=lambda: "bash" if sys.platform != "win32" else "cmd.exe"
    )


__all__ = ["ExecutionResult", "ReverseShellConfig"]

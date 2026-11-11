from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionInfo:
    """Represents connection information for a shell session."""
    host: str
    port: int
    protocol: str = "ssh"


@dataclass(frozen=True)
class ShellCommand:
    """Represents a shell command to be executed remotely."""
    command: str
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class ExecutionResult:
    """Represents the result of executing a shell command."""
    stdout: str
    stderr: str
    return_code: int
    duration_ms: float

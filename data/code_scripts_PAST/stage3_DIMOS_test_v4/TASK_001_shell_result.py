from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionInfo:
    """Connection metadata for shell command execution."""
    host: str
    port: int
    protocol: str = "tcp"


@dataclass(frozen=True)
class ShellCommand:
    """Represents a shell command to be executed remotely."""
    command: str
    timeout_seconds: float


@dataclass(frozen=True)
class ExecutionResult:
    """Captured output and metadata from a shell command execution.

    Attributes:
        stdout: Captured standard output as bytes.
        stderr: Captured standard error as bytes.
        return_code: Exit code of the executed process (0-255).
        duration_ms: Total execution time including I/O overhead in milliseconds.
    """
    stdout: bytes
    stderr: bytes
    return_code: int
    duration_ms: int

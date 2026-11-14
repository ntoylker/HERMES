from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ListenerConfig:
    """Configuration for the reverse shell listener."""
    host: str = "0.0.0.0"
    port: int = 4444
    timeout: float = 30.0
    bind_address: Optional[str] = None


@dataclass(frozen=True)
class ExecutionResult:
    """Typed execution results for a reverse shell command."""
    command: str
    output: str
    status: int
    duration_ms: float
    exit_code: int = 0
    stderr: str = ""


@dataclass(frozen=True)
class ShellSession:
    """A complete shell session tying together configuration and execution results."""
    config: ListenerConfig
    command: str
    output: str
    status: int
    duration_ms: float
    exit_code: int = 0
    stderr: str = ""

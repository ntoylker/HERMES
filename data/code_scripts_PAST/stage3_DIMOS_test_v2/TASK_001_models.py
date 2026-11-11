from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SocketAddress:
    """Represents a network socket address (host and port)."""
    host: str
    port: int


@dataclass(frozen=True)
class ReverseShellConfig:
    """Immutable configuration for the reverse shell system.
    
    Defines the bind address and port that all downstream components
    consume as their single source of truth.
    """
    bind_address: SocketAddress = field(default_factory=lambda: SocketAddress(host="0.0.0.0", port=5522))
    port: int = 5522


@dataclass(frozen=True)
class CommandHandler:
    """Metadata for command execution within the reverse shell."""
    name: str
    description: Optional[str] = None
    timeout_seconds: float = field(default_factory=lambda: 30.0)
    max_output_bytes: int = field(default_factory=lambda: 1024 * 1024)


@dataclass(frozen=True)
class SessionState:
    """Runtime session state for a connected reverse shell client."""
    session_id: str
    client_address: SocketAddress
    commands_executed: list[str] = field(default_factory=list)
    output_buffer: list[str] = field(default_factory=list)
    is_active: bool = True

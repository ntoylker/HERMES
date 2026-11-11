"""Data models for the reverse shell system."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SocketAddress:
    """Represents a socket binding address configuration."""
    host: str = "0.0.0.0"
    port: int = 5522
    family: str = "AF_INET"
    protocol: str = "TCP"


@dataclass(frozen=True)
class ReverseShellConfig:
    """Immutable configuration for the reverse shell system."""
    bind_address: SocketAddress = field(default_factory=SocketAddress)
    listen_timeout: float = 30.0
    max_connections: int = 100
    command_timeout: float = 60.0
    encoding: str = "utf-8"
    log_level: str = "INFO"


@dataclass(frozen=True)
class CommandHandler:
    """Handles command execution metadata and routing."""
    name: str
    description: str
    timeout: float = 60.0
    max_output_size: int = field(default_factory=lambda: 1024 * 1024)
    allowed_args: Optional[list[str]] = None
    required_env: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SessionState:
    """Tracks the state of a reverse shell session."""
    session_id: str
    connected: bool = False
    active: bool = True
    command_queue: list[CommandHandler] = field(default_factory=list)
    output_buffer: list[str] = field(default_factory=list)
    last_activity: Optional[float] = None

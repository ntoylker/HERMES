"""Data models for the reverse shell system."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ExecutionResult:
    """Represents the result of a command execution in the reverse shell system.
    
    Attributes:
        command_output: The stdout/stderr output from the executed command.
        exit_code: The exit code returned by the command (0 for success).
        error_messages: List of any error messages encountered during execution.
    """
    command_output: str = ""
    exit_code: int = 0
    error_messages: List[str] = field(default_factory=list)


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell system.
    
    Attributes:
        host: The target host address to connect to (IP or hostname).
        port: The TCP port on the target host to listen on.
        timeout: Connection timeout in seconds before giving up.
        shell_type: The type of shell to spawn ('bash', 'sh', 'cmd.exe', etc.).
    """
    host: str = "127.0.0.1"
    port: int = 4444
    timeout: float = 30.0
    shell_type: str = "bash"

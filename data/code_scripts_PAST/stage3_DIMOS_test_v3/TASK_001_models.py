from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ExecutionResult:
    """Encapsulates the output of shell command execution."""
    
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    command: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

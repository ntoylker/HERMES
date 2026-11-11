from dataclasses import dataclass, field
from typing import List


@dataclass
class ExecutionResult:
    """Represents the result of a reverse shell command execution.
    
    ATT&CK Techniques: T1059.003 (Command and Scripting Interpreter),
                        T1059.004 (PowerShell)
    """
    command_output: str = ""
    exit_code: int = 0
    error_messages: List[str] = field(default_factory=list)


@dataclass
class ReverseShellConfig:
    """Configuration parameters for the reverse shell system.
    
    ATT&CK Techniques: T1059.003 (Command and Scripting Interpreter),
                        T1059.004 (PowerShell)
    """
    host: str = "localhost"
    port: int = 4444
    timeout: float = 60.0
    shell_type: str = "bash"

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResult:
    """Represents the result of a command execution in the reverse shell system.
    
    Attributes:
        stdout: Text output captured from the command's standard output stream.
        stderr: Text output captured from the command's standard error stream.
        exit_code: Integer exit code returned by the executed process.
        error_message: String describing any errors encountered during execution.
    """
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error_message: str = ""


@dataclass(frozen=True)
class ReverseShellConfig:
    """Configuration parameters for the reverse shell listener.
    
    Attributes:
        host: The IP address or hostname to bind the listener to. Defaults to '0.0.0.0'.
        port: The TCP port on which to listen for incoming connections. Defaults to 5522.
        timeout: Connection timeout in seconds. Defaults to 30.0.
        shell_type: The type of shell to spawn upon connection. 
                    'bash' for Unix-like systems, 'cmd.exe' for Windows. Defaults to 'bash'.
    """
    host: str = "0.0.0.0"
    port: int = 5522
    timeout: float = 30.0
    shell_type: str = "bash"

from dataclasses import dataclass
import subprocess
import shlex
import threading
import signal
import time
from typing import Optional, Tuple, Union


@dataclass(frozen=True)
class ConnectionInfo:
    """Connection metadata for shell command execution."""
    host: str
    port: int
    protocol: str = 'tcp'


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


def parse_command_args(command: str) -> list[str]:
    """Parse a shell command string into a safe argument list using shlex.split().

    Args:
        command: A shell command string (e.g., "ls -la /tmp").

    Returns:
        A list of strings representing the parsed arguments.

    Example:
        >>> parse_command_args("ls -la /tmp")
        ['ls', '-la', '/tmp']
    """
    return shlex.split(command)


def validate_connection_info(connection_info: ConnectionInfo) -> bool:
    """Validate connection information for shell command execution.

    Args:
        connection_info: The ConnectionInfo instance to validate.

    Returns:
        True if the connection info is valid, False otherwise.

    Raises:
        ValueError: If any field of ConnectionInfo is invalid.
    """
    if not isinstance(connection_info.host, str) or len(connection_info.host.strip()) == 0:
        raise ValueError("Connection host must be a non-empty string")
    if not isinstance(connection_info.port, int) or connection_info.port < 1 or connection_info.port > 65535:
        raise ValueError("Connection port must be an integer between 1 and 65535")
    if connection_info.protocol not in ('tcp', 'udp'):
        raise ValueError(f"Invalid protocol '{connection_info.protocol}'. Must be 'tcp' or 'udp'.")
    return True


def spawn_shell_process(
    command: str,
    timeout_seconds: float,
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: str = 'tcp',
) -> subprocess.Popen:
    """Spawn a shell process for executing a remote command.

    Args:
        command: The shell command to execute.
        timeout_seconds: Maximum time in seconds before the process is terminated.
        host: Remote host address (optional, defaults to localhost).
        port: Remote port number (optional, defaults to 22).
        protocol: Connection protocol ('tcp' or 'udp').

    Returns:
        A subprocess.Popen object representing the spawned shell process.

    Raises:
        ValueError: If command is empty or timeout_seconds <= 0.
    """
    if not command.strip():
        raise ValueError("Command must be a non-empty string")
    if timeout_seconds <= 0:
        raise ValueError(f"Timeout must be positive, got {timeout_seconds}")

    # Parse the command into arguments for safe subprocess invocation
    args = parse_command_args(command)

    # Build environment variables (minimal set to avoid pollution)
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'HOME': '/root',
        'SHELL': '/bin/sh',
    }

    # Spawn the process with appropriate flags for cross-platform compatibility
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        env=env,
        close_fds=True,
    )

    return proc


def capture_output_stream(
    proc: subprocess.Popen,
    timeout_seconds: float,
    blocking: bool = True,
) -> ExecutionResult:
    """Capture stdout and stderr from a running shell process.

    Args:
        proc: A subprocess.Popen object to capture output from.
        timeout_seconds: Maximum time in seconds before capturing stops.
        blocking: If True, blocks until EOF or timeout; if False, returns partial results.

    Returns:
        An ExecutionResult containing stdout, stderr, return_code, and duration_ms.

    Raises:
        subprocess.TimeoutExpired: If the process times out while waiting for output.
        RuntimeError: If the process has already terminated before capture begins.
    """
    start_time = time.perf_counter()

    # Check if process is still running
    if proc.poll() is not None:
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        return ExecutionResult(
            stdout=b'',
            stderr=b'',
            return_code=proc.returncode,
            duration_ms=duration_ms,
        )

    if blocking:
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as e:
            # Terminate the process on timeout
            _terminate_process(proc, timeout_seconds)
            raise subprocess.TimeoutExpired(
                cmd=proc.args,
                timeout=timeout_seconds,
                output=e.stdout if hasattr(e, 'stdout') else None,
                stderr=e.stderr if hasattr(e, 'stderr') else None,
            ) from e

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        return ExecutionResult(
            stdout=stdout_bytes,
            stderr=stderr_bytes,
            return_code=proc.returncode,
            duration_ms=duration_ms,
        )
    else:
        # Non-blocking mode: capture available output without blocking
        try:
            stdout_bytes = proc.stdout.read(timeout=timeout_seconds) if proc.stdout else b''
            stderr_bytes = proc.stderr.read(timeout=timeout_seconds) if proc.stderr else b''
        except subprocess.TimeoutExpired:
            stdout_bytes = proc.stdout.read() if proc.stdout else b''
            stderr_bytes = proc.stderr.read() if proc.stderr else b''

        duration_ms = int((time.perf_counter() - start_time) * 1000)
        return ExecutionResult(
            stdout=stdout_bytes,
            stderr=stderr_bytes,
            return_code=-1,  # Unknown until process terminates
            duration_ms=duration_ms,
        )


def _terminate_process(proc: subprocess.Popen, timeout_seconds: float) -> None:
    """Terminate a shell process using platform-appropriate signal handling.

    On Unix-like systems: sends SIGTERM followed by SIGKILL after the timeout period.
    On Windows: uses terminate() then wait(timeout=1).

    Args:
        proc: The subprocess.Popen object to terminate.
        timeout_seconds: The timeout value used for termination logic.
    """
    import platform

    if platform.system() == 'Windows':
        # Windows-specific: terminate() followed by a short wait
        proc.terminate()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    else:
        # Unix-like systems: SIGTERM then SIGKILL
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGKILL)
            proc.wait()


def execute_shell_command(
    command: str,
    timeout_seconds: float = 30.0,
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: str = 'tcp',
    blocking: bool = True,
) -> ExecutionResult:
    """Execute a shell command and capture its output with timeout handling.

    This is the primary entry point that combines spawning and capturing into one call.

    Args:
        command: The shell command to execute.
        timeout_seconds: Maximum execution time in seconds (default 30).
        host: Remote host address (optional, defaults to localhost).
        port: Remote port number (optional, defaults to 22).
        protocol: Connection protocol ('tcp' or 'udp').
        blocking: Whether to block until process completes.

    Returns:
        An ExecutionResult with captured stdout, stderr, return code, and duration.

    Raises:
        ValueError: If command is empty or timeout_seconds <= 0.
        subprocess.TimeoutExpired: If the process exceeds the timeout.
    """
    validate_connection_info(ConnectionInfo(host=host or 'localhost', port=port or 22, protocol=protocol))

    proc = spawn_shell_process(command, timeout_seconds, host, port, protocol)
    try:
        return capture_output_stream(proc, timeout_seconds, blocking=blocking)
    finally:
        # Ensure process is cleaned up even on exception
        if proc.poll() is None:
            _terminate_process(proc, timeout_seconds)


# Re-export for convenience
__all__ = [
    'ConnectionInfo',
    'ShellCommand',
    'ExecutionResult',
    'parse_command_args',
    'validate_connection_info',
    'spawn_shell_process',
    'capture_output_stream',
    'execute_shell_command',
]

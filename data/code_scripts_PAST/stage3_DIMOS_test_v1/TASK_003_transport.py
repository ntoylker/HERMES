"""Core reverse shell listener that binds to 0.0.0.0:5522 and handles incoming client connections."""

import select
import socket
import threading
import time
from typing import Optional, List, Dict, Any
from data.code_scripts.stage3_DIMOS_test.TASK_001_models import ReverseShellConfig, SocketAddress, CommandHandler, SessionState


class ClientConnection:
    """Manages a bidirectional stream for a single reverse shell client connection."""

    def __init__(self, server_socket: socket.socket, session_id: str):
        self.server_socket = server_socket
        self.session_id = session_id
        self.client_socket: Optional[socket.socket] = None
        self.connected: bool = False
        self.active: bool = True
        self.command_queue: List[CommandHandler] = []
        self.output_buffer: List[str] = []
        self.last_activity: Optional[float] = time.time()
        self._receive_thread: Optional[threading.Thread] = None
        self._send_thread: Optional[threading.Thread] = None

    def connect(self) -> bool:
        """Establish connection to the client."""
        try:
            self.client_socket, _ = self.server_socket.accept()
            self.client_socket.setblocking(False)
            self.connected = True
            self.active = True
            return True
        except socket.timeout:
            return False
        except Exception as e:
            print(f"[{self.session_id}] Connection error: {e}")
            return False

    def receive(self, timeout: float = 1.0) -> Optional[bytes]:
        """Non-blocking receive from client."""
        try:
            data = self.client_socket.recv(4096, socket.MSG_DONTWAIT)
            if data:
                self.output_buffer.append(data.decode('utf-8', errors='replace'))
                self.last_activity = time.time()
                return data
            return None
        except BlockingIOError:
            return None
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[{self.session_id}] Receive error: {e}")
            return None

    def send(self, data: bytes) -> bool:
        """Send data to client."""
        try:
            self.client_socket.sendall(data)
            return True
        except BlockingIOError:
            return False
        except socket.timeout:
            return False
        except Exception as e:
            print(f"[{self.session_id}] Send error: {e}")
            return False

    def close(self):
        """Close the client connection."""
        self.active = False
        if self.client_socket and not self.client_socket.closed:
            try:
                self.client_socket.close()
            except Exception:
                pass
        if self.server_socket and not self.server_socket.closed:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def __del__(self):
        """Cleanup on garbage collection."""
        self.close()


class ReverseShellServer:
    """Reverse shell server that binds to 0.0.0.0:5522 and handles multiple client connections via non-blocking I/O."""

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        if config is None:
            config = ReverseShellConfig()
        self.config = config
        self._server_socket: Optional[socket.socket] = None
        self._clients: Dict[str, ClientConnection] = {}
        self._running: bool = False
        self._main_thread: Optional[threading.Thread] = None

    def _create_server_socket(self) -> socket.socket:
        """Create and configure the server socket."""
        sock = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            proto=0
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.bind_address.host, self.config.bind_address.port))
        sock.listen(self.config.max_connections)
        sock.setblocking(False)
        return sock

    def _accept_connection(self) -> Optional[ClientConnection]:
        """Accept a new client connection."""
        try:
            client_socket, addr = self._server_socket.accept()
            session_id = f"conn_{client_socket.fileno()}_{int(time.time())}"
            conn = ClientConnection(self._server_socket, session_id)
            conn.client_socket = client_socket
            conn.connected = True
            conn.active = True
            self._clients[session_id] = conn
            print(f"[{session_id}] Connected from {addr}")
            return conn
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[Server] Accept error: {e}")
            return None

    def _handle_client(self, conn: ClientConnection) -> bool:
        """Handle a single client connection in a background thread."""
        try:
            while conn.active and conn.connected:
                # Non-blocking receive
                data = conn.receive(timeout=self.config.listen_timeout / 10.0)

                if data is not None:
                    self._process_input(conn, data)
                elif conn.client_socket is not None and conn.client_socket.fileno() > 0:
                    try:
                        # Check if client closed connection
                        result = select.select([conn.client_socket], [], [], 1.0)
                        if result[0]:
                            conn.connected = False
                            print(f"[{conn.session_id}] Client disconnected")
                    except Exception as e:
                        print(f"[{conn.session_id}] Select error: {e}")

                time.sleep(0.05)
        except Exception as e:
            print(f"[{conn.session_id}] Handle thread error: {e}")
        finally:
            conn.close()

    def _process_input(self, conn: ClientConnection, data: bytes):
        """Process incoming client input."""
        try:
            text = data.decode('utf-8', errors='replace')
            self._handle_command(conn, text)
        except Exception as e:
            print(f"[{conn.session_id}] Decode error: {e}")

    def _handle_command(self, conn: ClientConnection, input_text: str):
        """Route and execute commands from client."""
        if not input_text.strip():
            return

        self._last_activity = time.time()
        print(f"[{conn.session_id}] Received: {input_text}")

        # Simple command routing - can be extended with CommandHandler logic
        parts = input_text.split(maxsplit=1)
        cmd = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "help":
            output = "Available commands: help, whoami, hostname, date, echo <msg>, exit\n"
        elif cmd == "whoami":
            import os
            output = f"user={os.getuid()}, group={os.getgid()}\n"
        elif cmd == "hostname":
            import socket as skt
            output = f"{skt.gethostname()} ({skt.gethostbyname(skt.gethostname())})\n"
        elif cmd == "date":
            import datetime
            output = f"{datetime.datetime.now()}\n"
        elif cmd == "echo":
            output = args + "\n" if args else "echo\n"
        elif cmd == "exit" or cmd == "quit":
            conn.active = False
            print(f"[{conn.session_id}] Session ending")
            return
        else:
            output = f"{cmd} {args}\n"

        conn.output_buffer.append(output)
        self._send_output(conn, output.encode('utf-8'))

    def _send_output(self, conn: ClientConnection, data: bytes):
        """Send output to client."""
        if not conn.active or not conn.connected:
            return
        success = conn.send(data)
        if success:
            print(f"[{conn.session_id}] Sent: {data.decode('utf-8', errors='replace')}")

    def _run(self):
        """Main server loop using select for non-blocking I/O."""
        sockets_to_monitor = [self._server_socket]
        active_connections: List[ClientConnection] = []

        print(f"[Server] Listening on {self.config.bind_address.host}:{self.config.bind_address.port}")

        while self._running and len(active_connections) < self.config.max_connections:
            try:
                # Build list of sockets to monitor
                monitor_sockets = [self._server_socket] + [c.client_socket for c in active_connections if c.connected and c.client_socket is not None]

                readable, _, _ = select.select(monitor_sockets, [], [], self.config.listen_timeout)

                for sock in readable:
                    if sock == self._server_socket:
                        # New connection accepted
                        conn = self._accept_connection()
                        if conn and conn.connected:
                            active_connections.append(conn)
                            t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                            t.start()
                            print(f"[Server] New client connected")

                    elif sock is not None and sock in [c.client_socket for c in active_connections]:
                        # Data received from existing connection
                        conn = next((c for c in active_connections if c.client_socket == sock), None)
                        if conn:
                            data = conn.receive(timeout=0.1)
                            if data is not None:
                                self._process_input(conn, data)

            except select.error as e:
                print(f"[Server] Select error: {e}")
            except Exception as e:
                print(f"[Server] Error: {e}")

        # Cleanup remaining connections
        for conn in active_connections:
            if conn.active and conn.connected:
                conn.close()

    def start(self):
        """Start the server."""
        self._server_socket = self._create_server_socket()
        self._running = True
        self._main_thread = threading.Thread(target=self._run, daemon=True)
        self._main_thread.start()
        print("[Server] Server started on 0.0.0.0:5522")

    def stop(self):
        """Stop the server."""
        self._running = False
        if self._server_socket and not self._server_socket.closed:
            try:
                self._server_socket.close()
            except Exception:
                pass
        for conn in list(self._clients.values()):
            conn.close()

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running and self._main_thread is not None and self._main_thread.is_alive()

    @property
    def clients(self) -> Dict[str, ClientConnection]:
        """Get active client connections."""
        return dict(self._clients)


__all__ = ['ReverseShellServer', 'ClientConnection']

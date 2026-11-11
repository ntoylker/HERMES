from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys
from typing import Optional, List



def setup_signal_handlers(listener: Optional[UnixReverseShellListener] = None,
                          windows_listener: Optional[WindowsReverseShellListener] = None) -> None:
    """Set up signal handlers for graceful shutdown.
    
    Args:
        listener: Unix reverse shell listener instance (may be None).
        windows_listener: Windows reverse shell listener instance (may be None).
    """
    def signal_handler(signum: int, frame: Optional[None]) -> None:
        """Handle SIGINT and SIGTERM signals for graceful shutdown.
        
        Args:
            signum: The signal number received.
            frame: The current stack frame (unused).
        """
        print('\nReceived shutdown signal...')
        if listener is not None:
            try:
                # Unix listener doesn't have a stop method, so we just exit
                sys.exit(0)
            except Exception as e:
                print(f'Error during shutdown: {e}', file=sys.stderr)
                sys.exit(1)
        if windows_listener is not None and hasattr(windows_listener, 'stop'):
            try:
                result = windows_listener.stop()
                if result.error_message:
                    print(f'Shutdown errors:\n{result.error_message}')
            except Exception as e:
                print(f'Error during shutdown: {e}', file=sys.stderr)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments.
    
    Returns:
        Parsed namespace with host, port, shell_type, and platform options.
    """
    parser = argparse.ArgumentParser(
        prog='reverse_shell',
        description='Reverse Shell Orchestrator - Unix and Windows reverse shell listener.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python __main__.py --platform unix          # Start Unix reverse shell on port 5522
  python __main__.py --platform windows       # Start Windows reverse shell on port 5522
  python __main__.py --host 0.0.0.0 --port 9999 --platform unix
        """
    )

    parser.add_argument(
        '--host', '-h',
        type=str,
        default='0.0.0.0',
        help='Host address to bind the listener to (default: 0.0.0.0)'
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
        help='Shell type to spawn (bash for Unix, cmd.exe/powershell.exe for Windows)'
    )

    subparsers = parser.add_subparsers(dest='platform', required=True)

    # Unix platform subparser
    unix_parser = subparsers.add_parser('unix', help='Unix reverse shell listener')
    unix_parser.set_defaults(platform='unix')

    # Windows platform subparser
    windows_parser = subparsers.add_parser('windows', help='Windows reverse shell listener')
    windows_parser.set_defaults(platform='windows')

    args = parser.parse_args()
    return args


def create_reverse_shell_server(config: ReverseShellConfig) -> UnixReverseShellListener | WindowsReverseShellListener:
    """Create the appropriate reverse shell server based on platform.
    
    Args:
        config: ReverseShellConfig instance with host, port, timeout, and shell_type.
        
    Returns:
        A configured listener instance ready to listen for connections.
    """
    if config.shell_type == 'bash':
        return UnixReverseShellListener(config)
    elif config.shell_type in ('cmd.exe', 'powershell.exe'):
        return WindowsReverseShellListener(config)
    else:
        # Default to Unix listener for unknown shell types
        return UnixReverseShellListener(config)


def run_unix_listener(listener: UnixReverseShellListener, args: argparse.Namespace) -> ExecutionResult:
    """Run the Unix reverse shell listener.
    
    Args:
        listener: Configured UnixReverseShellListener instance.
        args: Parsed command line arguments.
        
    Returns:
        ExecutionResult summarizing the listener's operation.
    """
    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type='bash'
    )

    print(f'Unix Reverse Shell Listener starting on {config.host}:{config.port}')
    print('Listening for incoming connections...')
    print('Press Ctrl+C to stop.\n')

    result = listener.listen()

    if result.error_message:
        print(f'Errors encountered:\n{result.error_message}', file=sys.stderr)

    print('\nListener stopped.')
    return result


def run_windows_listener(listener: WindowsReverseShellListener, args: argparse.Namespace) -> ExecutionResult:
    """Run the Windows reverse shell listener.
    
    Args:
        listener: Configured WindowsReverseShellListener instance.
        args: Parsed command line arguments.
        
    Returns:
        ExecutionResult summarizing the listener's operation.
    """
    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type
    )

    print(f'Windows Reverse Shell Listener starting on {config.host}:{config.port}')
    print('Listening for incoming connections...')
    print('Press Ctrl+C to stop.\n')

    result = listener()

    if result.error_message:
        print(f'Errors encountered:\n{result.error_message}', file=sys.stderr)

    print('\nListener stopped.')
    return result


def main() -> ExecutionResult:
    """Main entry point for the reverse shell orchestrator.
    
    Parses CLI arguments, creates the appropriate listener based on platform,
    sets up signal handlers, and runs the main loop that accepts connections
    and spawns subprocesses via the selected listener class.
    
    Returns:
        ExecutionResult summarizing the overall execution.
    """
    args = parse_arguments()

    # Create configuration
    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type
    )

    # Create the appropriate listener based on platform
    if args.platform == 'unix':
        listener: UnixReverseShellListener | None = create_reverse_shell_server(config)
        windows_listener: Optional[WindowsReverseShellListener] = None
    else:  # windows
        listener: UnixReverseShellListener | None = None
        windows_listener: WindowsReverseShellListener = create_reverse_shell_server(config)

    # Set up signal handlers for graceful shutdown
    setup_signal_handlers(listener=listener, windows_listener=windows_listener)

    try:
        if args.platform == 'unix':
            result = run_unix_listener(listener, args)
        else:
            result = run_windows_listener(windows_listener, args)
    except KeyboardInterrupt:
        print('\nInterrupted by user (Ctrl+C).')
        return ExecutionResult(
            stdout='',
            stderr='KeyboardInterrupt',
            exit_code=0,
            error_message=''
        )
    except Exception as e:
        result = ExecutionResult(
            stdout='',
            stderr=str(e),
            exit_code=1,
            error_message=f'Unexpected error: {e}'
        )

    return result


if __name__ == '__main__':
    main()

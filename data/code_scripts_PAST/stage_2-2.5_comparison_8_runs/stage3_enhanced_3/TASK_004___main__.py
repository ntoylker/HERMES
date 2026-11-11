from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys


def create_reverse_shell_server(config: ReverseShellConfig) -> object:
    """Create a reverse shell server instance based on the given configuration.

    Args:
        config: The ReverseShellConfig to use for server initialization.

    Returns:
        A listener instance (Unix or Windows depending on platform).
    """
    if sys.platform == 'win32':
        return WindowsReverseShellListener(config)
    else:
        return UnixReverseShellListener(config)


def run_unix_listener(listener: UnixReverseShellListener, config: ReverseShellConfig) -> None:
    """Run the Unix reverse shell listener.

    Args:
        listener: The UnixReverseShellListener instance to run.
        config: The configuration for the listener.
    """
    print(f"[Unix] Starting reverse shell server on {config.host}:{config.port}...")
    try:
        listener.start()
    except KeyboardInterrupt:
        print("[Unix] Shutting down gracefully...")
        listener.stop()


def run_windows_listener(listener: WindowsReverseShellListener, config: ReverseShellConfig) -> None:
    """Run the Windows reverse shell listener.

    Args:
        listener: The WindowsReverseShellListener instance to run.
        config: The configuration for the listener.
    """
    print(f"[Windows] Starting reverse shell server on {config.host}:{config.port}...")
    try:
        listener.start()
    except KeyboardInterrupt:
        print("[Windows] Shutting down gracefully...")
        listener.stop()


def main(args=None) -> int:
    """Main entry point for the reverse shell orchestrator.

    Parses CLI arguments, creates the appropriate listener based on platform,
    and runs the server loop with graceful shutdown handling.

    Args:
        args: Optional list of command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    parser = argparse.ArgumentParser(
        prog='reverse_shell',
        description='Reverse shell orchestrator - wires Unix and Windows components together.'
    )
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the listener on (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5522, help='Port to listen on (default: 5522)')
    parser.add_argument('--shell-type', type=str, choices=['bash', 'sh', 'cmd.exe', 'powershell'],
                        default=None, help='Shell type for the reverse shell')
    parser.add_argument('--platform', type=str, choices=['unix', 'windows'],
                        default=None, help='Force platform mode (default: auto-detect)')

    parsed_args = parser.parse_args(args)

    config = ReverseShellConfig(
        host=parsed_args.host,
        port=parsed_args.port,
        timeout=30.0,
        shell_type=parsed_args.shell_type or 'bash' if sys.platform != 'win32' else 'cmd.exe'
    )

    listener = create_reverse_shell_server(config)

    def signal_handler(signum: int, frame):
        """Handle SIGINT/SIGTERM by gracefully shutting down the listener."""
        print(f"\n[Signal {signum}] Shutting down gracefully...")
        if hasattr(listener, 'stop'):
            try:
                listener.stop()
            except Exception as e:
                print(f"[Error] Shutdown error: {e}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if parsed_args.platform == 'unix':
        run_unix_listener(listener, config)
    elif parsed_args.platform == 'windows' or sys.platform == 'win32':
        run_windows_listener(listener, config)
    else:
        # Auto-detect based on platform
        if sys.platform == 'win32':
            run_windows_listener(listener, config)
        else:
            run_unix_listener(listener, config)

    return 0


if __name__ == '__main__':
    sys.exit(main())

"""Main orchestrator that wires together the Unix and Windows reverse shell components."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys
from typing import Optional, List



def create_reverse_shell_server(config: ReverseShellConfig) -> UnixReverseShellListener | WindowsReverseShellListener:
    """Factory function that creates the appropriate reverse shell server based on config.

    Args:
        config: The ReverseShellConfig instance specifying host, port, timeout, and shell_type.

    Returns:
        A UnixReverseShellListener or WindowsReverseShellListener instance.
    """
    if config.shell_type == 'cmd.exe' or config.shell_type == 'powershell':
        return WindowsReverseShellListener(config)
    else:
        return UnixReverseShellListener(config)


def run_unix_listener(config: ReverseShellConfig, timeout: Optional[float] = None) -> ExecutionResult:
    """Run the Unix reverse shell listener.

    Args:
        config: The ReverseShellConfig instance.
        timeout: Override for connection timeout in seconds (uses config.timeout if not provided).

    Returns:
        ExecutionResult with accumulated output from all sessions.
    """
    listener = UnixReverseShellListener(config)
    result = listener.run()
    return result


def run_windows_listener(config: ReverseShellConfig, timeout: Optional[float] = None) -> ExecutionResult | None:
    """Run the Windows reverse shell listener.

    Args:
        config: The ReverseShellConfig instance.
        timeout: Override for connection timeout in seconds (uses config.timeout if not provided).

    Returns:
        An ExecutionResult with any startup errors, or None if started successfully.
    """
    listener = WindowsReverseShellListener(config)
    result = listener.start()
    return result


def run_listener(listener: UnixReverseShellListener | WindowsReverseShellListener, timeout: Optional[float] = None) -> ExecutionResult:
    """Run the appropriate listener based on its type.

    Args:
        listener: The listener instance to run.
        timeout: Override for connection timeout in seconds (uses config.timeout if not provided).

    Returns:
        ExecutionResult with accumulated output from all sessions.
    """
    result = listener.run()
    return result


def setup_signal_handlers(listener: UnixReverseShellListener | WindowsReverseShellListener) -> None:
    """Set up signal handlers for graceful shutdown.

    Args:
        listener: The listener instance to handle signals for.
    """
    def signal_handler(signum, frame):
        if signum == signal.SIGINT or signum == signal.SIGTERM:
            print(f"\nReceived signal {signum}, shutting down...")
            listener.stop()
            sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main() -> ExecutionResult:
    """Main entry point for the reverse shell orchestrator.

    Parses CLI arguments, instantiates the appropriate listener based on shell_type,
    sets up signal handlers, and runs the listener loop until shutdown.

    Returns:
        ExecutionResult with final status of the server run.
    """
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - Unix and Windows Reverse Shell Listener'
    )
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5522, help='Port to listen on (default: 5522)')
    parser.add_argument('--timeout', type=float, default=30.0, help='Connection timeout in seconds (default: 30.0)')
    parser.add_argument('--shell-type', type=str, default='bash', help='Shell to spawn (e.g., bash, cmd.exe, powershell)')
    args = parser.parse_args()

    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type
    )

    print(f"Starting reverse shell listener...")
    print(f"  Host: {config.host}")
    print(f"  Port: {config.port}")
    print(f"  Timeout: {config.timeout}s")
    print(f"  Shell Type: {config.shell_type}")
    print("-" * 50)

    listener = create_reverse_shell_server(config)
    setup_signal_handlers(listener)

    result = run_listener(listener, timeout=config.timeout)

    if result.exit_code == 0:
        print("\nReverse shell server stopped gracefully.")
    else:
        print(f"\nServer exited with code {result.exit_code}")

    return result


if __name__ == '__main__':
    main()

"""Main orchestrator that wires together Unix and Windows reverse shell components."""
from TASK_001_models import ExecutionResult, ReverseShellConfig
from TASK_002_unix_reverse_shell import UnixReverseShellListener
from TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys


def create_reverse_shell_server(config: ReverseShellConfig) -> UnixReverseShellListener | WindowsReverseShellListener:
    """Factory function to create a reverse shell server based on platform.
    
    Args:
        config: The configuration parameters for the listener.
        
    Returns:
        A configured Unix or Windows reverse shell listener instance.
    """
    if config.shell_type in ('bash', 'sh'):
        return UnixReverseShellListener(config)
    elif config.shell_type == 'cmd.exe':
        return WindowsReverseShellListener(config)
    else:
        raise ValueError(f"Unsupported shell type: {config.shell_type}")


def run_unix_listener(listener: UnixReverseShellListener, args: argparse.Namespace) -> ExecutionResult:
    """Run the Unix reverse shell listener.
    
    Args:
        listener: The configured UnixReverseShellListener instance.
        args: Parsed command line arguments.
        
    Returns:
        ExecutionResult with accumulated output and status.
    """
    result = listener.start()
    if result.exit_code != 0:
        return result
    
    try:
        while True:
            result = listener.run()
            if result.exit_code != 0:
                break
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()
    
    return result


def run_windows_listener(listener: WindowsReverseShellListener, args: argparse.Namespace) -> ExecutionResult:
    """Run the Windows reverse shell listener.
    
    Args:
        listener: The configured WindowsReverseShellListener instance.
        args: Parsed command line arguments.
        
    Returns:
        ExecutionResult with accumulated output and status.
    """
    result = listener.start()
    if result.exit_code != 0:
        return result
    
    try:
        while True:
            result = listener.run()
            if result.exit_code != 0:
                break
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()
    
    return result


def main() -> None:
    """Main entry point for the reverse shell orchestrator.
    
    Parses CLI arguments, instantiates the appropriate listener based on
    platform selection, and runs the event loop accepting connections.
    Handles graceful shutdown via signal handlers.
    """
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - Unix and Windows listeners'
    )
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Target host address')
    parser.add_argument('--port', type=int, default=5522, help='TCP port to listen on')
    parser.add_argument('--timeout', type=float, default=30.0, help='Connection timeout in seconds')
    parser.add_argument('--shell-type', type=str, default='bash', choices=['bash', 'sh', 'cmd.exe'],
                        help='Shell type to spawn')
    
    args = parser.parse_args()
    
    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell_type
    )
    
    listener = create_reverse_shell_server(config)
    
    def signal_handler(signum, frame):
        """Handle graceful shutdown on SIGINT/SIGTERM."""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        result = listener.stop()
        sys.exit(result.exit_code if hasattr(result, 'exit_code') else 0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"Starting reverse shell server on {config.host}:{config.port}")
    print(f"Shell type: {config.shell_type}, Timeout: {config.timeout}s")
    
    try:
        if config.shell_type in ('bash', 'sh'):
            result = run_unix_listener(listener, args)
        else:
            result = run_windows_listener(listener, args)
        
        print(f"\nServer stopped. Exit code: {result.exit_code}")
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    finally:
        listener.stop()


if __name__ == '__main__':
    main()

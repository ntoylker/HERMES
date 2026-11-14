from data.code_scripts_PAST.stage3_DIMOS_test_v8_mvp2.TASK_001_models import ExecutionResult, ReverseShellConfig
from data.code_scripts_PAST.stage3_DIMOS_test_v8_mvp2.TASK_002_unix_reverse_shell import UnixReverseShellListener
from data.code_scripts_PAST.stage3_DIMOS_test_v8_mvp2.TASK_003_windows_reverse_shell import WindowsReverseShellListener
import argparse
import signal
import sys
from typing import Optional



def create_reverse_shell_server(shell_type: str) -> Optional[UnixReverseShellListener | WindowsReverseShellListener]:
    """Create and return the appropriate reverse shell listener based on platform."""
    if shell_type == 'unix':
        config = ReverseShellConfig(host='0.0.0.0', port=5522, timeout=30.0)
        return UnixReverseShellListener(config)
    elif shell_type == 'windows':
        config = ReverseShellConfig(host='0.0.0.0', port=5522, timeout=30.0)
        return WindowsReverseShellListener(config)
    else:
        raise ValueError(f"Unknown shell type: {shell_type}")


def run_unix_listener(listener: UnixReverseShellListener) -> None:
    """Run the Unix reverse shell listener in a blocking main loop."""
    print("[+] Starting Unix Reverse Shell Listener on 0.0.0.0:5522")
    try:
        listener.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping Unix Reverse Shell Listener...")
        listener.stop()


def run_windows_listener(listener: WindowsReverseShellListener) -> None:
    """Run the Windows reverse shell listener in a background thread."""
    print("[+] Starting Windows Reverse Shell Listener on 0.0.0.0:5522")
    try:
        listener.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping Windows Reverse Shell Listener...")
        listener.stop()


def main() -> int:
    """Main entry point for the reverse shell orchestrator."""
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - Unix and Windows listeners',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python __main__.py --shell unix
  python __main__.py --shell windows
  python __main__.py --host 0.0.0.0 --port 5522
        """
    )

    parser.add_argument(
        '--shell', '-s',
        choices=['unix', 'windows'],
        default='unix',
        help='Select the reverse shell platform (default: unix)'
    )

    parser.add_argument(
        '--host', '-H',
        type=str,
        default='0.0.0.0',
        help='Bind address for the listener (default: 0.0.0.0)'
    )

    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5522,
        help='Port to listen on (default: 5522)'
    )

    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=30.0,
        help='Connection timeout in seconds (default: 30.0)'
    )

    args = parser.parse_args()

    # Create the appropriate listener based on shell type
    config = ReverseShellConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        shell_type=args.shell
    )

    if args.shell == 'unix':
        listener = UnixReverseShellListener(config)
        run_unix_listener(listener)
    elif args.shell == 'windows':
        listener = WindowsReverseShellListener(config)
        run_windows_listener(listener)

    return 0


if __name__ == '__main__':
    sys.exit(main())

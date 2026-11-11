"""SSH Key Store and Lateral Movement Tracking Module.

This module provides data structures for SSH key management and lateral movement tracking,
supporting ATT&CK technique T1552.004 (Data from Removable Media) by managing SSH private keys
and logging lateral movement events across hosts.
"""

import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SSHKeyEntry:
    """Represents a single SSH private key entry in the store."""
    
    key_path: str
    fingerprint: str = ""
    host: str = ""
    comment: str = ""
    created_at: str = field(default_factory=lambda: __import__('datetime').strftime('%Y-%m-%d %H:%M:%S'))


@dataclass
class LateralMovementLogEntry:
    """Represents a single lateral movement event."""
    
    source_host: str
    target_host: str
    key_path: str
    timestamp: str = field(default_factory=lambda: __import__('datetime').strftime('%Y-%m-%d %H:%M:%S'))
    status: str = "success"


@dataclass
class SSHKeyStore:
    """Manages a collection of SSH private keys with fingerprint and host tracking.
    
    Supports parsing ssh-agent output to extract key fingerprints and hosts,
    enabling detection of unauthorized key usage (T1552.004).
    """
    
    _keys: dict[str, SSHKeyEntry] = field(default_factory=dict)
    
    def add_key(self, key_path: str, fingerprint: Optional[str] = None, host: Optional[str] = None) -> SSHKeyEntry:
        """Add a new SSH key entry to the store.
        
        Args:
            key_path: Path to the private key file.
            fingerprint: SHA256 fingerprint of the public key (optional).
            host: Associated hostname for this key (optional).
            
        Returns:
            The created SSHKeyEntry object.
        """
        entry = SSHKeyEntry(key_path=key_path, fingerprint=fingerprint or "", host=host or "")
        self._keys[key_path] = entry
        return entry
    
    def get_key(self, key_path: str) -> Optional[SSHKeyEntry]:
        """Retrieve a key entry by path.
        
        Args:
            key_path: Path to the private key file.
            
        Returns:
            SSHKeyEntry if found, None otherwise.
        """
        return self._keys.get(key_path)
    
    def get_all_keys(self) -> list[SSHKeyEntry]:
        """Retrieve all stored keys.
        
        Returns:
            List of all SSHKeyEntry objects.
        """
        return list(self._keys.values())
    
    def remove_key(self, key_path: str) -> bool:
        """Remove a key from the store.
        
        Args:
            key_path: Path to the private key file.
            
        Returns:
            True if key was removed, False otherwise.
        """
        return self._keys.pop(key_path, None) is not None
    
    def parse_ssh_agent(self) -> list[SSHKeyEntry]:
        """Parse ssh-agent output to extract loaded keys and their fingerprints.
        
        Executes 'ssh-add -l' command and parses the output for key paths,
        fingerprints, and host information. This enables detection of keys
        currently in use by an attacker (T1552.004).
        
        Returns:
            List of SSHKeyEntry objects parsed from ssh-agent.
        """
        entries = []
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split()
                
                # Format: 256 SHA256:ABCD... /home/user/.ssh/id_rsa (comment)
                fingerprint = ""
                host = ""
                comment = ""
                
                for part in parts:
                    if part.startswith("SHA256:") or part.startswith("SHA1:"):
                        fingerprint = part.replace("SHA256:", "").replace("SHA1:", "")
                    elif part.startswith("/"):
                        key_path = part
                    elif "(" in part and ")" in part:
                        comment = part[1:-1]
                
                if key_path and fingerprint:
                    entry = SSHKeyEntry(
                        key_path=key_path,
                        fingerprint=fingerprint,
                        host=host or "",
                        comment=comment
                    )
                    entries.append(entry)
                    
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            pass
        
        return entries
    
    def get_keys_by_fingerprint(self, fingerprint: str) -> list[SSHKeyEntry]:
        """Find keys matching a specific fingerprint.
        
        Args:
            fingerprint: SHA256 fingerprint to search for.
            
        Returns:
            List of matching SSHKeyEntry objects.
        """
        return [e for e in self._keys.values() if e.fingerprint == fingerprint]
    
    def get_keys_by_host(self, host: str) -> list[SSHKeyEntry]:
        """Find keys associated with a specific host.
        
        Args:
            host: Hostname to search for.
            
        Returns:
            List of matching SSHKeyEntry objects.
        """
        return [e for e in self._keys.values() if e.host == host]


@dataclass
class LateralMovementLog:
    """Tracks lateral movement events across hosts using SSH keys.
    
    Records successful connections, failed attempts, and key usage patterns
    to detect anomalous lateral movement (T1552.004).
    """
    
    _entries: list[LateralMovementLogEntry] = field(default_factory=list)
    
    def log_connection(self, source_host: str, target_host: str, 
                        key_path: str, status: str = "success") -> LateralMovementLogEntry:
        """Record a lateral movement connection event.
        
        Args:
            source_host: The host initiating the connection.
            target_host: The destination host being accessed.
            key_path: SSH private key used for authentication.
            status: Connection result ("success" or "failed").
            
        Returns:
            The created LateralMovementLogEntry object.
        """
        entry = LateralMovementLogEntry(
            source_host=source_host,
            target_host=target_host,
            key_path=key_path,
            timestamp=__import__('datetime').strftime('%Y-%m-%d %H:%M:%S'),
            status=status
        )
        self._entries.append(entry)
        return entry
    
    def get_entries(self) -> list[LateralMovementLogEntry]:
        """Retrieve all logged movement events.
        
        Returns:
            List of all LateralMovementLogEntry objects.
        """
        return self._entries.copy()
    
    def get_by_source(self, source_host: str) -> list[LateralMovementLogEntry]:
        """Find entries by source host.
        
        Args:
            source_host: The source hostname to filter by.
            
        Returns:
            List of matching log entries.
        """
        return [e for e in self._entries if e.source_host == source_host]
    
    def get_by_target(self, target_host: str) -> list[LateralMovementLogEntry]:
        """Find entries by target host.
        
        Args:
            target_host: The destination hostname to filter by.
            
        Returns:
            List of matching log entries.
        """
        return [e for e in self._entries if e.target_host == target_host]
    
    def get_by_key(self, key_path: str) -> list[LateralMovementLogEntry]:
        """Find entries using a specific SSH key.
        
        Args:
            key_path: The SSH private key path to filter by.
            
        Returns:
            List of matching log entries.
        """
        return [e for e in self._entries if e.key_path == key_path]
    
    def get_failed_connections(self) -> list[LateralMovementLogEntry]:
        """Retrieve all failed connection attempts.
        
        Returns:
            List of failed LateralMovementLogEntry objects.
        """
        return [e for e in self._entries if e.status == "failed"]
    
    def get_successful_connections(self) -> list[LateralMovementLogEntry]:
        """Retrieve all successful connections.
        
        Returns:
            List of successful LateralMovementLogEntry objects.
        """
        return [e for e in self._entries if e.status == "success"]
    
    def clear(self) -> None:
        """Clear all logged entries."""
        self._entries.clear()


__all__ = ["SSHKeyStore", "LateralMovementLog", "SSHKeyEntry", "LateralMovementLogEntry"]

import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional


# Import from TASK_002_utils (dependency module)
from data.code_scripts_PAST.stage3_DIMOS_test_v2.TASK_002_utils import execute_shell_command


@dataclass
class SystemInfo:
    """Structured system information gathered via reconnaissance."""

    hostname: str = ""
    kernel: str = ""
    os_release: str = ""
    architecture: str = ""
    user: str = ""
    uptime_seconds: int = 0
    cpu_count: int = 0


@dataclass
class NetworkEnumResult:
    """Structured network enumeration results."""

    listening_ports: list[dict] = field(default_factory=list)
    established_connections: list[dict] = field(default_factory=list)
    all_sockets: list[dict] = field(default_factory=list)


class ReconScanner:
    """Reconnaissance scanner for reverse shell intelligence gathering.
    
    Implements a command registry pattern where each recon operation maps to
    a predefined shell command. Output is parsed using regex patterns and
    structured into SystemInfo or NetworkEnumResult objects.
    
    ATT&CK Technique: T1059.004 (Unix Shell)
    """

    # Command Registry: Maps operation names to shell commands
    COMMAND_REGISTRY = {
        "whoami": "whoami",
        "uname_a": "uname -a",
        "netstat": "netstat -tunap",
        "ps_auxf": "ps auxf",
    }

    # Regex patterns for parsing command outputs
    PARSERS = {
        "whoami": re.compile(r"^(?:root|user[^\s]+)\s+(.*)$"),
        "uname_a": re.compile(
            r"(?P<sysname>\S+)\s+"
            r"(?P<nodename>\S+)\s+"
            r"(?P<release>\S+)\s+"
            r"(?P<version>\S+)\s+"
            r"(?P<machine>\S+)"
        ),
        "netstat": re.compile(
            r"^(?:tcp|udp)\s+(?P<proto>\w+)\s+\S+\s+"
            r"(?P<local_addr>[\d\.]+:\d+)\s+"
            r"(?P<remote_addr>[\d\.\*]+:\d+)?\s+"
            r"(?P<state>\w+)"
        ),
        "ps_auxf": re.compile(
            r"^(?:root|user[^\s]+)\s+\S+\s+(?P<pid>\d+)\s+"
            r"(?P<ppid>\d+)\s+(?P<cpu>[\d\.]+)\s+"
            r"(?P<mem>[\d\.]+)\s+(?P<nice>\w+)\s+"
            r"(?P<status>\S+)\s+(?P<time>[\d:]+)\s+"
            r"(?P<cmd>.+)$"
        ),
    }

    def __init__(self) -> None:
        """Initialize the ReconScanner."""
        self._results_cache: dict[str, object] = {}

    def _parse_output(self, command_name: str, output: str) -> Optional[object]:
        """Parse command output using regex patterns.
        
        Args:
            command_name: The name of the command being parsed.
            output: Raw stdout from the shell command.
            
        Returns:
            Parsed object (SystemInfo or NetworkEnumResult) or None if parsing fails.
        """
        pattern = self.PARSERS.get(command_name)
        if not pattern:
            return None

        lines = output.strip().split("\n")
        results = []

        for line in lines:
            match = pattern.match(line)
            if match:
                results.append(match.groupdict())

        if not results:
            return None

        # Route to appropriate dataclass based on command type
        if command_name == "whoami":
            user_info = results[0]
            return SystemInfo(
                hostname=user_info.get("user", ""),
                kernel="",
                os_release="",
                architecture="",
                user=user_info.get("user", ""),
                uptime_seconds=0,
                cpu_count=0,
            )

        elif command_name == "uname_a":
            uname_data = results[0]
            return SystemInfo(
                hostname=uname_data.get("nodename", ""),
                kernel=uname_data.get("release", ""),
                os_release="",
                architecture=uname_data.get("machine", ""),
                user="",
                uptime_seconds=0,
                cpu_count=0,
            )

        elif command_name == "netstat":
            net_results = []
            for item in results:
                proto = item.get("proto", "")
                local_addr = item.get("local_addr", "")
                remote_addr = item.get("remote_addr", "")
                state = item.get("state", "")

                if proto == "tcp":
                    net_results.append({
                        "type": "TCP",
                        "protocol": proto,
                        "local_address": local_addr,
                        "remote_address": remote_addr or "-",
                        "state": state,
                    })
                elif proto == "udp":
                    net_results.append({
                        "type": "UDP",
                        "protocol": proto,
                        "local_address": local_addr,
                        "remote_address": remote_addr or "-",
                        "state": "",
                    })

            return NetworkEnumResult(
                listening_ports=[r for r in net_results if r["state"] == "LISTEN"],
                established_connections=[r for r in net_results if r["state"] == "ESTABLISHED"],
                all_sockets=net_results,
            )

        elif command_name == "ps_auxf":
            ps_results = []
            for item in results:
                ps_results.append({
                    "pid": int(item.get("pid", 0)),
                    "ppid": int(item.get("ppid", 0)),
                    "user": item.get("user", ""),
                    "cpu_percent": float(item.get("cpu", 0.0)) if item.get("cpu") else 0.0,
                    "mem_percent": float(item.get("mem", 0.0)) if item.get("mem") else 0.0,
                    "status": item.get("status", ""),
                    "time": item.get("time", ""),
                    "command": item.get("cmd", ""),
                })

            return NetworkEnumResult(
                listening_ports=[],
                established_connections=ps_results,
                all_sockets=ps_results,
            )

        return None

    def run_command(self, operation: str) -> object:
        """Execute a registered reconnaissance command and parse results.
        
        Args:
            operation: The name of the operation (e.g., "whoami", "netstat").
            
        Returns:
            Parsed SystemInfo or NetworkEnumResult object.
            
        Raises:
            KeyError: If the operation is not in the registry.
        """
        if operation not in self.COMMAND_REGISTRY:
            raise KeyError(f"Unknown operation: {operation}")

        command = self.COMMAND_REGISTRY[operation]
        result = execute_shell_command(command, timeout=30)

        if not result.success or not result.stdout.strip():
            return SystemInfo() if "whoami" in operation else NetworkEnumResult()

        parsed = self._parse_output(operation, result.stdout)
        if parsed is None:
            # Fallback to empty structured object on parse failure
            if "netstat" in operation or "ps_auxf" in operation:
                return NetworkEnumResult()
            return SystemInfo()

        return parsed

    def run_all(self) -> dict[str, object]:
        """Execute all registered reconnaissance commands.
        
        Returns:
            Dictionary mapping operation names to their parsed results.
        """
        results = {}
        for operation in self.COMMAND_REGISTRY.keys():
            results[operation] = self.run_command(operation)
        return results

    def get_cached(self, key: str) -> Optional[object]:
        """Retrieve a cached result by key.
        
        Args:
            key: The cache key (typically the operation name).
            
        Returns:
            Cached result object or None if not found.
        """
        return self._results_cache.get(key)

    def set_cached(self, key: str, value: object) -> None:
        """Cache a result for later retrieval.
        
        Args:
            key: The cache key.
            value: The result to cache.
        """
        self._results_cache[key] = value


# Convenience function for direct use
def scan_system(operation: str) -> object:
    """Execute a single reconnaissance operation.
    
    Args:
        operation: The name of the operation to run.
        
    Returns:
        Parsed SystemInfo or NetworkEnumResult object.
    """
    scanner = ReconScanner()
    return scanner.run_command(operation)


# Convenience function for full scan
def full_recon() -> dict[str, object]:
    """Execute all reconnaissance operations.
    
    Returns:
        Dictionary of all operation results.
    """
    scanner = ReconScanner()
    return scanner.run_all()

"""Reconnaissance module for reverse shell operations.

Provides system information gathering, network enumeration, and process listing
capabilities through a command registry pattern that maps recon operations to
predefined shell commands parsed via regex patterns.

ATT&CK techniques: T1059.004 (Command and Scripting Interpreter)
"""

import re
from dataclasses import dataclass, field
from typing import Any


# Import from TASK_002_utils by stem name
from data.code_scripts.stage3_DIMOS_test.TASK_002_utils import execute_shell_command, parse_socket_address


@dataclass
class NetworkEnumResult:
    """Structured result of network enumeration operations.
    
    Attributes:
        local_addresses: List of local IP addresses found.
        remote_connections: List of active remote connections with details.
        listening_ports: List of ports currently listening for connections.
        open_ports: Dictionary mapping port numbers to service information.
        dns_records: List of DNS records discovered.
        raw_output: Raw unprocessed output from the enumeration command.
    """
    local_addresses: list[str] = field(default_factory=list)
    remote_connections: list[dict[str, Any]] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    open_ports: dict[int, str] = field(default_factory=dict)
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""


class SystemInfo:
    """Gathers and structures system information from the target host.
    
    Collects OS details, hostname, architecture, kernel version, and user info
    using shell commands parsed via regex patterns.
    
    Attributes:
        os_info: Dictionary containing operating system details.
        hostname: The hostname of the system.
        architecture: System architecture (e.g., x86_64).
        kernel_version: Kernel version string.
        user: Current username.
        host_ip: Primary IP address of the host.
    """

    def __init__(self) -> None:
        self.os_info: dict[str, str] = {}
        self.hostname: str = ""
        self.architecture: str = ""
        self.kernel_version: str = ""
        self.user: str = ""
        self.host_ip: str = ""

    def gather(self) -> "SystemInfo":
        """Execute all system information gathering commands and populate attributes.
        
        Returns:
            Self for method chaining.
        """
        # Gather OS info using uname -a
        result = execute_shell_command("uname -a")
        if result["success"]:
            self._parse_uname(result["stdout"])

        # Gather hostname
        result = execute_shell_command("hostname")
        if result["success"]:
            self.hostname = result["stdout"].strip()

        # Gather architecture (redundant with uname but for completeness)
        result = execute_shell_command("uname -m")
        if result["success"]:
            self.architecture = result["stdout"].strip()

        # Gather kernel version
        result = execute_shell_command("uname -r")
        if result["success"]:
            self.kernel_version = result["stdout"].strip()

        # Gather current user
        result = execute_shell_command("whoami")
        if result["success"]:
            self.user = result["stdout"].strip()

        # Gather host IP address
        result = execute_shell_command("hostname -I | awk '{print $1}'")
        if result["success"]:
            self.host_ip = result["stdout"].strip()

        return self

    def _parse_uname(self, output: str) -> None:
        """Parse uname -a output using regex patterns.
        
        Args:
            output: Raw stdout from the 'uname -a' command.
        """
        # Pattern for OS name and version (e.g., "Linux hostname 5.15.0-generic")
        os_pattern = r"Linux\s+(\S+)\s+(\d+\.\d+\.\d+[-\w.]*)\s+(.+)"
        match = re.search(os_pattern, output)
        if match:
            self.os_info["os_name"] = match.group(1)
            self.os_info["kernel_version"] = match.group(2)
            self.os_info["hostname"] = match.group(3).split()[0]

    def to_dict(self) -> dict[str, Any]:
        """Convert system info to a serializable dictionary.
        
        Returns:
            Dictionary containing all gathered system information.
        """
        return {
            "os_info": self.os_info,
            "hostname": self.hostname,
            "architecture": self.architecture,
            "kernel_version": self.kernel_version,
            "user": self.user,
            "host_ip": self.host_ip,
        }


class ReconScanner:
    """Main reconnaissance scanner using a command registry pattern.
    
    Maps reconnaissance operations to predefined shell commands and parses
    output using regex patterns for structured data extraction.
    
    Attributes:
        commands: Registry mapping operation names to shell commands.
        results: Dictionary storing results from each recon operation.
    """

    def __init__(self) -> None:
        self.commands: dict[str, str] = {}
        self.results: dict[str, Any] = {}

        # Register command mappings (command name -> shell command)
        self._register_commands()

    def _register_commands(self) -> None:
        """Register all reconnaissance commands in the registry.
        
        Maps operation names to their corresponding shell commands.
        """
        self.commands["whoami"] = "whoami"
        self.commands["hostname"] = "hostname"
        self.commands["uname"] = "uname -a"
        self.commands["kernel_version"] = "uname -r"
        self.commands["network_connections"] = "netstat -anp 2>/dev/null || ss -anp"
        self.commands["listening_ports"] = "netstat -tlnp 2>/dev/null || ss -tlnp"
        self.commands["processes"] = "ps auxf"
        self.commands["open_files"] = "lsof -i"
        self.commands["dns_records"] = "nslookup $(hostname) 2>/dev/null || host $(hostname)"
        self.commands["system_info"] = "uname -a && hostname && whoami && id"

    def execute(self, operation: str) -> dict[str, Any]:
        """Execute a registered reconnaissance operation.
        
        Args:
            operation: Name of the operation to execute (key in commands registry).
            
        Returns:
            Dictionary containing the result of the operation or error info.
            
        Raises:
            KeyError: If the operation is not registered.
        """
        if operation not in self.commands:
            raise KeyError(f"Unknown operation: {operation}. Available: {list(self.commands.keys())}")

        command = self.commands[operation]
        result = execute_shell_command(command, timeout=30)

        if result["success"]:
            parsed_data = self._parse_output(operation, result["stdout"])
            self.results[operation] = parsed_data
            return {"status": "success", "data": parsed_data}
        else:
            self.results[operation] = {
                "error": result.get("stderr", ""),
                "return_code": result["return_code"],
            }
            return {"status": "failed", "data": None, "error": result.get("stderr", "")}

    def _parse_output(self, operation: str, output: str) -> Any:
        """Parse command output using regex patterns specific to each operation.
        
        Args:
            operation: Name of the operation being parsed.
            output: Raw stdout from the shell command.
            
        Returns:
            Parsed structured data as a dictionary or list.
        """
        if operation == "whoami":
            return {"user": output.strip()}

        elif operation == "hostname":
            return {"hostname": output.strip()}

        elif operation == "uname":
            # Parse: Linux hostname 5.15.0-generic x86_64 GNU/Linux
            pattern = r"Linux\s+(\S+)\s+(\d+\.\d+\.\d+[-\w.]*)\s+(.+)"
            match = re.search(pattern, output)
            if match:
                return {
                    "os_name": match.group(1),
                    "kernel_version": match.group(2),
                    "hostname": match.group(3).split()[0],
                    "architecture": match.group(3).split()[-1] if len(match.group(3).split()) > 1 else "",
                }

        elif operation == "kernel_version":
            return {"kernel_version": output.strip()}

        elif operation == "network_connections":
            # Parse netstat/ss output for connections
            lines = output.strip().split("\n")
            connections: list[dict[str, Any]] = []
            for line in lines[1:] if len(lines) > 1 else [output]:
                # Pattern for established/syn_sent/etc connections
                conn_pattern = r"(\d+\.\d+\.\d+\.\d+):\s+(\d+)\s+(.+)\s+(\S+)"
                match = re.search(conn_pattern, line)
                if match:
                    try:
                        port = int(match.group(2))
                        connections.append({
                            "remote_ip": match.group(1),
                            "port": port,
                            "state": match.group(3).strip(),
                            "process": match.group(4).strip() if match.group(4) else "",
                        })
                    except (ValueError, AttributeError):
                        continue
            return {"connections": connections}

        elif operation == "listening_ports":
            # Parse listening ports from netstat/ss output
            lines = output.strip().split("\n")
            ports: list[int] = []
            for line in lines[1:] if len(lines) > 1 else [output]:
                port_pattern = r"(\d+)\s+(.+)\s+(\S+)"
                match = re.search(port_pattern, line)
                if match:
                    try:
                        ports.append(int(match.group(1)))
                    except (ValueError, AttributeError):
                        continue
            return {"listening_ports": sorted(list(set(ports)))}

        elif operation == "processes":
            # Parse ps auxf output for process listing
            lines = output.strip().split("\n")
            processes: list[dict[str, Any]] = []
            header_found = False
            for line in lines:
                if not header_found and len(line.split()) > 10:
                    header_found = True
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        pid = int(parts[0])
                        processes.append({
                            "pid": pid,
                            "user": parts[1],
                            "cpu": float(parts[2]),
                            "mem": float(parts[3]),
                            "cmd": " ".join(parts[4:]) if len(parts) > 4 else "",
                        })
                    except (ValueError, IndexError):
                        continue
            return {"processes": processes}

        elif operation == "open_files":
            # Parse lsof output for open network files
            lines = output.strip().split("\n")
            files: list[dict[str, Any]] = []
            for line in lines[1:] if len(lines) > 1 else [output]:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        pid = int(parts[0])
                        port = int(parts[3])
                        files.append({
                            "pid": pid,
                            "process": parts[1],
                            "port": port,
                            "protocol": parts[2].lower(),
                        })
                    except (ValueError, IndexError):
                        continue
            return {"open_files": files}

        elif operation == "dns_records":
            # Parse nslookup/host output for DNS records
            lines = output.strip().split("\n")
            records: list[dict[str, Any]] = []
            current_record: dict[str, str] = {}
            for line in lines:
                if ":" in line and not line.startswith("Server"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        current_record[key] = value
                elif line.strip().startswith("Non-authoritative answer"):
                    records.append(current_record)
                    current_record = {}
            return {"dns_records": records}

        else:
            # Fallback: return raw output as string
            return {"raw_output": output}

    def scan_all(self) -> dict[str, Any]:
        """Execute all registered reconnaissance operations.
        
        Returns:
            Dictionary containing results from all operations.
        """
        self.results = {}
        for operation in self.commands.keys():
            self.execute(operation)
        return self.results

    def get_results(self) -> dict[str, Any]:
        """Get all collected reconnaissance results.
        
        Returns:
            Dictionary of all operation results.
        """
        return self.results


def format_recon_result(data: Any) -> str:
    """Format reconnaissance result as a JSON string for output.
    
    Args:
        data: The data to serialize (dict, list, or primitive).
        
    Returns:
        A formatted JSON string representation of the data.
    """
    try:
        return json.dumps(data, indent=2, default=str)
    except TypeError as e:
        return f"{{'error': '{str(e)}'}}"


def parse_network_info(output: str) -> NetworkEnumResult:
    """Parse network enumeration output into a structured result.
    
    Args:
        output: Raw stdout from netstat/ss command.
        
    Returns:
        A populated NetworkEnumResult object.
    """
    result = NetworkEnumResult()

    # Parse local addresses
    lines = output.strip().split("\n")
    for line in lines[1:] if len(lines) > 1 else [output]:
        addr_pattern = r"(\d+\.\d+\.\d+\.\d+):\s+(\d+)\s+(.+)\s+(\S+)"
        match = re.search(addr_pattern, line)
        if match:
            result.local_addresses.append(match.group(1))

    # Parse remote connections
    for line in lines[1:] if len(lines) > 1 else [output]:
        conn_pattern = r"(\d+\.\d+\.\d+\.\d+):\s+(\d+)\s+(.+)\s+(\S+)"
        match = re.search(conn_pattern, line)
        if match:
            try:
                port = int(match.group(2))
                result.remote_connections.append({
                    "remote_ip": match.group(1),
                    "port": port,
                    "state": match.group(3).strip(),
                    "process": match.group(4).strip() if match.group(4) else "",
                })
            except (ValueError, AttributeError):
                continue

    # Parse listening ports
    for line in lines[1:] if len(lines) > 1 else [output]:
        port_pattern = r"(\d+)\s+(.+)\s+(\S+)"
        match = re.search(port_pattern, line)
        if match:
            try:
                result.listening_ports.append(int(match.group(1)))
            except (ValueError, AttributeError):
                continue

    # Parse open ports mapping
    for line in lines[1:] if len(lines) > 1 else [output]:
        port_pattern = r"(\d+)\s+(.+)\s+(\S+)"
        match = re.search(port_pattern, line)
        if match:
            try:
                result.open_ports[int(match.group(1))] = match.group(3).strip()
            except (ValueError, AttributeError):
                continue

    # Parse DNS records
    lines = output.strip().split("\n")
    for line in lines[1:] if len(lines) > 1 else [output]:
        if ":" in line and not line.startswith("Server"):
            parts = line.split(":")
            if len(parts) >= 2:
                result.dns_records.append({parts[0].strip(): parts[1].strip()})

    return result


if __name__ == "__main__":
    print("=" * 60)
    print("RECONNAISSANCE MODULE - TEST")
    print("=" * 60)

    # Test SystemInfo
    print("\n--- System Info Gathering ---")
    sys_info = SystemInfo()
    sys_info.gather()
    print(f"Hostname: {sys_info.hostname}")
    print(f"User: {sys_info.user}")
    print(f"Architecture: {sys_info.architecture}")
    print(f"Kernel: {sys_info.kernel_version}")

    # Test ReconScanner
    print("\n--- Recon Scanner ---")
    scanner = ReconScanner()
    results = scanner.scan_all()

    for op, result in results.items():
        if result.get("status") == "success":
            data = result["data"]
            formatted = format_recon_result(data)
            print(f"\n{op}:")
            print(formatted[:500] + ("..." if len(formatted) > 500 else ""))

    # Test Network Enum Result parsing
    print("\n--- Network Enumeration ---")
    sample_output = """Active Internet connections (servers/servers only)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.1.100:22       0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 192.168.1.100:80       0.0.0.0:*               LISTEN      5678/nginx
tcp        0      0 192.168.1.100:443      0.0.0.0:*               LISTEN      5678/nginx
tcp        0      0 192.168.1.100:22       10.0.0.5:54321         ESTABLISHED 1234/sshd"""

    network_result = parse_network_info(sample_output)
    print(f"Local addresses: {network_result.local_addresses}")
    print(f"Listening ports: {network_result.listening_ports}")
    print(f"Open ports: {dict(network_result.open_ports)}")

"""Windows-specific utility functions for command execution via cmd.exe.

This module provides utilities for executing Windows commands through cmd.exe
for defensive security research purposes (ATT&CK T1059.003).

Usage:
    from windows_utils import execute_windows_command, parse_cmd_output, format_windows_response
    
    result = execute_windows_command("ipconfig /all")
    parsed = parse_cmd_output(result)
    formatted = format_windows_response(parsed)
"""

import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WindowsCommandResult:
    """Structured result from a Windows command execution."""
    command: str
    exit_code: int
    stdout: str
    stderr: str
    success: bool
    timeout_occurred: bool = False
    process_id: Optional[int] = None


@dataclass
class ParsedOutput:
    """Parsed structured output from Windows commands."""
    command_type: str
    sections: dict[str, list[str]]
    raw_output: str
    errors: list[str] = field(default_factory=list)


def execute_windows_command(
    cmd: str,
    timeout: int = 30,
    working_dir: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> WindowsCommandResult:
    """Execute a command via cmd.exe with CREATE_NEW_CONSOLE and shell=True.

    Args:
        cmd: The command string to execute (e.g., "ipconfig /all", "netstat -ano").
        timeout: Maximum time in seconds before the process is terminated.
        working_dir: Working directory for the subprocess. Defaults to current dir.
        env: Environment variables to pass to the subprocess.

    Returns:
        WindowsCommandResult containing stdout, stderr, exit code, and metadata.

    Raises:
        TimeoutExpired: If the command exceeds the timeout period.
        CalledProcessError: If the command exits with a non-zero status.
    """
    try:
        process = subprocess.Popen(
            ["cmd.exe", "/c", cmd],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_dir,
            env=env,
            text=True,
            bufsize=1,
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return WindowsCommandResult(
                command=cmd,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                success=process.returncode == 0,
                timeout_occurred=False,
                process_id=process.pid,
            )
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=1)
            return WindowsCommandResult(
                command=cmd,
                exit_code=-1,
                stdout=stdout,
                stderr=stderr,
                success=False,
                timeout_occurred=True,
                process_id=process.pid,
            )

    except FileNotFoundError:
        raise RuntimeError("cmd.exe not found. Ensure Windows environment is valid.")


def parse_cmd_output(result: WindowsCommandResult) -> ParsedOutput:
    """Parse the output of a Windows command into structured sections.

    Handles parsing for common commands: ipconfig, netstat -ano, tasklist, systeminfo.

    Args:
        result: The WindowsCommandResult from execute_windows_command.

    Returns:
        ParsedOutput with structured data extracted from the raw output.
    """
    command_type = _detect_command_type(result.command)
    sections: dict[str, list[str]] = {}

    if command_type == "ipconfig":
        sections = _parse_ipconfig_output(result.stdout)
    elif command_type == "netstat":
        sections = _parse_netstat_output(result.stdout)
    elif command_type == "tasklist":
        sections = _parse_tasklist_output(result.stdout)
    elif command_type == "systeminfo":
        sections = _parse_systeminfo_output(result.stdout)
    else:
        sections["raw"] = [result.stdout]

    return ParsedOutput(
        command_type=command_type,
        sections=sections,
        raw_output=result.stdout,
        errors=[e for e in result.stderr.strip().split("\n") if e],
    )


def _detect_command_type(cmd: str) -> str:
    """Detect the type of Windows command from its string representation."""
    cmd_lower = cmd.lower()

    if "ipconfig" in cmd_lower:
        return "ipconfig"
    elif "netstat" in cmd_lower:
        return "netstat"
    elif "tasklist" in cmd_lower:
        return "tasklist"
    elif "systeminfo" in cmd_lower:
        return "systeminfo"
    else:
        return "generic"


def _parse_ipconfig_output(output: str) -> dict[str, list[str]]:
    """Parse ipconfig output into structured sections."""
    sections = {}

    # Split by section headers (e.g., "Windows IP Configuration", "Ethernet adapter")
    lines = output.split("\n")
    current_section = None
    current_entries: list[str] = []

    for line in lines:
        if not line.strip():
            continue

        # Detect section header
        if re.match(r"^\s*(Windows IP Configuration|Ethernet adapter\s+\w+|Wireless LAN adapter\s+\w+)", line, re.IGNORECASE):
            if current_section and current_entries:
                sections[current_section] = current_entries
            current_section = line.strip()
            current_entries = []
        else:
            current_entries.append(line)

    # Don't forget the last section
    if current_section and current_entries:
        sections[current_section] = current_entries

    return sections


def _parse_netstat_output(output: str) -> dict[str, list[str]]:
    """Parse netstat -ano output into structured connections."""
    sections = {}

    lines = [l for l in output.split("\n") if l.strip()]

    # Parse active connections
    active_connections: list[dict] = []
    current_conn: Optional[dict] = None

    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and parts[0].startswith("Active Connections"):
            continue

        if not current_conn or (len(parts) >= 4 and parts[3] == "ESTABLISHED" or parts[3] == "LISTENING"):
            try:
                proto = parts[0]
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3] if len(parts) >= 4 else ""
                pid = int(parts[-1]) if len(parts) > 5 and re.match(r"^\d+$", parts[-1]) else None

                current_conn = {
                    "protocol": proto,
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "state": state,
                    "pid": pid,
                }
            except (ValueError, IndexError):
                pass

        elif current_conn and len(parts) >= 4:
            try:
                proto = parts[0]
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3] if len(parts) >= 4 else ""
                pid = int(parts[-1]) if len(parts) > 5 and re.match(r"^\d+$", parts[-1]) else None

                current_conn["protocol"] = proto
                current_conn["local_address"] = local_addr
                current_conn["remote_address"] = remote_addr
                current_conn["state"] = state
                current_conn["pid"] = pid
            except (ValueError, IndexError):
                pass

    if current_conn:
        active_connections.append(current_conn)

    sections["active_connections"] = [c for c in active_connections if c]

    # Parse listening ports
    listening_ports: list[dict] = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("TCP") or parts[0].startswith("UDP"):
            try:
                proto = parts[0]
                local_addr = parts[1]
                pid = int(parts[-1]) if len(parts) > 5 and re.match(r"^\d+$", parts[-1]) else None

                listening_ports.append({
                    "protocol": proto,
                    "local_address": local_addr,
                    "pid": pid,
                })
            except (ValueError, IndexError):
                pass

    sections["listening_ports"] = listening_ports

    return sections


def _parse_tasklist_output(output: str) -> dict[str, list[str]]:
    """Parse tasklist output into structured process information."""
    sections = {}

    lines = [l for l in output.split("\n") if l.strip()]

    # Parse header to determine column count
    header_line = None
    data_lines: list[dict] = []

    for line in lines:
        parts = line.split()
        if len(parts) >= 5 and "Image Name" in str(parts):
            header_line = line
            continue

        if not header_line or len(parts) < 5:
            continue

        try:
            session_name = parts[0] if len(parts) > 0 else ""
            user = parts[1] if len(parts) > 1 else ""
            pid = int(parts[2]) if len(parts) > 2 and re.match(r"^\d+$", parts[2]) else None
            ppid = int(parts[3]) if len(parts) > 3 and re.match(r"^\d+$", parts[3]) else None
            memory = parts[4] if len(parts) > 4 else ""

            data_lines.append({
                "session_name": session_name,
                "user": user,
                "pid": pid,
                "ppid": ppid,
                "memory": memory,
            })
        except (ValueError, IndexError):
            pass

    sections["processes"] = data_lines

    return sections


def _parse_systeminfo_output(output: str) -> dict[str, list[str]]:
    """Parse systeminfo output into structured sections."""
    sections = {}

    lines = [l for l in output.split("\n") if l.strip()]

    current_section: Optional[str] = None
    section_entries: list[str] = []

    for line in lines:
        # Detect section headers (common systeminfo sections)
        section_patterns = [
            r"^(System Information)",
            r"^OS Name",
            r"^OS Version",
            r"^System Manufacturer",
            r"^System Model",
            r"^Processor(s)",
            r"^BIOS Version",
            r"^Windows Directory",
            r"^System Directories",
            r"^Boot Device",
            r"^System Root",
            r"^System Time",
            r"^Total Physical Memory",
            r"^Available Physical Memory",
            r"^Page File(s)",
            r"^Domain Name",
            r"^Logon Server",
            r"^Windows Directory",
            r"^System Directories",
            r"^Current Control Set",
            r"^Machine Name",
            r"^Computer Name",
            r"^User Domain",
            r"^Hostname",
            r"^Domain Controller for Hostname",
            r"^Logon Server",
            r"^Windows Directory",
            r"^System Directories",
            r"^Configuration File(s)",
            r"^Default Configuration File(s)",
            r"^Win32 Node",
            r"^Node Label",
            r"^Domain Name",
            r"^NetBIOS Hostname",
            r"^NetBIOS Computer Name",
            r"^IP Address(es)",
        ]

        is_header = False
        for pattern in section_patterns:
            if re.match(pattern, line, re.IGNORECASE):
                current_section = line.strip()
                section_entries = []
                is_header = True
                break

        if not is_header and current_section:
            section_entries.append(line)

    # Collect last section
    if current_section and section_entries:
        sections[current_section] = section_entries

    return sections


def format_windows_response(parsed_output: ParsedOutput, include_raw: bool = True) -> str:
    """Format a parsed Windows command response into a human-readable report.

    Args:
        parsed_output: The ParsedOutput from parse_cmd_output.
        include_raw: Whether to include the raw output in the formatted response.

    Returns:
        A formatted string representation of the command execution result.
    """
    lines = []

    # Header
    lines.append("=" * 60)
    lines.append(f"Windows Command Execution Report")
    lines.append(f"Command: {parsed_output.command_type}")
    lines.append(f"Raw Output Length: {len(parsed_output.raw_output)} characters")
    if parsed_output.errors:
        lines.append(f"Errors: {'; '.join(parsed_output.errors)}")
    else:
        lines.append("Errors: None")
    lines.append("=" * 60)

    # Structured sections
    for section_name, entries in parsed_output.sections.items():
        lines.append("")
        lines.append(f"[{section_name.upper()}]")
        if isinstance(entries[0], dict):
            for entry in entries:
                lines.append(f"  {entry}")
        else:
            for entry in entries:
                lines.append(f"  - {entry}")

    # Raw output (optional)
    if include_raw and parsed_output.raw_output.strip():
        lines.append("")
        lines.append("-" * 60)
        lines.append("RAW OUTPUT:")
        lines.append("-" * 60)
        for line in parsed_output.raw_output.split("\n"):
            lines.append(f"  {line}")

    return "\n".join(lines)


__all__ = [
    "execute_windows_command",
    "parse_cmd_output",
    "format_windows_response",
    "WindowsCommandResult",
    "ParsedOutput",
]

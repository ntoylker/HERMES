import subprocess
import re
from typing import Optional


def execute_windows_command(command: str, timeout: int = 30) -> tuple[str, str]:
    """Execute a command via cmd.exe on Windows with CREATE_NEW_CONSOLE flag.
    
    Args:
        command: The command to execute (e.g., 'ipconfig /all', 'netstat -ano')
        timeout: Timeout in seconds for the command execution
        
    Returns:
        Tuple of (stdout, stderr) from the cmd.exe process
    """
    try:
        result = subprocess.run(
            ['cmd.exe'],
            shell=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            input=command + '\n',
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**subprocess.os.environ, 'PATH': r'C:\Windows\System32'}
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command '{command}' timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("cmd.exe not found. Ensure Windows environment is accessible.")


def parse_cmd_output(output: str) -> dict[str, list[str]]:
    """Parse cmd.exe output into structured sections based on command type.
    
    Args:
        output: Raw stdout from a cmd.exe process
        
    Returns:
        Dictionary mapping command types to parsed results
    """
    result = {}
    
    # Parse ipconfig /all output
    if 'ipconfig' in output.lower():
        sections = re.split(r'\n\s*\d+\.\s+.*\n', output)
        for section in sections:
            if section.strip():
                lines = [line.strip() for line in section.strip().split('\n') if line.strip()]
                result['ipconfig'] = lines
    
    # Parse netstat -ano output
    if 'netstat' in output.lower():
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        result['netstat'] = lines
    
    # Parse tasklist /V output
    if 'tasklist' in output.lower():
        lines = [line.strip() for line in output.split('\n') if line.strip()]
        result['tasklist'] = lines
    
    # Parse systeminfo output
    if 'systeminfo' in output.lower():
        sections = re.split(r'\n\s*OS Name.*\n', output)
        for section in sections:
            if section.strip():
                lines = [line.strip() for line in section.strip().split('\n') if line.strip()]
                result['systeminfo'] = lines
    
    return result


def format_windows_response(command: str, stdout: str, stderr: str) -> dict[str, any]:
    """Format the response from a Windows command execution.
    
    Args:
        command: The executed command
        stdout: Standard output from cmd.exe
        stderr: Standard error from cmd.exe
        
    Returns:
        Dictionary with structured response data
    """
    parsed = parse_cmd_output(stdout)
    
    return {
        'command': command,
        'status': 'success' if not stderr else ('warning' if stdout.strip() else 'error'),
        'stdout': stdout,
        'stderr': stderr,
        'parsed': parsed,
        'exit_code': 0 if not stderr and stdout.strip() else (1 if stderr else None)
    }


__all__ = ['execute_windows_command', 'parse_cmd_output', 'format_windows_response']

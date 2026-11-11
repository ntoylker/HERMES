from data.code_scripts_PAST.stage3_DIMOS_test_v7_mvp2.TASK_001_models import ExecutionResult
import os
import subprocess
import stat


def execute_shell_command(command: str, timeout: float = 30.0) -> ExecutionResult:
    """Execute a shell command using subprocess.Popen and return typed results."""
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output, stderr = process.communicate(timeout=timeout)
        duration_ms = process.wait() * 1000 if process.poll() is not None else 0.0
        
        return ExecutionResult(
            command=command,
            output=output,
            status=process.returncode,
            duration_ms=duration_ms,
            exit_code=process.returncode,
            stderr=stderr
        )
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return ExecutionResult(
            command=command,
            output='',
            status=-1,
            duration_ms=timeout * 1000,
            exit_code=-1,
            stderr='Command timed out'
        )


def get_current_user() -> str:
    """Retrieve the current user's login name using os module."""
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get('USER', 'unknown')


def is_root_check() -> bool:
    """Check if the process is running as root using stat module."""
    try:
        uid = os.getuid()
        return uid == 0
    except (OSError, AttributeError):
        return False

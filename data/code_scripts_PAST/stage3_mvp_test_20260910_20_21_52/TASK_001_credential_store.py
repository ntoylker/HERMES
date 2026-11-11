"""Credential store data model for harvested cloud credentials and SSH keys."""

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AWSCredential:
    """Represents an AWS credential entry (T1552.004 - Cloud Credentials).
    
    Attributes:
        access_key_id: The AWS Access Key ID.
        secret_access_key: The AWS Secret Access Key.
        session_token: Optional temporary session token for STS credentials.
        region: Optional AWS region the credential applies to.
        profile_name: Optional IAM profile name associated with the key.
    """

    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None
    profile_name: Optional[str] = None


@dataclass
class SSHKeyEntry:
    """Represents an SSH key entry (T1552.004 - SSH Keys).
    
    Attributes:
        private_key_path: Path to the private key file on disk.
        public_key_path: Path to the corresponding public key file.
        known_hosts: List of host entries for this key's authorized hosts.
        comment: Optional key comment (e.g., "user@host").
    """

    private_key_path: str
    public_key_path: str
    known_hosts: list[str] = field(default_factory=list)
    comment: Optional[str] = None


@dataclass
class CredentialStore:
    """Container for storing multiple credential entries.
    
    Attributes:
        aws_credentials: List of AWSCredential instances.
        ssh_keys: List of SSHKeyEntry instances.
    """

    aws_credentials: list[AWSCredential] = field(default_factory=list)
    ssh_keys: list[SSHKeyEntry] = field(default_factory=list)


def serialize_aws_credential(credential: AWSCredential) -> dict[str, str]:
    """Serialize an AWSCredential to a JSON-serializable dictionary."""
    return {
        "access_key_id": credential.access_key_id,
        "secret_access_key": credential.secret_access_key,
        "session_token": credential.session_token or "",
        "region": credential.region or "",
        "profile_name": credential.profile_name or "",
    }


def serialize_ssh_key_entry(entry: SSHKeyEntry) -> dict[str, str]:
    """Serialize an SSHKeyEntry to a JSON-serializable dictionary."""
    return {
        "private_key_path": entry.private_key_path,
        "public_key_path": entry.public_key_path,
        "known_hosts": entry.known_hosts,
        "comment": entry.comment or "",
    }


def serialize_credential_store(store: CredentialStore) -> dict[str, list[dict]]:
    """Serialize a CredentialStore to a JSON-serializable dictionary."""
    return {
        "aws_credentials": [serialize_aws_credential(c) for c in store.aws_credentials],
        "ssh_keys": [serialize_ssh_key_entry(k) for k in store.ssh_keys],
    }


def deserialize_aws_credential(data: dict[str, str]) -> AWSCredential:
    """Deserialize an AWSCredential from a dictionary."""
    return AWSCredential(
        access_key_id=data["access_key_id"],
        secret_access_key=data["secret_access_key"],
        session_token=data.get("session_token"),
        region=data.get("region"),
        profile_name=data.get("profile_name"),
    )


def deserialize_ssh_key_entry(data: dict[str, str]) -> SSHKeyEntry:
    """Deserialize an SSHKeyEntry from a dictionary."""
    return SSHKeyEntry(
        private_key_path=data["private_key_path"],
        public_key_path=data["public_key_path"],
        known_hosts=data.get("known_hosts", []),
        comment=data.get("comment"),
    )


def deserialize_credential_store(data: dict[str, list[dict]]) -> CredentialStore:
    """Deserialize a CredentialStore from a dictionary."""
    store = CredentialStore()
    for cred_data in data.get("aws_credentials", []):
        store.aws_credentials.append(deserialize_aws_credential(cred_data))
    for key_data in data.get("ssh_keys", []):
        store.ssh_keys.append(deserialize_ssh_key_entry(key_data))
    return store


if __name__ == "__main__":
    # Demo usage
    store = CredentialStore()

    store.aws_credentials.append(
        AWSCredential(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="AQoDYXdzEPT//////////wEXAMPLEtc764nNrNdwBsK698...",
            region="us-east-1",
            profile_name="default",
        )
    )

    store.ssh_keys.append(
        SSHKeyEntry(
            private_key_path="/home/user/.ssh/id_rsa",
            public_key_path="/home/user/.ssh/id_rsa.pub",
            known_hosts=["ec2.amazonaws.com:22"],
            comment="user@production-server",
        )
    )

    print("Serialized store:")
    print(json.dumps(serialize_credential_store(store), indent=2))

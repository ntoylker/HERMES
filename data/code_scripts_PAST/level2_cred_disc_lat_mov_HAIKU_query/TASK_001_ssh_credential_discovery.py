import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SshCredentials:
    """Container for discovered SSH credentials."""
    private_key_paths: list[str]
    known_hosts: list[str]


def discover_ssh_credentials() -> SshCredentials:
    """Scan the user's home directory for SSH private keys and parse known_hosts.

    Returns:
        SshCredentials object containing lists of private key paths and extracted hostnames.
    """
    ssh_dir = Path(os.path.expanduser("~")).joinpath(".ssh")
    if not ssh_dir.exists():
        return SshCredentials(private_key_paths=[], known_hosts=[])

    # Common SSH private key file names to search for
    key_patterns = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]
    private_key_paths: list[str] = []

    for pattern in key_patterns:
        keys_path = ssh_dir / f"{pattern}*"
        if keys_path.exists():
            private_key_paths.extend(keys_path.glob("*"))

    # Parse ~/.ssh/known_hosts file
    known_hosts_file = ssh_dir / "known_hosts"
    known_hosts: list[str] = []

    if known_hosts_file.exists():
        with open(known_hosts_file, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Split on spaces and commas to extract hostnames/IPs
                entries = line.split() + [entry for entry in line.split(",")]
                for entry in entries:
                    # Filter out hashed entries (contain ':' characters)
                    if ":" not in entry:
                        known_hosts.append(entry)

    return SshCredentials(private_key_paths=private_key_paths, known_hosts=known_hosts)


if __name__ == "__main__":
    creds = discover_ssh_credentials()
    print(f"Discovered {len(creds.private_key_paths)} private key(s):")
    for path in creds.private_key_paths:
        print(f"  - {path}")

    print(f"\nFound {len(creds.known_hosts)} known host(s):")
    for host in creds.known_hosts:
        print(f"  - {host}")

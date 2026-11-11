"""
File Discovery Collector - Single-shot file discovery and collection pipeline.
Implements T1083 (file enumeration), T1074.001 (local data staging), T1119 (automated collection),
and T1005 (data from local system) using only filesystem I/O on Ubuntu 22.04 LTS.

Scans /home, /tmp, and /var/log for sensitive files matching SSH key patterns,
config extensions, shell history files, and credential keywords. Copies readable
matches to results/ preserving relative paths and generates discovery_manifest.json.
"""

import os
import re
import shutil
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class FileMetadata:
    """Represents metadata for a discovered file."""
    path: str
    relative_path: str
    size: int
    readable: bool
    modification_time: float
    matched_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "relative_path": self.relative_path,
            "size": self.size,
            "readable": self.readable,
            "modification_time": self.modification_time,
            "matched_patterns": self.matched_patterns,
        }


@dataclass
class DiscoveryResult:
    """Represents the complete discovery result containing all discovered files."""
    total_files_found: int = 0
    readable_files_copied: int = 0
    unreadable_files_skipped: int = 0
    manifest_path: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_files_found": self.total_files_found,
            "readable_files_copied": self.readable_files_copied,
            "unreadable_files_skipped": self.unreadable_files_skipped,
            "manifest_path": self.manifest_path,
        }


def get_ssh_key_patterns() -> List[str]:
    """Return regex patterns for SSH key files."""
    return [r"id_rsa$", r"id_ed25519$", r"id_ecdsa$", r"id_x509$", r".*\.pem$"]


def get_config_patterns() -> List[str]:
    """Return regex patterns for config file extensions."""
    return [r"\.conf$", r"\.cfg$", r"\.ini$", r"\.xml$", r"\.json$", r"\.yaml$", r"\.yml$"]


def get_history_patterns() -> List[str]:
    """Return regex patterns for shell history files."""
    return [r".*\.bash_history$", r".*\.zsh_history$", r".*\.history$", r"~/.bash_history", r"~/.zsh_history"]


def get_credential_keywords() -> List[str]:
    """Return regex patterns for credential-related keywords in filenames."""
    return [
        r"\.ssh/",
        r"\.pgpass$",
        r"\.netrc$",
        r"\.gnupg",
        r"credentials",
        r"passwords",
        r"secrets",
        r"\.env$",
        r"\.secret$",
    ]


def get_all_patterns() -> List[str]:
    """Return all regex patterns combined."""
    return (
        get_ssh_key_patterns() +
        get_config_patterns() +
        get_history_patterns() +
        get_credential_keywords()
    )


def matches_pattern(filename: str, patterns: List[str]) -> bool:
    """Check if a filename matches any of the given regex patterns."""
    for pattern in patterns:
        if re.search(pattern, filename):
            return True
    return False


def get_matched_patterns(filename: str) -> List[str]:
    """Get all matching patterns for a given filename."""
    matched = []
    for pattern in get_all_patterns():
        if re.search(pattern, filename):
            matched.append(pattern)
    return matched


def scan_directory(base_path: str) -> List[FileMetadata]:
    """
    Recursively scan a directory for sensitive files.
    
    Args:
        base_path: The root directory to scan (e.g., /home, /tmp, /var/log).
        
    Returns:
        A list of FileMetadata objects for all discovered files.
    """
    results = []
    patterns = get_all_patterns()

    for root, dirs, files in os.walk(base_path):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Skip if not a regular file (skip symlinks, sockets, etc.)
            try:
                stat_info = os.stat(file_path)
                if not os.path.isfile(file_path):
                    continue
            except OSError:
                continue

            relative_path = os.path.relpath(file_path, "/")

            # Check readability without elevated privileges
            readable = os.access(file_path, os.R_OK)

            # Get file size and modification time
            try:
                size = os.path.getsize(file_path)
                mtime = os.path.getmtime(file_path)
            except OSError:
                continue

            matched_patterns = get_matched_patterns(filename)

            metadata = FileMetadata(
                path=file_path,
                relative_path=relative_path,
                size=size,
                readable=readable,
                modification_time=mtime,
                matched_patterns=matched_patterns,
            )
            results.append(metadata)

    return results


def copy_file_to_results(file_path: str, relative_path: str, results_dir: str) -> bool:
    """
    Copy a file to the results directory preserving its relative path.
    
    Args:
        file_path: The absolute source path of the file.
        relative_path: The relative path from the scan root.
        results_dir: The destination directory for copied files.
        
    Returns:
        True if copy was successful, False otherwise.
    """
    dest_path = os.path.join(results_dir, relative_path)

    # Create parent directories if they don't exist
    dest_parent = os.path.dirname(dest_path)
    if not os.path.exists(dest_parent):
        try:
            os.makedirs(dest_parent, exist_ok=True)
        except OSError as e:
            print(f"  Warning: Could not create directory {dest_parent}: {e}")
            return False

    # Copy file preserving metadata (mode, timestamps)
    try:
        shutil.copy2(file_path, dest_path)
        return True
    except OSError as e:
        print(f"  Warning: Could not copy {file_path} to {dest_path}: {e}")
        return False


def generate_manifest(manifest_path: str, metadata_list: List[FileMetadata]) -> None:
    """
    Generate a JSON manifest file containing discovery results.
    
    Args:
        manifest_path: The path where the manifest will be written.
        metadata_list: List of FileMetadata objects to include in the manifest.
    """
    manifest = {
        "discovery_manifest": {
            "version": "1.0",
            "generated_by": "file_discovery_collector.py",
            "scan_targets": ["/home", "/tmp", "/var/log"],
            "total_files_found": len(metadata_list),
            "files": [],
        }
    }

    for metadata in metadata_list:
        manifest["discovery_manifest"]["files"].append(metadata.to_dict())

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)


def run_discovery() -> DiscoveryResult:
    """
    Execute the complete file discovery and collection pipeline.
    
    Scans /home, /tmp, and /var/log for sensitive files matching SSH key patterns,
    config extensions, shell history files, and credential keywords. Copies readable
    matches to results/ preserving relative paths and generates discovery_manifest.json.
    
    Returns:
        A DiscoveryResult object containing summary statistics.
    """
    # Define scan targets
    scan_targets = ["/home", "/tmp", "/var/log"]

    # Create results directory if it doesn't exist
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    # Collect all discovered files
    all_metadata: List[FileMetadata] = []

    for target in scan_targets:
        print(f"Scanning {target}...")
        metadata_list = scan_directory(target)
        all_metadata.extend(metadata_list)

    # Separate readable and unreadable files
    readable_files = [m for m in all_metadata if m.readable]
    unreadable_files = [m for m in all_metadata if not m.readable]

    # Copy readable files to results/
    copied_count = 0
    skipped_count = 0

    print(f"\nCopying {len(readable_files)} readable file(s) to '{results_dir}/'...")
    for metadata in readable_files:
        success = copy_file_to_results(
            metadata.path,
            metadata.relative_path,
            results_dir,
        )
        if success:
            copied_count += 1
        else:
            skipped_count += 1

    # Generate manifest
    manifest_path = os.path.join(results_dir, "discovery_manifest.json")
    generate_manifest(manifest_path, all_metadata)

    # Build and return result
    result = DiscoveryResult(
        total_files_found=len(all_metadata),
        readable_files_copied=copied_count,
        unreadable_files_skipped=skipped_count,
        manifest_path=manifest_path,
    )

    print(f"\n{'='*60}")
    print("DISCOVERY COMPLETE")
    print(f"{'='*60}")
    print(f"  Total files found:      {result.total_files_found}")
    print(f"  Readable (copied):      {result.readable_files_copied}")
    print(f"  Unreadable (skipped):   {result.unreadable_files_skipped}")
    print(f"  Manifest written to:    {manifest_path}")
    print(f"{'='*60}\n")

    return result


def main() -> None:
    """Main entry point for the file discovery collector."""
    run_discovery()


if __name__ == "__main__":
    main()

import json
import os
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class FileManifest:
    path: str
    size: int
    timestamp: str


def discover_and_archive_files(source_dir: str = "/tmp/test_data", output_dir: str = "results/") -> list[FileManifest]:
    """
    Recursively discovers generic text and data files (*.txt, *.csv) within a designated safe test directory,
    copies them to a local backup directory with flattened paths, and generates a summary manifest.

    Args:
        source_dir: The source directory to scan (default: /tmp/test_data).
        output_dir: The destination directory for copied files (default: results/).

    Returns:
        A list of FileManifest dataclasses representing the discovered and archived files.
    """
    manifest_entries = []

    source_path = Path(source_dir)
    output_path = Path(output_dir)

    if not source_path.exists():
        raise FileNotFoundError(f"Source directory does not exist: {source_path}")

    for file_path in source_path.rglob("*.txt"):
        if os.access(file_path, os.R_OK):
            relative_path = str(file_path.relative_to(source_path)).replace(os.sep, "_")
            dest_path = output_path / relative_path

            shutil.copy2(file_path, dest_path)

            manifest_entries.append(FileManifest(
                path=str(dest_path),
                size=file_path.stat().st_size,
                timestamp=os.path.getmtime(file_path).strftime("%Y-%m-%d %H:%M:%S")
            ))

    for file_path in source_path.rglob("*.csv"):
        if os.access(file_path, os.R_OK):
            relative_path = str(file_path.relative_to(source_path)).replace(os.sep, "_")
            dest_path = output_path / relative_path

            shutil.copy2(file_path, dest_path)

            manifest_entries.append(FileManifest(
                path=str(dest_path),
                size=file_path.stat().st_size,
                timestamp=os.path.getmtime(file_path).strftime("%Y-%m-%d %H:%M:%S")
            ))

    with open(output_path / "discovery_manifest.json", "w") as f:
        json.dump([asdict(entry) for entry in manifest_entries], f, indent=2)

    return manifest_entries


if __name__ == "__main__":
    results = discover_and_archive_files()
    print(f"Discovered and archived {len(results)} files.")

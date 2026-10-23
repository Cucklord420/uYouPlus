#!/usr/bin/env python3
"""Extract an authenticated uYou Debian archive without reusing stale payload files."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def _require_directory(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise ValueError(f"required package directory is missing: {path.name}") from None
    if not stat.S_ISDIR(mode):
        raise ValueError(f"required package path is not a real directory: {path.name}")


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError:
        raise ValueError(f"required package file is missing: {path.name}") from None
    if not stat.S_ISREG(mode):
        raise ValueError(f"required package path is not a regular file: {path.name}")


def _validate_payload(library: Path) -> None:
    _require_directory(library)
    _require_directory(library / "MobileSubstrate")
    _require_directory(library / "MobileSubstrate" / "DynamicLibraries")
    _require_regular_file(
        library / "MobileSubstrate" / "DynamicLibraries" / "uYou.dylib"
    )
    _require_directory(library / "Application Support")
    _require_directory(library / "Application Support" / "uYouBundle.bundle")


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def extract_package(package: Path, destination: Path) -> None:
    package = Path(package)
    destination = Path(destination)
    if package.is_symlink() or not package.is_file():
        raise ValueError("uYou package must be a regular file")
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("uYou build destination must be an existing real directory")

    package = package.resolve(strict=True)
    destination = destination.resolve(strict=True)
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb is None:
        raise RuntimeError("dpkg-deb is required to extract the verified uYou package")

    with tempfile.TemporaryDirectory(prefix="uyou-deb-stage-") as stage_name:
        stage = Path(stage_name)
        result = subprocess.run(
            [dpkg_deb, "--extract", str(package), str(stage)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"dpkg-deb extraction failed with exit status {result.returncode}"
            )

        staged_library = stage / "Library"
        _validate_payload(staged_library)

        with tempfile.TemporaryDirectory(
            prefix=".uyou-library-install-", dir=str(destination)
        ) as install_name:
            new_library = Path(install_name) / "Library"
            shutil.copytree(staged_library, new_library, symlinks=True)
            _validate_payload(new_library)

            installed_library = destination / "Library"
            backup = None
            if _exists(installed_library):
                _require_directory(installed_library)
                backup = Path(
                    tempfile.mkdtemp(
                        prefix=".uyou-library-backup-", dir=str(destination)
                    )
                )
                backup.rmdir()
                os.replace(installed_library, backup)

            try:
                os.replace(new_library, installed_library)
            except OSError:
                if backup is not None:
                    try:
                        os.replace(backup, installed_library)
                        backup = None
                    except OSError as restore_error:
                        raise RuntimeError(
                            "new package could not be installed; prior Library "
                            f"payload remains at {backup}"
                        ) from restore_error
                raise

            if backup is not None:
                shutil.rmtree(backup)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        extract_package(args.file, args.destination)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"uYou package extraction rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

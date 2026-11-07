#!/usr/bin/env python3
"""Check local wheel/sdist contents and exact public source assets before install."""

import argparse
import email.parser
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tomllib
import zipfile


FORBIDDEN = {".git", ".planning", ".superpowers", ".worker", ".venv", "__pycache__"}
MAX_TOTAL = 256 * 1024 * 1024


def safe_name(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and all(part not in {".", ".."} for part in path.parts), name
    assert not FORBIDDEN.intersection(path.parts) and not name.endswith((".pyc", ".pyo")), name


def public_files(root, relative):
    selected = root / relative
    for path in sorted(selected.rglob("*")):
        if path.is_file() and not FORBIDDEN.intersection(path.relative_to(root).parts) and path.suffix not in {".pyc", ".pyo"}:
            assert not path.is_symlink(), path
            yield path.relative_to(root).as_posix(), path.read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    options = parser.parse_args(argv)
    root = options.source_root.absolute()
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    wheels = list(options.dist.glob("*.whl"))
    sdists = list(options.dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, "one wheel and one sdist are required"
    wheel, sdist = wheels[0], sdists[0]

    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        assert sum(entry.file_size for entry in entries) <= MAX_TOTAL
        for entry in entries:
            safe_name(entry.filename)
            assert not stat.S_ISLNK(entry.external_attr >> 16), entry.filename
        for relative, data in public_files(root, "src/tallylock"):
            expected = relative.removeprefix("src/")
            assert archive.read(expected) == data, f"missing or changed wheel asset: {expected}"
        metadata_files = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata_files) == 1
        metadata_path = metadata_files[0]
        metadata = email.parser.BytesParser().parsebytes(archive.read(metadata_path))
        assert metadata["Name"] == project["name"] and metadata["Version"] == project["version"]
        assert metadata["License-Expression"] == "Apache-2.0"
        prefix = metadata_path.removesuffix("METADATA")
        for name in ("LICENSE", "NOTICE"):
            assert archive.read(prefix + "licenses/" + name) == (root / name).read_bytes()
        assert b"tallylock = tallylock.cli:main" in archive.read(prefix + "entry_points.txt")
        wheel_files = len(entries)

    required = {name: (root / name).read_bytes() for name in
                ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "RUNBOOK.md",
                 "docs/PROTOCOL.md", "docs/QUICKSTART.md", "docs/INTEGRATION.md",
                 "conformance/README.md", "tools/reference_verify.py", "tools/check_install.py",
                 "tools/check_distribution.py", "tests/reference_corpus_author.py")}
    for directory in ("src/tallylock", "tests", "docs", "examples/basic", "conformance", "tools"):
        required.update(public_files(root, directory))
    with tarfile.open(sdist, "r:gz") as archive:
        entries = archive.getmembers()
        assert sum(entry.size for entry in entries) <= MAX_TOTAL
        roots = {PurePosixPath(entry.name).parts[0] for entry in entries}
        assert len(roots) == 1
        prefix = next(iter(roots)) + "/"
        actual = {}
        for entry in entries:
            safe_name(entry.name)
            assert entry.isdir() or entry.isfile(), f"nonregular source archive member: {entry.name}"
            if entry.isfile():
                actual[entry.name.removeprefix(prefix)] = entry
        missing = sorted(required.keys() - actual.keys())
        assert not missing, f"source archive missing public source inputs: {missing[:20]}"
        for name, data in required.items():
            assert archive.extractfile(actual[name]).read() == data, f"changed source archive asset: {name}"
        sdist_files = len(actual)

    reports = []
    for path, count in ((wheel, wheel_files), (sdist, sdist_files)):
        data = path.read_bytes()
        reports.append({"file": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                        "files": count})
    print(json.dumps({"format": "prove.distribution-audit.v1", "code": 0,
                      "version": project["version"], "artifacts": reports}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

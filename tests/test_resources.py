"""Installed static resources must exist independently of a repository cwd."""
from importlib import resources
from pathlib import Path
import json
import os
import subprocess
import sys


def test_generic_packaged_examples_match_source():
    packaged = resources.files('tallylock').joinpath('data/examples/basic')
    source = Path(__file__).parents[1] / 'examples/basic'
    for name in ('README.md', 'manifest.json', 'outputs/metrics.json', 'outputs/run-log.txt'):
        assert packaged.joinpath(name).read_bytes() == (source / name).read_bytes()


def test_conformance_resources_include_every_static_file():
    packaged = resources.files('tallylock').joinpath('data/conformance')
    assert packaged.joinpath('index.json').is_file()
    assert packaged.joinpath('canonical.json').is_file()
    assert packaged.joinpath('trees.json').is_file()
    assert packaged.joinpath('cases/bad-profile.json').is_file()


def test_installed_resource_lookup_without_pythonpath_or_repository_cwd(tmp_path):
    script = ("from importlib.resources import files; import json; "
              "root=files('tallylock'); "
              "print(json.dumps([root.joinpath('data/examples/basic/manifest.json').is_file(),"
              "root.joinpath('data/conformance/cases/bad-profile.json').is_file()]))")
    environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
    result = subprocess.run([sys.executable, '-I', '-c', script], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [True, True]

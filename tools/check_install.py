#!/usr/bin/env python3
"""Exercise an already installed TallyLock without importing its source checkout.

Run inside an externally network-disabled environment for the OS-level gate.
The per-command Python audit hook additionally rejects socket operations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


GUARDED_CONSOLE = r'''
import runpy, sys
def deny_socket(event, arguments):
    if event.startswith('socket.'):
        raise AssertionError('offline installation check attempted a socket operation')
sys.addaudithook(deny_socket)
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
'''

RESOURCE_PROBE = r'''
import hashlib, importlib.metadata, importlib.resources, json, pathlib, sys
import tallylock
origin = pathlib.Path(tallylock.__file__).resolve()
assert origin.is_relative_to(pathlib.Path(sys.prefix).resolve()), origin
package = importlib.resources.files('tallylock')
required = ['data/schemas/protocol-v1.json', 'data/conformance/index.json',
            'data/conformance/canonical.json', 'data/conformance/trees.json',
            'data/examples/basic/manifest.json',
            'data/examples/basic/outputs/metrics.json',
            'data/examples/basic/outputs/run-log.txt']
digests = {}
for name in required:
    data = package.joinpath(name).read_bytes()
    assert data, name
    digests[name] = hashlib.sha256(data).hexdigest()
index = json.loads(package.joinpath('data/conformance/index.json').read_bytes())
for case in index['cases']:
    relative = pathlib.PurePosixPath(case['file'])
    assert relative.parts[0] == 'cases' and not relative.is_absolute()
    assert all(part not in ('', '.', '..') for part in relative.parts)
    assert package.joinpath('data/conformance', *relative.parts).read_bytes()
print(json.dumps({'version': importlib.metadata.version('tallylock'),
                  'module': str(origin), 'cases': len(index['cases']), 'resources': digests}))
'''

SYNTHETIC_ANCHORS = r'''
# Fabricated headers exercise internal consistency only. They are not node evidence.
import hashlib, json, pathlib, sys
from bitcoin.core import CBlockHeader, b2lx
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
def deny_socket(event, arguments):
    if event.startswith('socket.'):
        raise AssertionError('synthetic fixture attempted a socket operation')
sys.addaudithook(deny_socket)
receipt, cache_path = map(pathlib.Path, sys.argv[1:])
(receipt / 'proofs').mkdir()
blocks = {}
for height, name in enumerate(('manifest', 'result'), 1):
    digest = hashlib.sha256((receipt / (name + '.json')).read_bytes()).digest()
    timestamp = Timestamp(digest)
    timestamp.attestations.add(BitcoinBlockHeaderAttestation(height))
    context = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), timestamp).serialize(context)
    (receipt / 'proofs' / (name + '.ots')).write_bytes(context.getbytes())
    header = CBlockHeader(hashMerkleRoot=digest, nTime=1700000000 + height)
    blocks[str(height)] = {'header': header.serialize().hex(), 'hash': b2lx(header.GetHash()),
                           'confirmations': 8 - height}
cache = {'format': 'prove.chain.v1', 'exported_at': '2026-11-06T00:00:00Z',
         'source': 'FABRICATED test cache. Internal consistency only, never node evidence.',
         'tip': {'height': 7, 'hash': 'ab' * 32},
         'node': {'chain': 'main', 'initialblockdownload': False, 'blocks': 7,
                  'headers': 7, 'verificationprogress': '1'}, 'blocks': blocks}
cache_path.write_text(json.dumps(cache))
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True, help="clean installed environment's Python")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-index-sha256")
    options = parser.parse_args(argv)
    interpreter = options.python.absolute()
    console = interpreter.parent / "tallylock"
    if not interpreter.is_file() or not console.is_file():
        raise AssertionError("installed interpreter and console entrypoint are required")
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"}}

    with tempfile.TemporaryDirectory(prefix="prove-installed-") as temporary:
        workspace = Path(temporary)

        def execute(command, *, expected=0):
            result = subprocess.run(command, cwd=workspace, env=environment, capture_output=True,
                                    text=True, timeout=60, check=False)
            if result.returncode != expected:
                raise AssertionError(f"command exited {result.returncode}, expected {expected}: "
                                     f"{result.stdout[:4000]} {result.stderr[:2000]}")
            return result

        def prove(arguments, *, expected=0):
            # This runs the installed console script under an isolated interpreter.
            command = [str(interpreter), "-I", "-c", GUARDED_CONSOLE, str(console), *arguments]
            result = execute(command, expected=expected)
            report = json.loads(result.stdout)
            assert report["code"] == expected, report
            return report

        version = execute([str(console), "--version"]).stdout
        assert options.expected_version in version
        assert "usage:" in execute([str(console), "--help"]).stdout.lower()
        assert options.expected_version in execute([str(interpreter), "-I", "-m", "tallylock", "--version"]).stdout
        resources = json.loads(execute([str(interpreter), "-I", "-c", RESOURCE_PROBE]).stdout)
        assert resources["version"] == options.expected_version
        if options.expected_index_sha256:
            assert resources["resources"]["data/conformance/index.json"] == options.expected_index_sha256

        initialized = prove(["init", "--out", "manifest.json", "--name", "Installed generic smoke"])
        assert initialized["local_state"] == "initialized"
        original_manifest = (workspace / "manifest.json").read_bytes()
        registered = prove(["pre-register", "manifest.json", "--receipt", "receipt"])
        assert registered["local_state"] == "registered" and registered["receipt_id"] is None
        registration_id = registered["registration_id"]
        assert hashlib.sha256(original_manifest).hexdigest() == registration_id
        prove(["verify", "receipt", "--policy", "integrity-only"], expected=3)

        outputs = workspace / "ordinary-outputs"
        outputs.mkdir()
        source = {"Metrics.json": b'{"successes":1,"total":2,"value":0.5}\n',
                  "Nested Results/Log.txt": "No model or private service. Café.\n".encode()}
        for name, data in source.items():
            target = outputs / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        sealed = prove(["seal", "receipt", "--artifacts", str(outputs)])
        assert sealed["local_state"] == "sealed" and sealed["registration_id"] == registration_id
        assert sealed["anchor_action"]["state"] == "not_requested"
        receipt = workspace / "receipt"
        assert (receipt / "manifest.json").read_bytes() == original_manifest
        assert hashlib.sha256((receipt / "result.json").read_bytes()).hexdigest() == sealed["receipt_id"]
        for name, data in source.items():
            assert (outputs / name).read_bytes() == data
            assert (receipt / "artifacts" / name).read_bytes() == data

        local = prove(["verify", "receipt", "--offline", "--policy", "integrity-only",
                       "--chain-cache", "absent-and-irrelevant.json"])
        assert local["scope"] == "full" and local["artifact_integrity"]["files"] == 2
        assert local["record_integrity"]["state"] == "checked" and local["score"]["state"] == "unavailable"
        assert local["execution"] == local["model"]["state"] == "unverified"
        prove(["verify", "receipt", "--offline", "--policy", "anchored"], expected=3)
        friendly = prove(["verify", "receipt", "--offline"])
        assert friendly["timestamp_checked"] is False and friendly["effective_policy"] == "integrity-only"
        inspection = prove(["inspect", "receipt"])
        assert inspection["verification"] == "not_performed" and inspection["inventory_count"] == 2
        assert inspection["receipt_id"] == sealed["receipt_id"]

        execute([str(interpreter), "-I", "-c", SYNTHETIC_ANCHORS,
                 str(receipt), str(workspace / "synthetic-chain.json")])
        prove(["verify", "receipt", "--offline", "--policy", "anchored"], expected=3)
        coherent = prove(["verify", "receipt", "--offline", "--chain-cache", "synthetic-chain.json"])
        assert coherent["chain_view"]["trust"] == "external_explicit"
        assert coherent["chain_view"]["freshness"] == "cached_only"
        assert coherent["manifest_anchor"]["state"] == coherent["result_anchor"]["state"] == "anchored"
        assert coherent["execution"] == coherent["model"]["state"] == "unverified"
        prove(["verify", "receipt", "--offline", "--chain-cache", "synthetic-chain.json",
               "--min-confirmations", "7"], expected=3)
        prove(["proof", "create", "receipt", "--index", "0", "--out", "synthetic-membership.json"])

        prove(["proof", "create", "receipt", "--index", "0", "--out", "membership.json", "--without-proofs"])
        membership = (workspace / "membership.json").read_bytes()
        prove(["proof", "create", "receipt", "--index", "0", "--out", "membership.json"], expected=2)
        assert (workspace / "membership.json").read_bytes() == membership
        prove(["proof", "create", "receipt", "--index", "0", "--out", "receipt/unlisted.json"], expected=2)
        assert not (receipt / "unlisted.json").exists()
        prove(["verify", "receipt", "--policy", "integrity-only"])
        hidden = workspace / "receipt-unavailable"
        receipt.rename(hidden)
        inclusion = prove(["verify", "--inclusion", "membership.json", "--policy", "integrity-only"])
        assert inclusion["record_integrity"]["state"] == "membership_checked"
        for dimension in ("artifact_integrity", "score", "coverage", "resources", "budget"):
            assert inclusion[dimension]["state"] == "not_checked"
        anchored_inclusion = prove(["verify", "--inclusion", "synthetic-membership.json", "--offline",
                                    "--chain-cache", "synthetic-chain.json"])
        assert anchored_inclusion["record_integrity"]["state"] == "membership_checked"
        assert anchored_inclusion["artifact_integrity"]["state"] == "not_checked"
        hidden.rename(receipt)
        with (receipt / "artifacts/Metrics.json").open("ab") as stream:
            stream.write(b"changed")
        invalid = prove(["verify", "receipt", "--offline"], expected=2)
        assert invalid["artifact_integrity"]["state"] == "invalid"
        prove(["--unknown-argument"], expected=2)

    print(json.dumps({"format": "prove.install-check.v1", "code": 0,
                      "version": resources["version"], "module": resources["module"],
                      "conformance_cases": resources["cases"], "resources": resources["resources"],
                      "socket_audit": "enforced_for_workflow_commands",
                      "synthetic_header_check": "internal_consistency_only_not_node_evidence",
                      "os_network_isolation": "must_be_supplied_by_runner"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

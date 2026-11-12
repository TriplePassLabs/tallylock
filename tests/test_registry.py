"""Export bundles and the registry of verified entries."""
import json
import os
import shutil

import pytest

from test_ledger import Project, three_runs, edit_line, ledger_lines, rewrite
from tallylock import ledger, registry, tally
from tallylock.errors import TallyLockError


def claim_for(repo, plan_id):
    return tally.format_claim(tally.plan_summary(repo, plan_id), tally.repo_summary(repo))


META = {"source": "tallylock", "trust": "anchored", "title": "Demo model", "submitted_by": "alice",
        "links": ["https://example.org/paper"]}


def test_export_makes_a_bundle_that_verifies_on_its_own(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    bundle = tmp_path / "bundle"
    registry.export(project.repo, plan.plan_id, bundle)
    assert (bundle / ".tallylock" / "plans" / plan.plan_id / "ledger.jsonl").is_file()
    shutil.rmtree(project.repo)
    checked = ledger.verify_ledger(bundle, plan.plan_id)
    assert checked["entries"] == 3
    assert not (bundle / ".tallylock" / "plans" / plan.plan_id / "ledger.jsonl").is_symlink()


def test_export_refuses_existing_output_unknown_plans_and_symlinks(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    taken = tmp_path / "taken"
    taken.mkdir()
    (taken / "file").write_text("x")
    with pytest.raises(TallyLockError):
        registry.export(project.repo, plan.plan_id, taken)
    with pytest.raises(TallyLockError):
        registry.export(project.repo, "0" * 64, tmp_path / "o1")
    with pytest.raises(TallyLockError):
        registry.export(project.repo, "not-an-id", tmp_path / "o2")
    outside = tmp_path / "secret.txt"
    outside.write_text("private")
    os.symlink(outside, plan.directory / "link")
    with pytest.raises(TallyLockError):
        registry.export(project.repo, plan.plan_id, tmp_path / "o3")
    assert not (tmp_path / "o3").exists()


def test_add_entry_stores_bundle_and_entry_json(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    entry = registry.add_entry(reg, project.repo, plan.plan_id, META)
    assert entry["format"] == "tallylock.registry-entry.v1"
    assert set(entry) == {"format", "plan_id", "claim", "source", "trust", "title", "submitted_by", "links"}
    assert entry["claim"] == claim_for(project.repo, plan.plan_id)
    saved = json.loads((reg / "entries" / plan.plan_id / "entry.json").read_text())
    assert saved == entry
    report = registry.verify_registry(reg)
    assert report["format"] == "tallylock.registry-verification.v1"
    assert report["verified"] == 1 and report["failed"] == 0
    assert report["entries"][0]["plan_id"] == plan.plan_id and report["entries"][0]["ok"] is True


def test_a_claim_at_an_earlier_ledger_head_is_refused(tmp_path):
    # Picking the head where the numbers looked best would hide the later runs behind the board's headline.
    project, plan, _ = three_runs(tmp_path)
    entries = ledger.verify_ledger(project.repo, plan.plan_id)["ledger"]
    early = tally.format_claim_fields(tally._fields(tally._summary(plan.plan_id, 1, entries[:1]), 1))
    assert tally.check_claim(project.repo, early)["verdict"] == "match"
    with pytest.raises(TallyLockError) as error:
        registry.add_entry(tmp_path / "reg", project.repo, plan.plan_id, {**META, "claim": early})
    assert "covers 1 of 3 runs" in error.value.message
    reg = tmp_path / "reg2"
    registry.add_entry(reg, project.repo, plan.plan_id, META)
    entry = json.loads((reg / "entries" / plan.plan_id / "entry.json").read_text())
    (reg / "entries" / plan.plan_id / "entry.json").write_text(json.dumps({**entry, "claim": early}))
    assert registry.verify_registry(reg)["failed"] == 1


def test_add_entry_accepts_an_exported_bundle(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    bundle = tmp_path / "bundle"
    registry.export(project.repo, plan.plan_id, bundle)
    reg = tmp_path / "reg"
    registry.add_entry(reg, bundle, plan.plan_id, META)
    assert registry.verify_registry(reg)["verified"] == 1


def test_add_entry_validates_metadata_and_refuses_duplicates(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    for bad in ({**META, "trust": "great"}, {**META, "title": ""}, {**META, "title": "x" * 500},
                {**META, "links": ["javascript:alert(1)"]}, {**META, "extra": 1},
                {k: v for k, v in META.items() if k != "source"}, {**META, "claim": "made up"}):
        with pytest.raises(TallyLockError):
            registry.add_entry(reg, project.repo, plan.plan_id, bad)
    assert not (reg / "entries" / plan.plan_id).exists()
    registry.add_entry(reg, project.repo, plan.plan_id, META)
    with pytest.raises(TallyLockError):
        registry.add_entry(reg, project.repo, plan.plan_id, META)


def test_add_entry_refuses_a_ledger_that_does_not_verify(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    lines = ledger_lines(plan)
    rewrite(plan, [lines[0], edit_line(lines[1], exit_code=0), lines[2]])
    with pytest.raises(TallyLockError):
        registry.add_entry(tmp_path / "reg", project.repo, plan.plan_id, META)


def test_verify_registry_flags_edited_entries_and_claims(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    registry.add_entry(reg, project.repo, plan.plan_id, META)
    entry_file = reg / "entries" / plan.plan_id / "entry.json"
    entry = json.loads(entry_file.read_text())
    entry["claim"] = entry["claim"].replace("0.742 best", "0.999 best")
    entry_file.write_text(json.dumps(entry))
    report = registry.verify_registry(reg)
    assert report["verified"] == 0 and report["failed"] == 1
    assert report["entries"][0]["ok"] is False and report["entries"][0]["reason"]


def test_verify_registry_flags_a_tampered_ledger_and_junk_entries(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    registry.add_entry(reg, project.repo, plan.plan_id, META)
    bundle_ledger = reg / "entries" / plan.plan_id / ".tallylock" / "plans" / plan.plan_id / "ledger.jsonl"
    lines = bundle_ledger.read_bytes().splitlines(keepends=True)
    bundle_ledger.write_bytes(b"".join([lines[0], edit_line(lines[1], exit_code=0), lines[2]]))
    junk = reg / "entries" / ("f" * 64)
    junk.mkdir()
    (junk / "entry.json").write_text("{not json")
    (reg / "entries" / "stray.txt").write_text("ignore me")
    report = registry.verify_registry(reg)
    assert report["failed"] == 2 and report["verified"] == 0
    assert all(item["ok"] is False for item in report["entries"])


def test_claims_from_multi_plan_repos_verify_and_say_other_plans_are_absent(tmp_path):
    project = Project(tmp_path, [{"stdout": "tallylock: score=0.5\n"}, {"stdout": "tallylock: score=0.6\n"}])
    plan = project.plan()
    project.run(plan)
    project.git.head = "b2" * 20
    second = project.plan()
    project.run(second)
    assert second.plan_id != plan.plan_id
    reg = tmp_path / "reg"
    entry = registry.add_entry(reg, project.repo, second.plan_id, META)
    assert "2 of 2 in repo" in entry["claim"]
    report = registry.verify_registry(reg)
    assert report["verified"] == 1
    assert report["entries"][0]["other_plans_not_in_bundle"] is True

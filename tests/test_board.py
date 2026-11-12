"""The static board: one HTML file, one inline script that only enhances, no remote assets, every string escaped."""
import json
import re

from test_ledger import three_runs, edit_line
from tallylock import board, registry

META = {"source": "tallylock", "trust": "anchored", "title": "Demo model", "submitted_by": "alice",
        "links": ["https://example.org/paper"]}


def make_registry(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    registry.add_entry(reg, project.repo, plan.plan_id, META)
    return reg, plan


def test_build_writes_index_and_entries(tmp_path):
    reg, plan = make_registry(tmp_path)
    out = tmp_path / "site"
    result = board.build(reg, out)
    assert sorted(p.name for p in out.iterdir()) == ["entries.json", "index.html"]
    page = (out / "index.html").read_text()
    data = json.loads((out / "entries.json").read_text())
    assert data["format"] == "tallylock.board.v1"
    assert result["rows"] == 1 and result["excluded"] == 0
    row = data["rows"][0]
    assert row["plan_id"] == plan.plan_id and row["title"] == "Demo model"
    assert row["best"] == "0.742" and row["runs"] == 3 and row["failed"] == 1
    assert row["trust"] == "anchored" and row["source"] == "tallylock"
    assert re.fullmatch(r"[0-9]+\.[0-9]{3}", row["score"]) and row["range"] is not None
    assert "tallylock check" in row["recheck"]
    for text in ("Demo model", "0.742", "anchored", "alice", row["claim"].split(";")[0]):
        assert text in page
    assert "tallylock check" in page


def test_page_is_static_and_themed(tmp_path):
    reg, _ = make_registry(tmp_path)
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    # One inline script for animation and copy buttons; it never writes HTML, and the page works without it.
    assert page.lower().count("<script") == 1 and "<script>" in page and "innerHTML" not in page
    assert "<details" in page and "<summary>" in page
    assert "prefers-color-scheme: light" in page and "color-scheme: dark light" in page and "<style>" in page
    assert not re.search(r"(src|href)=[\"']https?://(?!example\.org)", page)
    assert "—" not in page
    assert 'name="viewport"' in page


def test_hostile_strings_are_escaped(tmp_path):
    project, plan, _ = three_runs(tmp_path)
    reg = tmp_path / "reg"
    evil = {**META, "title": "<script>alert(1)</script>", "submitted_by": '"><img src=x onerror=alert(2)>',
            "source": "<b>x</b>"}
    registry.add_entry(reg, project.repo, plan.plan_id, evil)
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    assert page.lower().count("<script") == 1 and "<img" not in page and "<b>" not in page
    assert "&lt;script&gt;" in page


def test_rows_that_fail_verification_are_listed_apart(tmp_path):
    reg, plan = make_registry(tmp_path)
    ledger_file = reg / "entries" / plan.plan_id / ".tallylock" / "plans" / plan.plan_id / "ledger.jsonl"
    lines = ledger_file.read_bytes().splitlines(keepends=True)
    ledger_file.write_bytes(b"".join([lines[0], edit_line(lines[1], exit_code=0), lines[2]]))
    out = tmp_path / "site"
    result = board.build(reg, out)
    assert result["rows"] == 0 and result["excluded"] == 1
    data = json.loads((out / "entries.json").read_text())
    assert data["rows"] == [] and data["could_not_verify"][0]["plan_id"] == plan.plan_id
    page = (out / "index.html").read_text()
    assert "could not verify" in page.lower()
    assert "Demo model" not in page.split("could not verify")[0]


def test_empty_registry_and_groups_hook(tmp_path):
    reg = tmp_path / "reg"
    (reg / "entries").mkdir(parents=True)
    out = tmp_path / "site"
    assert board.build(reg, out)["rows"] == 0
    (tmp_path / "two").mkdir()
    reg2, plan = make_registry(tmp_path / "two")
    board.build(reg2, tmp_path / "site2", groups=[{"label": "Statistical tie", "plan_ids": [plan.plan_id]}])
    page = (tmp_path / "site2" / "index.html").read_text()
    assert "Statistical tie" in page
    data = json.loads((tmp_path / "site2" / "entries.json").read_text())
    assert data["groups"][0]["plan_ids"] == [plan.plan_id]


def three_entries(tmp_path, titles=("Alpha", "Beta", "Gamma")):
    from test_compare import make
    from test_ledger import SETUP
    other = {**SETUP, "dataset": {**SETUP["dataset"], "sha256": "ee" * 32}}
    plans = []
    reg = tmp_path / "reg"
    for name, title, scores, setup in zip("abc", titles, (["0.50", "0.60", "0.70"], ["0.45", "0.62", "0.68"], ["0.50", "0.60", "0.70"]),
                                          (SETUP, SETUP, other)):
        repo, plan_id = make(tmp_path, name, scores, setup)
        registry.add_entry(reg, repo, plan_id, {**META, "title": title})
        plans.append(plan_id)
    return reg, plans


def test_default_groups_tie_comparable_entries_and_warn_about_mismatches(tmp_path):
    reg, (a, b, c) = three_entries(tmp_path)
    out = tmp_path / "site"
    board.build(reg, out)
    data = json.loads((out / "entries.json").read_text())
    ties = [g for g in data["groups"] if g["kind"] == "tie"]
    warnings = [g for g in data["groups"] if g["kind"] == "warning"]
    assert [sorted(g["plan_ids"]) for g in ties] == [sorted([a, b])]
    assert sorted(sorted(g["plan_ids"]) for g in warnings) == sorted([sorted([a, c]), sorted([b, c])])
    assert all("dataset" in g["label"] for g in warnings)
    page = (out / "index.html").read_text()
    assert "Statistical tie" in page and "Not comparable" in page and 'class="warn"' in page
    assert "Alpha and Beta" in page or "Beta and Alpha" in page


def test_groups_override_replaces_the_default(tmp_path):
    reg, (a, b, c) = three_entries(tmp_path)
    out = tmp_path / "site"
    board.build(reg, out, groups=[])
    assert json.loads((out / "entries.json").read_text())["groups"] == []
    board.build(reg, out, groups=[{"label": "Mine", "plan_ids": [a]}])
    data = json.loads((out / "entries.json").read_text())
    assert data["groups"] == [{"kind": "tie", "label": "Mine", "plan_ids": [a]}]


def test_group_text_is_escaped(tmp_path):
    reg, _ = three_entries(tmp_path, titles=("<script>x</script>", "<img src=x onerror=1>", "Gamma"))
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    assert page.lower().count("<script") == 1 and "<img" not in page
    assert "&lt;script&gt;" in page


def test_other_plans_note_only_where_the_entry_shows_them(tmp_path):
    from test_ledger import Project
    (tmp_path / "single").mkdir()
    reg, _ = make_registry(tmp_path / "single")
    board.build(reg, tmp_path / "single-site")
    page = (tmp_path / "single-site" / "index.html").read_text()
    assert "Only this plan is part of this entry" not in page and "not part of it" not in page
    project = Project(tmp_path, [{"stdout": "tallylock: score=0.5\n"}, {"stdout": "tallylock: score=0.6\n"}])
    first = project.plan()
    project.run(first)
    project.git.head = "b2" * 20
    second = project.plan()
    project.run(second)
    reg = tmp_path / "reg"
    registry.add_entry(reg, project.repo, first.plan_id, {**META, "title": "First"})
    registry.add_entry(reg, project.repo, second.plan_id, {**META, "title": "Second"})
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    # The second plan's locked number proves an earlier plan exists; the first only has the claimed count.
    assert page.count("Only this plan is part of this entry") == 1
    assert "Plan 2 in its repo. Only this plan is part of this entry; the earlier plans stay in the repo." in page
    assert page.count("not part of it") == 1
    assert page.index("not part of it") > page.index("<footer>")


def test_ties_are_pairs_and_never_chain(tmp_path):
    # Grace ties Quinn and Quinn ties Graham, but Grace beats Graham: no group may claim all three are tied.
    from test_compare import make
    from test_ledger import SETUP
    reg = tmp_path / "reg"
    plans = {}
    for name, scores in (("grace", ("0.235", "0.2525", "0.26", "0.2375", "0.245")),
                         ("quinn", ("0.215", "0.2575", "0.1975", "0.24", "0.2025")),
                         ("graham", ("0.205", "0.22", "0.2075", "0.1975", "0.19"))):
        repo, plan_id = make(tmp_path, name, scores, SETUP)
        registry.add_entry(reg, repo, plan_id, {**META, "title": name})
        plans[name] = plan_id
    out = tmp_path / "site"
    board.build(reg, out)
    ties = {frozenset(g["plan_ids"]) for g in json.loads((out / "entries.json").read_text())["groups"] if g["kind"] == "tie"}
    assert ties == {frozenset([plans["grace"], plans["quinn"]]), frozenset([plans["quinn"], plans["graham"]])}


def test_benchmarks_runs_and_verdicts(tmp_path):
    reg, (a, b, c) = three_entries(tmp_path)
    out = tmp_path / "site"
    board.build(reg, out)
    data = json.loads((out / "entries.json").read_text())
    rows = {row["plan_id"]: row for row in data["rows"]}
    assert [attempt["score"] for attempt in rows[a]["attempts"]] == ["0.500", "0.600", "0.700"]
    assert all(not key.startswith("_") for row in data["rows"] for key in row)
    page = (out / "index.html").read_text()
    # Alpha and Beta share a setup; Gamma used another dataset, so it gets its own benchmark and is never ranked against them.
    assert "Benchmark 1" in page and "Benchmark 2" in page and "Benchmark 3" not in page
    assert "Tied with Beta" in page and "Tied with Alpha" in page and "Gamma beyond noise" not in page
    assert page.count('class="tie-link"') == 1
    assert 'id="alpha"' in page and 'id="beta"' in page and 'id="gamma"' in page
    assert page.count('class="run"') == 9 and "Plan locked" in page and "3 runs recorded" in page


def test_failed_runs_and_bitcoin_state_show_in_the_record(tmp_path):
    reg, plan = make_registry(tmp_path)
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    assert "1 failed run: counted in the claim, never averaged in." in page and page.count('class="x"') == 1
    row = json.loads((out / "entries.json").read_text())["rows"][0]
    assert [attempt["outcome"] for attempt in row["attempts"]].count("completed") == 2
    if row["bitcoin"]:
        assert "Bitcoin timestamp" in page


def test_record_counts_tsa_services_by_signer_and_does_not_claim_unchecked_blocks(tmp_path, monkeypatch):
    from tallylock import rfc3161
    reg, plan = make_registry(tmp_path)
    folder = reg / "entries" / plan.plan_id / ".tallylock" / "plans" / plan.plan_id
    # One token copied under two service names is still one service.
    for name in ("ledger-head-3.freetsa.org.tsr", "ledger-head-3.timestamp.digicert.com.tsr"):
        (folder / name).write_bytes(b"same token")
    monkeypatch.setattr(rfc3161, "verify", lambda data, digest, **_: {"time": "2026-11-07T00:00:00Z", "tsa": "One TSA"})
    # A proof that only names a block costs nothing to write; the page must not call it checked.
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    from tallylock import ledger
    stamp = Timestamp(bytes.fromhex(ledger.ledger_head(folder.parents[2], plan.plan_id)))
    stamp.attestations.add(BitcoinBlockHeaderAttestation(974785))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), stamp).serialize(ctx)
    (folder / "ledger-head-3.ots").write_bytes(ctx.getbytes())
    out = tmp_path / "site"
    board.build(reg, out)
    page = (out / "index.html").read_text()
    assert "2 of 2 verified from 1 public service " in page
    # The registry cannot check the trust label, so the page says whose word it is.
    assert '<span class="tag">anchored</span> <span class="by">(as the submitter declared it)</span>' in page
    assert "naming Bitcoin block 974,785" in page and "This page did not check the blocks" in page
    # A proof of an older head only covers the runs before it.
    (folder / "ledger-head-3.ots").rename(folder / "ledger-head-1.ots")
    monkeypatch.setattr(ledger.anchors, "verify", lambda *a, **k: {"state": "insufficient_chain", "required_heights": [974785]})
    board.build(reg, out)
    page = (out / "index.html").read_text()
    assert "naming Bitcoin block" not in page and "newest ledger update has no Bitcoin proof yet" in page

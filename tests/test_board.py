"""The static board: one HTML file, no scripts, no remote assets, every string escaped."""
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
    assert "<script" not in page.lower()
    assert "prefers-color-scheme: dark" in page and "<style>" in page
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
    assert "<script" not in page.lower() and "<img" not in page and "<b>" not in page
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
    assert "Alpha, Beta" in page or "Beta, Alpha" in page


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
    assert "<script" not in page.lower() and "<img" not in page
    assert "&lt;script&gt;" in page


def test_other_plans_note_only_where_the_entry_shows_them(tmp_path):
    from test_ledger import Project
    (tmp_path / "single").mkdir()
    reg, _ = make_registry(tmp_path / "single")
    board.build(reg, tmp_path / "single-site")
    page = (tmp_path / "single-site" / "index.html").read_text()
    assert "not part of this entry" not in page and "not part of it" not in page
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
    assert page.count("not part of this entry") == 1
    assert "This is plan 2 from its repo. The earlier plans are not part of this entry." in page
    assert page.count("not part of it") == 1
    assert page.index("not part of it") > page.index("</table>")

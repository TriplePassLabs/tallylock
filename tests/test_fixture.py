import pytest

from tallylock import fixture, schema, scoring, store
from tallylock.errors import TallyLockError


def test_example_is_fresh_pure_fixture_with_two_samples_and_no_calls():
    first, second = fixture.example(), fixture.example()
    assert first is not second and first.manifest is not second.manifest
    assert first.manifest["nonce"] != second.manifest["nonce"]
    assert first.aggregate == {"numerator": 1, "denominator": 2}
    assert [event["kind"] for event in first.events] == ["sample_start", "sample_end", "sample_start", "sample_end", "attempt_end"]
    assert all(event["kind"] != "call" for event in first.events)
    assert schema.validate_manifest(first.manifest) is first.manifest
    assert first.manifest["model"]["id"] == "local-no-model-fixture"


def test_fixture_seals_through_store_and_recomputes_from_local_artifacts(tmp_path):
    value = fixture.example()
    receipt = tmp_path / "receipt"
    source = tmp_path / "source"
    receipt.mkdir()
    source.mkdir()
    for path, data in value.artifacts.items():
        (source / path).write_bytes(data)
    store.register(value.manifest, receipt)
    result = store.seal(receipt, source, events=value.events, roles=value.roles,
                        score_path=value.score_path, aggregate=value.aggregate)

    def local_reader(path, limit):
        data = (receipt / "artifacts" / path).read_bytes()
        assert len(data) <= limit
        return data

    evidence = scoring.check(value.manifest, result, local_reader)
    assert evidence["recomputed"] == {"numerator": 1, "denominator": 2}


def test_store_can_seal_honestly_hashed_false_fixture_math_that_scoring_rejects(tmp_path):
    from tallylock import canonical
    value = fixture.example()
    score = canonical.loads(value.artifacts[value.score_path])
    score["samples"][0]["observed"] = "green"
    value.artifacts[value.score_path] = canonical.dumps(score)
    receipt, source = tmp_path / "receipt", tmp_path / "source"
    receipt.mkdir()
    source.mkdir()
    for path, data in value.artifacts.items():
        (source / path).write_bytes(data)
    store.register(value.manifest, receipt)
    result = store.seal(receipt, source, events=value.events, roles=value.roles,
                        score_path=value.score_path, aggregate=value.aggregate)

    with pytest.raises(TallyLockError):
        scoring.check(value.manifest, result, lambda path, limit: (receipt / "artifacts" / path).read_bytes())

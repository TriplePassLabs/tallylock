"""The machine-readable capabilities list must match the real command parser."""
import argparse
import json

from tallylock import capabilities, cli


def parser_commands():
    found = {}

    def walk(parser, prefix):
        subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
        if not subs:
            options = {}
            positionals = []
            for action in parser._actions:
                if isinstance(action, (argparse._HelpAction, argparse._VersionAction)):
                    continue
                # --json and --human come from the shared parent parser on every command.
                if action.option_strings in (["--json"], ["--human"]):
                    continue
                if action.option_strings:
                    options[tuple(action.option_strings)] = (action.required, list(action.choices or []))
                else:
                    positionals.append(action.dest)
            found[prefix] = (options, positionals)
            return
        for name, child in subs[0].choices.items():
            walk(child, f"{prefix} {name}".strip())

    walk(cli._parser(), "")
    return found


def test_available_commands_match_the_real_parser():
    data = capabilities.capabilities()
    real = parser_commands()
    available = {c["name"]: c for c in data["commands"] if c["status"] == "available"}
    assert set(available) == set(real)
    assert {tuple(o["flags"]) for o in data["common_options"]} == {("--json",), ("--human",)}
    for name, command in available.items():
        options, positionals = real[name]
        listed = {tuple(o["flags"]): (o["required"], o.get("choices", [])) for o in command["options"]}
        assert listed == options, name
        assert [p["name"] for p in command["arguments"]] == positionals, name


def test_every_command_documents_effects_formats_and_exit_codes():
    data = capabilities.capabilities()
    assert data["format"] == "tallylock.capabilities.v1"
    assert {0, 2, 3, 4, 5, 130} == {c["code"] for c in data["exit_codes"]}
    names = [c["name"] for c in data["commands"]]
    assert len(names) == len(set(names))
    for planned in ("run", "score", "check", "doctor", "export", "registry", "board", "compare", "adapters"):
        assert any(n == planned or n.startswith(planned + " ") for n in names), planned
    for command in data["commands"]:
        assert command["status"] in ("available", "planned")
        assert set(command["effects"]) <= {"reads", "writes", "network"}
        assert command["effects"], command["name"]
        assert command["summary"] and command["outputs"]
        for effect in command["effects"].values():
            assert isinstance(effect, str) and effect
    effects = {c["name"]: c["effects"] for c in data["commands"]}
    assert effects["verify"]["network"].startswith("Only with --online") and effects["check"]["network"].startswith("Only with --online")
    assert "writes" not in effects["score"] and "writes" not in effects["inspect"]
    assert "network" in effects["run"]


def test_text_matches_the_house_rules_and_is_plain_json():
    data = capabilities.capabilities()
    text = capabilities.capabilities_json()
    assert json.loads(text) == data
    assert "—" not in text
    assert "\n" in text and text.endswith("\n")


def test_agent_guide_covers_the_safety_basics():
    from importlib import resources
    guide = resources.files("tallylock").joinpath("data/agent-guide.md").read_text()
    assert "—" not in guide
    for phrase in ("read-only", "Never execute", "Exit codes", "tallylock run", "tallylock score", "tallylock check",
                   "failed", "Declared"):
        assert phrase in guide, phrase
    for code in capabilities.capabilities()["exit_codes"]:
        assert f"- {code['code']}:" in guide

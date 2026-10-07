from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def page(name: str) -> str:
    return " ".join((ROOT / name).read_text(encoding="utf-8").split())


def test_quickstart_explains_installer_choice_and_init() -> None:
    text = page("get-started/quickstart.mdx")
    assert "installer asks you to pick one agent to guard (or none)" in text
    assert "That choice is saved" in text
    assert "sets up the agent chosen during install" in text


def test_copilot_workspace_scope_and_guardrail_route() -> None:
    text = page("connectors/copilot.mdx")
    assert "workspace for the whole install" in text
    assert "Setup refuses it once another connector is configured" in text
    assert "defenseclaw setup guardrail --workspace /path/to/repo" in text


def test_connector_prompts_and_scripted_mode() -> None:
    for connector in ("cursor", "copilot", "hermes"):
        text = page("connectors/" + connector + ".mdx")
        assert "Interactive setup asks for the mode" in text
        assert "add to or replace an existing connector roster" in text
        assert "whether to add an LLM judge" in text
        assert "--yes --mode observe" in text


def test_domain_group_yaml_and_space_lookup() -> None:
    text = page("guardrail/user-and-group-policies.mdx")
    quote = chr(39)
    slash = chr(92)
    assert quote + "CORP" + slash + "ML-Team" + quote in text
    assert chr(34) + "CORP" + slash * 2 + "ML-Team" + chr(34) in text
    assert "dscl" in text and "Windows names containing spaces" in text


def test_macos_membership_cache_recovery() -> None:
    text = page("guardrail/user-and-group-policies.mdx")
    assert "dscacheutil -flushcache" in text
    assert "dsmemberutil flushcache" in text
    assert "then restart the gateway" in text


def test_profile_enforcement_matches_install_mode() -> None:
    text = page("guardrail/user-and-group-policies.mdx")
    assert "On a standalone enterprise install" in text
    assert "or move to a weaker one" in text
    assert "On a per-user install, the user owns the configuration" in text


def test_authentication_cooldown_and_half_open_probe() -> None:
    text = page("observability/index.mdx")
    assert "Authentication failures open the affected route immediately for five minutes" in text
    assert "a half-open probe then retries it" in text

"""Final-cert UX batch 7 (ux2): keys list footer on Windows, telemetry row count."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui.command_line import command_result_summary
from defenseclaw.tui.panels import setup_catalog


def test_keys_list_summary_reads_ascii_console_rows() -> None:
    # GAP-2238: a Windows console without UTF-8 prints "*", "o", "-" and "OK set".
    lines = [
        "     ENV NAME                  FEATURE      REQUIREMENT  SOURCE  STATUS",
        "  -  ------------------------  -----------  -----------  ------  ------",
        "  o  DEFENSECLAW_LLM_KEY       llm.default  OPTIONAL     unset   unset",
        "  -  VIRUSTOTAL_API_KEY        scanner      NOT_USED     unset   n/a",
        "  *  GALILEO_API_KEY           galileo      REQUIRED     dotenv  OK set",
        "  *  OPENAI_API_KEY            llm          REQUIRED     unset   MISSING",
        "  Legend:  * required   o optional   - not used by current config",
        "  Managed by DefenseClaw (gateway auth token, do not remove): DEFENSECLAW_GATEWAY_TOKEN",
    ]
    assert command_result_summary("keys list", lines) == "4 credentials, 2 required, missing: OPENAI_API_KEY"
    assert command_result_summary("keys list", lines[:5]) == "3 credentials, 1 required, all set"


def test_export_telemetry_row_counts_the_local_store() -> None:
    # GAP-2239: the row said "2 destinations" next to "3 destinations listed".
    def dest(name, kind="otlp", generated=False):
        return SimpleNamespace(name=name, kind=kind, enabled=True, generated=generated)

    plan = SimpleNamespace(destinations=(dest("local-sqlite", "sqlite", True), dest("o11y"), dest("galileo")))
    assert setup_catalog._observability_status(plan, "").text == "2 exports + local"
    one = SimpleNamespace(destinations=(dest("local-sqlite", "sqlite", True), dest("o11y")))
    assert setup_catalog._observability_status(one, "").text == "1 export + local"
    no_local = SimpleNamespace(destinations=(dest("o11y"),))
    assert setup_catalog._observability_status(no_local, "").text == "1 destination"

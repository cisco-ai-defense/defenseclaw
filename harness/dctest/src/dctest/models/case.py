"""Case and result models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class FollowupEvidenceSpec(BaseModel):
    """A piece of evidence the harness gathers after the command runs.

    Followup evidence supplements the standard stdout/stderr/exit-code
    triple with structured artifacts the classify prompt can quote
    deterministically. Kinds:

    - ``file_content``: read ``path`` and emit its contents.
    - ``file_diff``: read ``a`` and ``b`` and emit a unified diff.
    - ``jsonpath``: evaluate ``expression`` against captured stdout (parsed
      as JSON). The result is JSON-encoded; if the expression doesn't
      match, the evidence value is ``null`` and ``ok=false`` is set.
    - ``exit_code_chain``: capture exit codes of multiple commands in
      ``path`` (a file with one integer per line, written by the case
      command via ``echo $? >> path``).
    - ``stdout_jsonschema``: validate captured stdout against the JSON
      schema at ``schema_path``; report PASS/FAIL with schema errors.
    """

    kind: Literal[
        "file_content",
        "file_diff",
        "jsonpath",
        "exit_code_chain",
        "stdout_jsonschema",
    ]
    label: str
    path: str | None = None
    a: str | None = None
    b: str | None = None
    expression: str | None = None
    schema_path: str | None = None


class Verdict(str, Enum):
    """Final classification the AI agent assigns to a case after reviewing evidence."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    BLOCKED = "blocked"
    NEEDS_HUMAN = "needs-human"


class CaseStatus(str, Enum):
    """Lifecycle status of a case within a run."""

    PENDING = "pending"
    RUNNING = "running"
    EXECUTED = "executed"  # command ran; awaiting agent verdict
    CLASSIFIED = "classified"  # agent verdict written
    SKIPPED = "skipped"


Surface = Literal[
    "python-cli",
    "go-cli",
    "tui",
    "connector",
    "gateway-api",
    "story",
    "lifecycle",
    "error",
]


class TestCase(BaseModel):
    """A single test case loaded from a YAML file under ``cases/``."""

    id: str = Field(description="Stable, dot-delimited case id (e.g. cli-py.skill.scan.basic).")
    title: str
    surface: Surface
    feature: str = Field(description="Logical feature this case validates (e.g. scanning.skill).")
    preconditions: list[str] = Field(default_factory=list)
    command: str = Field(description="Exact shell command(s) to execute.")
    cwd: str | None = None
    env_overrides: dict[str, str] = Field(default_factory=dict)
    expected_exit_code: int | None = 0
    expected_substrings: list[str] = Field(default_factory=list)
    must_not_contain: list[str] = Field(default_factory=list)
    timeout_s: int | None = None
    human_review_required: bool = False
    requires_sidecar: bool = False
    requires_internet: bool = False
    requires_provider_kind: list[str] = Field(
        default_factory=list,
        description=(
            "Optional list of provider vendors this case requires "
            "(e.g. ['anthropic', 'openai']). Empty = provider-agnostic."
        ),
    )
    requires_services: list[
        Literal["gateway", "sidecar", "observability", "webhook-target"]
    ] = Field(
        default_factory=list,
        description=(
            "Optional list of services that must be reachable before the "
            "case command runs. If any is down, case_runner emits a skip "
            "with reason 'service-down:<name>' and never invokes the agent."
        ),
    )
    expected_to_fail_at: list[Literal["cli-registry", "execution", "verdict"]] = Field(
        default_factory=list,
        description=(
            "Stages at which this case is KNOWN to fail today. Reasons:\n"
            "  - 'cli-registry': the documented flag/subcommand isn't in the "
            "CLI yet — lint-cases will note this as expected, not blocking.\n"
            "  - 'execution': command runs but exit code / output drifts from\n"
            "    expectation; verdict will be 'fail' but it's a tracked bug.\n"
            "  - 'verdict': agent verdict disagrees with the case author's "
            "intent because the underlying behavior is ambiguous.\n"
            "Used by case_linter and the cluster/findings report to "
            "distinguish 'known bug, tracked' from 'new regression'."
        ),
    )
    requires_role: list[str] = Field(
        default_factory=list,
        description=(
            "Optional list of provider roles (e.g. ['guardrail-only', "
            "'judge-only', 'both']) this case requires. Empty = role-agnostic. "
            "Mirrors requires_provider_kind but for the cell's role dimension."
        ),
    )
    followup_evidence: list[FollowupEvidenceSpec] = Field(
        default_factory=list,
        description=(
            "Structured artifacts the harness gathers AFTER the command runs "
            "and passes to the classify prompt as additional evidence. "
            "Reduces 'needs-human' verdicts on cases where stdout/stderr "
            "alone are insufficient."
        ),
    )
    expect_json_path: list[str] = Field(
        default_factory=list,
        description=(
            "List of jsonpath-like expressions to evaluate against captured "
            "stdout (parsed as JSON). Each expression can be a plain JSONPath "
            "(e.g. '$.version') or a JSONPath followed by ' exists' to assert "
            "presence rather than non-empty value."
        ),
    )
    expect_jsonschema: str | None = Field(
        default=None,
        description=(
            "Optional path under fixtures/schemas/ — the harness validates "
            "captured stdout against this JSON schema after the command runs."
        ),
    )
    docs_site_refs: list[str] = Field(
        default_factory=list,
        description="Paths under docs-site/content/docs/ that this case validates.",
    )
    tags: list[str] = Field(default_factory=list)
    notes_for_agent: str = ""


class CaseResult(BaseModel):
    """Result of running a single case inside a single cell."""

    case_id: str
    cell_id: str
    run_id: str
    started_at: datetime
    ended_at: datetime
    exit_code: int
    timed_out: bool = False
    stdout_path: Path
    stderr_path: Path
    transcript_path: Path | None = None
    verdict: Verdict = Verdict.NEEDS_HUMAN
    agent_reasoning: str = ""
    evidence_paths: list[Path] = Field(default_factory=list)
    status: CaseStatus = CaseStatus.PENDING

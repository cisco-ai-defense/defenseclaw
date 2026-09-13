#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# SPDX-License-Identifier: Apache-2.0

"""Build a publication-safe deterministic benchmark coverage report.

Only aggregate benchmark artifacts are read. Predictions, normalized cases,
and payload-bearing files are intentionally outside this tool's input model.
The public lock is the report's allowlist; an optional private lock is used
only to exclude private-only dataset identifiers from consideration.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = "1"
REPORT_SCHEMA_VERSION = "1"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_DATASETS = 100_000
MAX_GROUPS = 1_000_000
ALLOWED_STATUSES = {
    "normalized-only",
    "normalized-mining-only",
    "label-only",
    "gated",
    "inaccessible",
    "missing",
}
REPORT_DOMAINS = (
    "bounded_chains",
    "sql",
    "kubernetes",
    "aws",
    "azure",
    "gcp",
    "endpoint_host",
    "credentials",
    "privacy_pii",
    "yara_content",
)
PUBLIC_PROFILES = {"default", "balanced", "permissive", "strict", "all"}
METRIC_FOCUSES = {"detection", "enforcement", "both"}
ENFORCEMENT_INTENDED_USES = {
    "cloud-policy-conformance",
    "database-policy-conformance",
    "infrastructure-policy-conformance",
    "kubernetes-policy-conformance",
}
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
WINDOWS_ABSOLUTE_PATH = re.compile(r"(?i)(?:^|\s)[A-Z]:\\[^\s|,;)]*")
UNC_ABSOLUTE_PATH = re.compile(r"(?:^|\s)\\\\[^\s|,;)]*")
UNIX_ABSOLUTE_PATH = re.compile(r"(?<![:A-Za-z0-9])/(?!/)[^\s|,;)]*")
VERSION_SUFFIX = re.compile(r"(?:^|[-_])v(\d+)(?:$|[-_])", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-lock", required=True)
    parser.add_argument("--private-lock")
    parser.add_argument("--results-root", required=True)
    parser.add_argument("--mapping", help="optional dataset domain/use/status mapping JSON")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    if path.is_symlink():
        raise ValueError("symbolic-link JSON inputs are not accepted")
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError("JSON input exceeds the maximum allowed size")
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def require_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object")
    return value


def safe_identifier(value: Any, description: str) -> str:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{description} is not a safe identifier")
    return value


def exact_group_value(value: Any, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2_000
        or CONTROL_CHARACTER.search(value)
    ):
        raise ValueError(f"{description} must be a bounded string without control characters")
    return value


def load_lock(path: Path) -> list[dict[str, Any]]:
    raw = require_object(read_json(path), "dataset lock")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported dataset lock schema")
    datasets = raw.get("datasets")
    if not isinstance(datasets, list) or len(datasets) > MAX_DATASETS:
        raise ValueError("dataset lock has an invalid dataset list")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in datasets:
        row = require_object(item, "dataset lock entry")
        dataset_id = safe_identifier(row.get("id"), "dataset ID")
        if dataset_id in seen:
            raise ValueError("dataset lock contains a duplicate ID")
        seen.add(dataset_id)
        output.append(row)
    return output


def private_only_ids(public: Sequence[Mapping[str, Any]], private_path: Path | None) -> set[str]:
    if private_path is None:
        return set()
    public_ids = {str(item["id"]) for item in public}
    return {str(item["id"]) for item in load_lock(private_path)} - public_ids


def private_tokens(private_path: Path | None, public: Sequence[Mapping[str, Any]]) -> set[str]:
    if private_path is None:
        return set()
    public_ids = {str(item["id"]) for item in public}
    tokens: set[str] = set()
    for item in load_lock(private_path):
        dataset_id = str(item["id"])
        if dataset_id in public_ids:
            continue
        tokens.add(dataset_id)
        source = item.get("source_url")
        if isinstance(source, str) and source:
            tokens.add(source)
            parsed = urlsplit(source)
            if parsed.hostname:
                tokens.add(parsed.hostname)
            source_parts = [part for part in parsed.path.split("/") if part]
            if source_parts:
                tokens.add(source_parts[-1])
        id_parts = [part for part in dataset_id.split("/") if part]
        if id_parts:
            tokens.add(id_parts[-1])
    return {token for token in tokens if len(token) >= 6}


def sanitize_text(value: Any, redactions: Iterable[str]) -> str:
    rendered = "" if value is None else str(value)
    rendered = CONTROL_CHARACTER.sub(" ", rendered)
    rendered = WINDOWS_ABSOLUTE_PATH.sub("[local path]", rendered)
    rendered = UNC_ABSOLUTE_PATH.sub("[local path]", rendered)
    rendered = UNIX_ABSOLUTE_PATH.sub("[local path]", rendered)
    for token in sorted(redactions, key=len, reverse=True):
        rendered = rendered.replace(token, "[private]")
    return " ".join(rendered.split())[:2_000]


def safe_public_source(value: Any) -> str | None:
    if not isinstance(value, str) or not value or CONTROL_CHARACTER.search(value):
        return None
    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        return value
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return candidate.as_posix()


def string_list(value: Any, description: str, redactions: Iterable[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 1_000:
        raise ValueError(f"{description} must be a bounded string list")
    output: list[str] = []
    for item in value:
        text = sanitize_text(item, redactions)
        if text and text not in output:
            output.append(text)
    return output


def selector_list(
    value: Any,
    domain: str,
    public_ids: set[str],
    private_ids: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 1_000:
        raise ValueError("each domain selector list must be non-empty and bounded")
    output: list[dict[str, Any]] = []
    dimensions: set[str] = set()
    seen_scopes: list[tuple[set[str], set[str]]] = []
    for raw_selector in value:
        selector = require_object(raw_selector, "domain group selector")
        dimension = safe_identifier(selector.get("dimension"), "selector dimension")
        raw_groups = selector.get("group_values")
        if not isinstance(raw_groups, list) or not raw_groups or len(raw_groups) > 10_000:
            raise ValueError("selector group_values must be a non-empty bounded list")
        groups = sorted({exact_group_value(item, "selector group value") for item in raw_groups})
        raw_dataset_ids = selector.get("dataset_ids", [])
        if not isinstance(raw_dataset_ids, list) or len(raw_dataset_ids) > MAX_DATASETS:
            raise ValueError("selector dataset_ids must be a bounded list")
        dataset_ids = {safe_identifier(item, "selector dataset ID") for item in raw_dataset_ids}
        if dataset_ids & private_ids or not dataset_ids <= public_ids:
            raise ValueError("domain selector references a non-public dataset")
        dimensions.add(dimension)
        group_set = set(groups)
        for prior_groups, prior_datasets in seen_scopes:
            dataset_scopes_overlap = not dataset_ids or not prior_datasets or bool(dataset_ids & prior_datasets)
            if group_set & prior_groups and dataset_scopes_overlap:
                raise ValueError("domain selectors contain overlapping exact group scopes")
        seen_scopes.append((group_set, dataset_ids))
        output.append(
            {
                "dimension": dimension,
                "group_values": groups,
                "dataset_ids": sorted(dataset_ids),
            }
        )
    if len(dimensions) != 1:
        raise ValueError(f"domain {domain!r} selectors must use one exact dimension")
    return output


def load_mapping(
    path: Path | None,
    public_ids: set[str],
    private_ids: set[str],
    redactions: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if path is None:
        return {}, {}
    raw = require_object(read_json(path), "dataset mapping")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported dataset mapping schema")
    datasets = require_object(raw.get("datasets", {}), "dataset mapping datasets")
    output: dict[str, dict[str, Any]] = {}
    for raw_id, raw_entry in datasets.items():
        dataset_id = safe_identifier(raw_id, "mapping dataset ID")
        if dataset_id in private_ids:
            continue
        entry = require_object(raw_entry, "dataset mapping entry")
        domains = string_list(entry.get("domains"), "mapping domains", redactions)
        unknown = sorted(set(domains) - set(REPORT_DOMAINS))
        if unknown:
            raise ValueError("dataset mapping contains an unsupported report domain")
        status = entry.get("status")
        if status is not None and status not in ALLOWED_STATUSES:
            raise ValueError("dataset mapping contains an unsupported status")
        metric_focus = entry.get("metric_focus")
        if metric_focus is not None and metric_focus not in METRIC_FOCUSES:
            raise ValueError("dataset mapping contains an unsupported metric focus")
        counts: dict[str, int] = {}
        for field in ("case_count", "applicable_count"):
            if field in entry:
                number = entry[field]
                if not isinstance(number, int) or isinstance(number, bool) or number < 0:
                    raise ValueError(f"mapping {field} must be a non-negative integer")
                counts[field] = number
        output[dataset_id] = {
            "domains": domains if "domains" in entry else None,
            "intended_use": string_list(entry.get("intended_use"), "mapping intended use", redactions),
            "limitations": string_list(entry.get("limitations"), "mapping limitations", redactions),
            "status": status,
            **({"metric_focus": metric_focus} if metric_focus is not None else {}),
            **counts,
        }
    raw_selectors = require_object(raw.get("domain_group_selectors", {}), "domain group selectors")
    unknown_domains = sorted(set(raw_selectors) - set(REPORT_DOMAINS))
    if unknown_domains:
        raise ValueError("mapping contains an unsupported report domain selector")
    selectors = {
        domain: selector_list(value, domain, public_ids, private_ids)
        for domain, value in raw_selectors.items()
    }
    return output, selectors


def non_negative_int(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{description} must be a non-negative integer")
    return value


def confusion_from_metric(
    value: Any, description: str, applicable: int
) -> dict[str, int] | None:
    if value is None:
        return None
    metric = require_object(value, description)
    confusion = require_object(metric.get("confusion"), f"{description} confusion")
    counts = {
        "tp": non_negative_int(confusion.get("true_positive", 0), f"{description} true positives"),
        "tn": non_negative_int(confusion.get("true_negative", 0), f"{description} true negatives"),
        "fp": non_negative_int(confusion.get("false_positive", 0), f"{description} false positives"),
        "fn": non_negative_int(confusion.get("false_negative", 0), f"{description} false negatives"),
    }
    if sum(counts.values()) > applicable:
        raise ValueError(f"{description} confusion counts exceed applicable cases")
    return counts


def metric_from_group(group: Mapping[str, Any]) -> dict[str, Any]:
    cases = non_negative_int(group.get("cases", 0), "group cases")
    applicable = non_negative_int(group.get("applicable", 0), "group applicable")
    block_rate = require_object(group.get("benign_block_rate", {}), "benign block rate")
    metrics = {
        "cases": cases,
        "applicable": applicable,
        "detection": confusion_from_metric(group.get("detection"), "detection", applicable),
        "enforcement": confusion_from_metric(group.get("enforcement"), "enforcement", applicable),
        "benign_blocks": non_negative_int(block_rate.get("numerator", 0), "benign blocks"),
        "benign_total": non_negative_int(block_rate.get("denominator", 0), "benign block denominator"),
    }
    if metrics["benign_blocks"] > metrics["benign_total"]:
        raise ValueError("benign blocks exceed their denominator")
    return metrics


def calculated_confusion(counts: Mapping[str, int]) -> dict[str, Any]:
    tp, tn, fp, fn = (counts[name] for name in ("tp", "tn", "fp", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    fpr = fp / (fp + tn) if fp + tn else None
    return {
        "available": True,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def unavailable_confusion() -> dict[str, Any]:
    return {
        "available": False,
        "tp": None,
        "tn": None,
        "fp": None,
        "fn": None,
        "precision": None,
        "recall": None,
        "f1": None,
        "fpr": None,
    }


def rendered_metrics(counts: Mapping[str, Any]) -> dict[str, Any]:
    blocks = int(counts["benign_blocks"])
    benign_total = int(counts["benign_total"])
    enforcement_counts = counts["enforcement"]
    enforcement = (
        calculated_confusion(enforcement_counts)
        if enforcement_counts is not None
        else unavailable_confusion()
    )
    enforcement.update(
        {
            "benign_blocks": blocks,
            "benign_total": benign_total,
            "benign_block_rate": blocks / benign_total if benign_total else None,
        }
    )
    return {
        "cases": int(counts["cases"]),
        "applicable": int(counts["applicable"]),
        "detection": (
            calculated_confusion(counts["detection"])
            if counts["detection"] is not None
            else unavailable_confusion()
        ),
        "enforcement": enforcement,
    }


def candidate_rank(candidate: Mapping[str, Any]) -> tuple[int, int, int, str]:
    run_id = str(candidate["run_id"])
    versions = [int(match.group(1)) for match in VERSION_SUFFIX.finditer(run_id)]
    return (
        int(candidate["metrics"]["cases"]),
        int(candidate["metrics"]["applicable"]),
        max(versions, default=-1),
        run_id,
    )


def result_files(root: Path) -> list[Path]:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("results root must be a directory")
    output: list[Path] = []
    for candidate in resolved.rglob("results.json"):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        try:
            candidate.resolve(strict=True).relative_to(resolved)
        except ValueError:
            continue
        output.append(candidate)
    return sorted(output, key=lambda item: item.relative_to(resolved).as_posix())


def collect_candidates(
    root: Path,
    public_ids: set[str],
    private_ids: set[str],
) -> tuple[
    dict[tuple[str, str], list[dict[str, Any]]],
    list[dict[str, Any]],
    set[str],
    list[str],
]:
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    group_candidates: list[dict[str, Any]] = []
    normalized: set[str] = set()
    global_limitations: set[str] = set()
    for results_path in result_files(root):
        directory = results_path.parent
        manifest_path = directory / "corpus-manifest.json"
        inventory_path = directory / "inventory.json"
        if not manifest_path.is_file() or not inventory_path.is_file():
            global_limitations.add("ignored_result_missing_required_sibling_artifact")
            continue
        results = require_object(read_json(results_path), "results artifact")
        manifest = require_object(read_json(manifest_path), "corpus manifest")
        inventory = require_object(read_json(inventory_path), "policy inventory")
        run_id = safe_identifier(results.get("run_id"), "result run ID")
        dataset_counts = require_object(manifest.get("dataset_counts", {}), "manifest dataset counts")
        for dataset_id, count in dataset_counts.items():
            if dataset_id in private_ids or dataset_id not in public_ids:
                continue
            non_negative_int(count, "manifest dataset count")
            if count:
                normalized.add(dataset_id)
        inventory_profiles = {
            str(item.get("profile"))
            for item in inventory.get("profiles", [])
            if isinstance(item, dict) and isinstance(item.get("profile"), str)
        }
        groups = results.get("groups")
        if not isinstance(groups, list) or len(groups) > MAX_GROUPS:
            raise ValueError("results artifact has an invalid group list")
        manifest_ids = {str(dataset_id) for dataset_id in dataset_counts}
        public_scope = bool(manifest_ids) and manifest_ids <= public_ids and not (manifest_ids & private_ids)
        for group in groups:
            if not isinstance(group, dict):
                continue
            dimension = safe_identifier(group.get("dimension"), "result group dimension")
            group_value = exact_group_value(group.get("group"), "result group value")
            profile = group.get("profile")
            if not isinstance(profile, str) or not SAFE_IDENTIFIER.fullmatch(profile):
                raise ValueError("result group has an invalid profile")
            if profile not in PUBLIC_PROFILES:
                global_limitations.add("ignored_non_public_profile")
                continue
            if inventory_profiles and profile not in inventory_profiles:
                global_limitations.add("ignored_metric_profile_missing_from_inventory")
                continue
            metrics = metric_from_group(group)
            group_candidates.append(
                {
                    "run_id": run_id,
                    "profile": profile,
                    "dimension": dimension,
                    "group": group_value,
                    "dataset_ids": sorted(manifest_ids & public_ids),
                    "public_scope": public_scope,
                    "metrics": metrics,
                }
            )
            if dimension != "dataset":
                continue
            dataset_id = group_value
            if dataset_id not in public_ids or dataset_id in private_ids:
                continue
            if dataset_id not in dataset_counts:
                global_limitations.add("ignored_metric_dataset_missing_from_corpus_manifest")
                continue
            candidates[(dataset_id, profile)].append({"run_id": run_id, "metrics": metrics})
    return candidates, group_candidates, normalized, sorted(global_limitations)


def zero_counts() -> dict[str, Any]:
    return {
        "cases": 0,
        "applicable": 0,
        "detection": {key: 0 for key in ("tp", "tn", "fp", "fn")},
        "enforcement": {key: 0 for key in ("tp", "tn", "fp", "fn")},
        "benign_blocks": 0,
        "benign_total": 0,
    }


def sum_profile_metrics(metrics: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    rows = list(metrics)
    if not rows:
        return None
    counts = zero_counts()
    metric_availability = {metric_type: True for metric_type in ("detection", "enforcement")}
    for row in rows:
        for key in ("cases", "applicable", "benign_blocks", "benign_total"):
            counts[key] += int(row[key])
        for metric_type in ("detection", "enforcement"):
            if row[metric_type] is None:
                metric_availability[metric_type] = False
                continue
            for key in ("tp", "tn", "fp", "fn"):
                counts[metric_type][key] += int(row[metric_type][key])
    for metric_type, available in metric_availability.items():
        if not available:
            counts[metric_type] = None
    return rendered_metrics(counts)


def build_domain_metrics(
    selectors: Mapping[str, Sequence[Mapping[str, Any]]],
    group_candidates: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for domain in REPORT_DOMAINS:
        domain_selectors = selectors.get(domain, ())
        if not domain_selectors:
            output[domain] = {
                "available": False,
                "reason": "no_exact_group_selector",
                "dataset_count": 0,
                "evidence_group_count": 0,
                "profiles": {},
            }
            continue
        matched: list[Mapping[str, Any]] = []
        for selector in domain_selectors:
            selected_ids = set(selector.get("dataset_ids", ()))
            groups = set(selector["group_values"])
            matched.extend(
                candidate
                for candidate in group_candidates
                if candidate["public_scope"]
                and candidate["dimension"] == selector["dimension"]
                and candidate["group"] in groups
                and (
                    not selected_ids
                    or bool(candidate["dataset_ids"])
                    and set(candidate["dataset_ids"]) <= selected_ids
                )
            )
        if not matched:
            output[domain] = {
                "available": False,
                "reason": "no_matching_result_groups",
                "dataset_count": 0,
                "evidence_group_count": 0,
                "profiles": {},
            }
            continue
        selected: list[Mapping[str, Any]] = []
        for profile in sorted({str(item["profile"]) for item in matched}):
            buckets: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
            for candidate in matched:
                if candidate["profile"] == profile:
                    buckets[(str(candidate["dimension"]), str(candidate["group"]))].append(candidate)
            for bucket in sorted(buckets):
                used_ids: set[str] = set()
                for candidate in sorted(buckets[bucket], key=candidate_rank, reverse=True):
                    candidate_ids = set(candidate["dataset_ids"])
                    if candidate_ids and not (candidate_ids & used_ids):
                        selected.append(candidate)
                        used_ids.update(candidate_ids)
        rendered_profiles: dict[str, Any] = {}
        for profile in sorted({str(item["profile"]) for item in selected}):
            aggregate = sum_profile_metrics(
                item["metrics"] for item in selected if item["profile"] == profile
            )
            if aggregate is not None:
                rendered_profiles[profile] = aggregate
        dataset_ids = {dataset_id for item in selected for dataset_id in item["dataset_ids"]}
        output[domain] = {
            "available": bool(rendered_profiles),
            "reason": None if rendered_profiles else "no_non_overlapping_result_groups",
            "dataset_count": len(dataset_ids),
            "evidence_group_count": len(selected),
            "profiles": rendered_profiles,
        }
    return output


def build_report(
    public_lock: Sequence[Mapping[str, Any]],
    candidates: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    group_candidates: Sequence[Mapping[str, Any]],
    normalized_ids: set[str],
    mapping: Mapping[str, Mapping[str, Any]],
    selectors: Mapping[str, Sequence[Mapping[str, Any]]],
    redactions: set[str],
    global_limitations: Sequence[str] = (),
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for locked in public_lock:
        dataset_id = str(locked["id"])
        configured = mapping.get(dataset_id, {})
        purposes = string_list(locked.get("purpose"), "dataset purpose", redactions)
        intended_use = list(configured.get("intended_use") or purposes)
        metric_focus = configured.get("metric_focus")
        if metric_focus is None:
            metric_focus = (
                "enforcement"
                if ENFORCEMENT_INTENDED_USES.intersection(intended_use)
                else "both"
            )
        domains = list(configured.get("domains") or [])
        limitations = list(configured.get("limitations") or [])
        profile_metrics: dict[str, dict[str, Any]] = {}
        profiles = sorted({profile for candidate_id, profile in candidates if candidate_id == dataset_id})
        selected_cases: list[int] = []
        selected_applicable: list[int] = []
        for profile in profiles:
            options = list(candidates[(dataset_id, profile)])
            selected = max(options, key=candidate_rank)
            metrics = selected["metrics"]
            profile_metrics[profile] = rendered_metrics(metrics)
            selected_cases.append(metrics["cases"])
            selected_applicable.append(metrics["applicable"])
            if len(options) > 1:
                limitations.append(f"multiple_result_candidates:{profile}; selected deterministically")
        enabled = locked.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("dataset enabled must be boolean")
        declared_status = configured.get("status")
        inaccessible_statuses = {"gated", "inaccessible", "label-only"}
        if not enabled:
            status = "disabled"
        elif declared_status in inaccessible_statuses:
            status = declared_status
            profile_metrics = {}
            selected_cases = []
            selected_applicable = []
        elif declared_status == "normalized-mining-only":
            status = declared_status
            profile_metrics = {}
            selected_applicable = []
        elif any(item["applicable"] > 0 for item in profile_metrics.values()):
            status = "scored"
        elif dataset_id in normalized_ids or profile_metrics or declared_status == "normalized-only":
            status = "normalized-only"
        else:
            status = "missing"
        if selected_cases and len(set(selected_cases)) > 1:
            limitations.append("selected profiles use different corpus case counts")
        if selected_applicable and len(set(selected_applicable)) > 1:
            limitations.append("selected profiles use different applicable counts")
        if status == "normalized-only" and not limitations:
            limitations.append("normalized cases exist but no applicable dataset metrics were found")
        if status == "label-only" and not limitations:
            limitations.append("offline labels exist without a normalized benchmark corpus")
        if status == "normalized-mining-only" and not limitations:
            limitations.append("normalized for rule mining or coverage only; excluded from population scoring")
        if status == "gated" and not limitations:
            limitations.append("source access is gated; no publication-safe scored artifact is available")
        if status == "inaccessible" and not limitations:
            limitations.append("source was inaccessible; no scored artifact is available")
        if status == "missing" and not limitations:
            limitations.append("no normalized or scored aggregate artifact was found")
        source = safe_public_source(locked.get("source_url"))
        if source is None:
            limitations.append("source link omitted because it was not a safe public URL or repository-relative path")
        case_count = max(selected_cases, default=int(configured.get("case_count", 0)))
        applicable_count = max(selected_applicable, default=int(configured.get("applicable_count", 0)))
        rows.append(
            {
                "dataset_id": dataset_id,
                "source": {"link": source, "revision": sanitize_text(locked.get("revision"), redactions)},
                "intended_use": intended_use,
                "domains": domains,
                "metric_focus": metric_focus,
                "status": status,
                "case_count": case_count if len(set(selected_cases)) <= 1 else None,
                "applicable_count": (
                    applicable_count if len(set(selected_applicable)) <= 1 else None
                ),
                "profiles": profile_metrics,
                "limitations": sorted(set(sanitize_text(item, redactions) for item in limitations if item)),
            }
        )
    status_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        status_counts[row["status"]] += 1
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "metric_unit": "dataset_profile_evaluations; no cross-profile confusion sum or F1 is calculated",
        "datasets": rows,
        "status_counts": dict(sorted(status_counts.items())),
        "domain_profile_metrics": build_domain_metrics(selectors, group_candidates),
        "limitations": sorted(set(global_limitations)),
    }


def percent(value: Any) -> str:
    if value is None:
        return "—"
    return f"{float(value) * 100:.4f}%"


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def source_markdown(source: Mapping[str, Any]) -> str:
    link = source.get("link")
    revision = markdown_escape(source.get("revision") or "unknown")
    if not link:
        return f"Unavailable @ `{revision}`"
    rendered = markdown_escape(link)
    if str(link).startswith("https://"):
        return f"[{rendered}]({rendered}) @ `{revision}`"
    return f"`{rendered}` @ `{revision}`"


def confusion_markdown_cells(metrics: Mapping[str, Any]) -> list[str]:
    if not metrics["available"]:
        return ["—"] * 8
    return [
        str(metrics["tp"]),
        str(metrics["tn"]),
        str(metrics["fp"]),
        str(metrics["fn"]),
        percent(metrics["precision"]),
        percent(metrics["recall"]),
        percent(metrics["f1"]),
        percent(metrics["fpr"]),
    ]


def profile_markdown_cells(metrics: Mapping[str, Any]) -> list[str]:
    return [
        str(metrics["cases"]),
        str(metrics["applicable"]),
        *confusion_markdown_cells(metrics["detection"]),
        *confusion_markdown_cells(metrics["enforcement"]),
        f'{metrics["enforcement"]["benign_blocks"]}/{metrics["enforcement"]["benign_total"]}',
        percent(metrics["enforcement"]["benign_block_rate"]),
    ]


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Deterministic benchmark coverage",
        "",
        "This report contains aggregate metrics only. It excludes benchmark payloads, local paths, "
        "private dataset identities, and private source identities.",
        "",
        "Each profile is reported separately. Confusion counts and F1 are never summed across profiles.",
        "",
        "## Dataset coverage",
        "",
        "| Dataset | Source and revision | Intended use | Metric focus | Status | Cases | Applicable | Profiles | "
        "Limitations |",
        "|---|---|---|---|---:|---:|---:|---|---|",
    ]
    for row in report["datasets"]:
        limitations = "; ".join(row["limitations"]) or "None"
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_escape(row["dataset_id"]),
                    source_markdown(row["source"]),
                    markdown_escape(", ".join(row["intended_use"]) or "Unspecified"),
                    markdown_escape(row["metric_focus"]),
                    markdown_escape(row["status"]),
                    str(row["case_count"]) if row["case_count"] is not None else "varies by profile",
                    str(row["applicable_count"]) if row["applicable_count"] is not None else "varies by profile",
                    markdown_escape(", ".join(row["profiles"]) or "—"),
                    markdown_escape(limitations),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Per-dataset profile metrics",
            "",
            "| Dataset | Profile | Cases | Applicable | Detection TP | Detection TN | Detection FP | "
            "Detection FN | Detection precision | Detection recall | Detection F1 | Detection FPR | "
            "Enforcement TP | Enforcement TN | Enforcement FP | Enforcement FN | Enforcement precision | "
            "Enforcement recall | Enforcement F1 | Enforcement FPR | Benign blocks | Benign block rate |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in report["datasets"]:
        for profile, metrics in row["profiles"].items():
            lines.append(
                "| "
                + " | ".join(
                    [
                        markdown_escape(row["dataset_id"]),
                        markdown_escape(profile),
                        *profile_markdown_cells(metrics),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "## Domain aggregate availability",
            "",
            "Domain totals require exact result-group selectors. Dataset purpose text is never used "
            "as aggregate evidence.",
            "",
            "| Domain | Available | Reason | Datasets | Evidence groups |",
            "|---|---:|---|---:|---:|",
        ]
    )
    for domain in REPORT_DOMAINS:
        aggregate = report["domain_profile_metrics"][domain]
        lines.append(
            "| "
            + " | ".join(
                [
                    domain,
                    "yes" if aggregate["available"] else "no",
                    markdown_escape(aggregate["reason"] or "—"),
                    str(aggregate["dataset_count"]),
                    str(aggregate["evidence_group_count"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Domain and profile metrics",
            "",
            "| Domain | Profile | Datasets | Evidence groups | Cases | Applicable | Detection TP | Detection TN | "
            "Detection FP | Detection FN | Detection precision | Detection recall | Detection F1 | Detection FPR | "
            "Enforcement TP | Enforcement TN | Enforcement FP | Enforcement FN | Enforcement precision | "
            "Enforcement recall | Enforcement F1 | Enforcement FPR | Benign blocks | Benign block rate |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for domain in REPORT_DOMAINS:
        aggregate = report["domain_profile_metrics"][domain]
        for profile, metrics in aggregate["profiles"].items():
            lines.append(
                "| "
                + " | ".join(
                    [
                        domain,
                        profile,
                        str(aggregate["dataset_count"]),
                        str(aggregate["evidence_group_count"]),
                        *profile_markdown_cells(metrics),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            "- A dataset is `scored` only when an aggregate dataset group has at least one applicable case.",
            "- Detection evaluates whether a rule produced a finding; enforcement evaluates the resulting block "
            "decision. `metric_focus` identifies the primary interpretation for a dataset; non-primary metrics "
            "remain visible but must not be presented as the dataset's headline score.",
            "- `normalized-only`, `normalized-mining-only`, `label-only`, `gated`, and `inaccessible` statuses "
            "can be supplied by the optional mapping.",
            "- Precision, recall, F1, FPR, and benign-block rate are unavailable when their denominator is zero.",
            "- When multiple run candidates exist, the generator deterministically selects the largest corpus, "
            "then the largest applicable set, then the highest numeric run-version suffix.",
            "- Domain aggregates are available only from mapping selectors with an exact dimension and exact "
            "group values; optional dataset IDs further constrain the evidence.",
            "- Intended-use and dataset-domain metadata are informational and never cause a mixed corpus to be "
            "included in a domain aggregate.",
            "",
        ]
    )
    return "\n".join(lines)


def atomic_write(path: Path, content: str) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    args = parse_args()
    public_path = Path(args.public_lock)
    private_path = Path(args.private_lock) if args.private_lock else None
    results_root = Path(args.results_root)
    mapping_path = Path(args.mapping) if args.mapping else None
    json_output = Path(args.json_output)
    markdown_output = Path(args.markdown_output)
    protected_inputs = {public_path.resolve(), results_root.resolve()}
    for optional in (private_path, mapping_path):
        if optional is not None:
            protected_inputs.add(optional.resolve())
    resolved_outputs = {json_output.resolve(), markdown_output.resolve()}
    if len(resolved_outputs) != 2 or protected_inputs & resolved_outputs:
        raise ValueError("report outputs must be distinct and must not overwrite an input")
    public_lock = load_lock(public_path)
    excluded_ids = private_only_ids(public_lock, private_path)
    redactions = private_tokens(private_path, public_lock)
    public_ids = {str(item["id"]) for item in public_lock}
    mapping, selectors = load_mapping(mapping_path, public_ids, excluded_ids, redactions)
    unknown_mapping_ids = sorted(set(mapping) - public_ids)
    if unknown_mapping_ids:
        raise ValueError("dataset mapping references an ID absent from the public lock")
    candidates, group_candidates, normalized, limitations = collect_candidates(
        results_root, public_ids, excluded_ids
    )
    report = build_report(
        public_lock,
        candidates,
        group_candidates,
        normalized,
        mapping,
        selectors,
        redactions,
        limitations,
    )
    rendered_json = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    rendered_markdown = render_markdown(report)
    atomic_write(json_output, rendered_json)
    atomic_write(markdown_output, rendered_markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .fixtures import read_json
from .galileo import merge_galileo_enrichment
from .galileo_config import apply_galileo_runtime_config
from .transform import build_summary


def build_payload_from_files(
    o11y_input: str | None = None,
    galileo_input: str | None = None,
    tenant_id: str | None = None,
    workspace_id: str | None = None,
    include_galileo: bool = False,
    realm: str | None = None,
) -> dict:
    rows = read_json(o11y_input, ("samples", "o11y_token_metric_rows.json"))
    payload = build_summary(rows, tenant_id=tenant_id, workspace_id=workspace_id, realm=realm)
    if include_galileo:
        galileo = read_json(galileo_input, ("samples", "galileo_runtime_controls.json"))
        galileo = apply_galileo_runtime_config(galileo)
        payload = merge_galileo_enrichment(payload, galileo)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a Cisco Cloud Control-ready Agent Tokenomics response.")
    parser.add_argument("--input", default=None, help="O11y token metric rows JSON. Defaults to packaged demo fixture.")
    parser.add_argument(
        "--galileo-input",
        default=None,
        help="Galileo runtime controls JSON. Defaults to packaged demo fixture.",
    )
    parser.add_argument(
        "--output",
        default="artifacts/generated_agent_tokenomics_summary.json",
        help="Output JSON path.",
    )
    parser.add_argument("--tenant-id", default="c3-demo-tenant")
    parser.add_argument("--workspace-id", default="wayne-demo")
    parser.add_argument("--realm", default=None, help="Splunk O11y realm for deep-link generation.")
    parser.add_argument(
        "--include-galileo",
        action="store_true",
        help="Attach Galileo runtime controls and eval evidence.",
    )
    args = parser.parse_args()

    payload = build_payload_from_files(
        o11y_input=args.input,
        galileo_input=args.galileo_input,
        tenant_id=args.tenant_id,
        workspace_id=args.workspace_id,
        include_galileo=args.include_galileo,
        realm=args.realm,
    )
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

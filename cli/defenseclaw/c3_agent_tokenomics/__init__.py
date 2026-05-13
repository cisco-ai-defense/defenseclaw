# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Cloud Control Agent Tokenomics demo bridge.

This package is intentionally thin: Splunk Observability remains the source of
truth for token metrics, and Galileo Agent Control / runtime eval evidence is an
optional server-side enrichment for the Cisco Cloud Control native app.
"""

from .galileo import merge_galileo_enrichment, summarize_galileo
from .transform import build_summary, metric_point_from_row, normalize_token_type

__all__ = [
    "build_summary",
    "merge_galileo_enrichment",
    "metric_point_from_row",
    "normalize_token_type",
    "summarize_galileo",
]

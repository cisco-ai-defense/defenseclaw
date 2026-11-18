# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0455: a prometheus destination listens on loopback only, refused at load with the reason."""

from __future__ import annotations

import pytest
from defenseclaw.observability.v8_config import V8ConfigError, load_validate_v8


def _source(listen: str) -> dict:
    return {
        "config_version": 8,
        "observability": {"destinations": [{"name": "prom", "kind": "prometheus", "listen": listen, "path": "/metrics"}]},
    }


@pytest.mark.parametrize("listen", ["0.0.0.0:9466", "[::]:9466", "10.0.0.5:9466", "metrics.example.com:9466"])
def test_gap0455_non_loopback_prometheus_listen_is_refused(listen: str) -> None:
    with pytest.raises(V8ConfigError) as captured:
        load_validate_v8(_source(listen))
    assert captured.value.path.endswith(".listen")
    assert "loopback" in captured.value.corrective_action


@pytest.mark.parametrize("listen", ["127.0.0.1:9466", "[::1]:9466", "localhost:9466"])
def test_gap0455_loopback_prometheus_listen_is_accepted(listen: str) -> None:
    load_validate_v8(_source(listen))

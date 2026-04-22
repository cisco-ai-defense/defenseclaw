# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OTel metrics for Python-side webhook sends (parity with ``internal/gateway/webhook.go``)."""

from __future__ import annotations

import hashlib
import time
from typing import Any

try:
    from opentelemetry import metrics
except ImportError:
    metrics = None  # type: ignore[assignment]

_meter: Any = None
_hist: Any = None


def _meter_hist():
    global _meter, _hist
    if metrics is None:
        return None, None
    if _hist is not None:
        return _meter, _hist
    _meter = metrics.get_meter("defenseclaw")
    _hist = _meter.create_histogram(
        name="defenseclaw.webhook.latency",
        unit="ms",
        description="Webhook dispatch latency (Python CLI test path)",
    )
    return _meter, _hist


def webhook_target_hash(url: str) -> str:
    """SHA-256 prefix of URL — matches Go ``hashWebhookTargetURL`` (12-byte hex)."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]


def record_webhook_delivery_ms(
    webhook_kind: str,
    target_url: str,
    status_code: int,
    duration_ms: float,
) -> None:
    """Record one delivery on the same series as the Go dispatcher."""
    _, h = _meter_hist()
    if h is None:
        return
    h.record(
        duration_ms,
        attributes={
            "webhook.kind": webhook_kind,
            "webhook.target_hash": webhook_target_hash(target_url),
            "http.status_code": status_code,
        },
    )


class WebhookDeliveryTimer:
    """Context manager: records latency + status on exit."""

    def __init__(self, webhook_kind: str, url: str) -> None:
        self.webhook_kind = webhook_kind
        self.url = url
        self._t0 = time.perf_counter()
        self.status_code: int | None = None

    def __enter__(self) -> WebhookDeliveryTimer:
        return self

    def __exit__(self, *exc: object) -> None:
        ms = (time.perf_counter() - self._t0) * 1000.0
        code = self.status_code if self.status_code is not None else 0
        record_webhook_delivery_ms(self.webhook_kind, self.url, code, ms)

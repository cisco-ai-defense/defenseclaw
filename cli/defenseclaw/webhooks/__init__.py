# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Webhook notifier package.

Parity layer for the runtime ``webhooks[]`` list consumed by
``internal/gateway/webhook.go``. Provides:

* ``writer`` — YAML CRUD (atomic tmp+rename) mirroring the observability
  writer for ``audit_sinks[]``.
* ``dispatch`` — pure-Python formatters for slack/pagerduty/webex/generic
  payloads plus a ``send_synthetic`` helper used by
  ``defenseclaw setup webhook test``.

The Go runtime stays the source of truth for dispatch; the Python
formatters share compact-JSON and HMAC semantics with the Go code and
are covered by structural-parity tests in both ``cli/tests`` and
``internal/gateway`` so drift is caught in CI.
"""

from defenseclaw.webhooks.dispatch import (
    DispatchResult,
    compute_hmac,
    format_generic_payload,
    format_pagerduty_payload,
    format_slack_payload,
    format_webex_payload,
    send_synthetic,
    synthetic_event,
)
from defenseclaw.webhooks.writer import (
    WebhookView,
    WebhookWriteResult,
    apply_webhook,
    list_webhooks,
    remove_webhook,
    set_webhook_enabled,
    validate_webhook_url,
)

__all__ = [
    "DispatchResult",
    "WebhookView",
    "WebhookWriteResult",
    "apply_webhook",
    "compute_hmac",
    "format_generic_payload",
    "format_pagerduty_payload",
    "format_slack_payload",
    "format_webex_payload",
    "list_webhooks",
    "remove_webhook",
    "send_synthetic",
    "set_webhook_enabled",
    "synthetic_event",
    "validate_webhook_url",
]

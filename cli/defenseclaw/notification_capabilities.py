# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Authoritative native desktop-notification platform capability."""

from __future__ import annotations

import platform
from dataclasses import dataclass


@dataclass(frozen=True)
class DesktopNotificationCapability:
    system: str
    supported: bool
    provider: str = ""
    unsupported_reason: str = ""

    def effective_enabled(self, configured_enabled: bool) -> bool:
        """Return effective native desktop delivery, not stored intent."""

        return self.supported and bool(configured_enabled)


def desktop_notification_capability(system: str | None = None) -> DesktopNotificationCapability:
    """Resolve support, accepting an injectable platform name for tests."""

    resolved = (system if system is not None else platform.system()).strip().lower()
    if resolved == "darwin":
        return DesktopNotificationCapability(resolved, True, provider="osascript")
    if resolved == "linux":
        return DesktopNotificationCapability(resolved, True, provider="notify-send")
    if resolved == "windows":
        return DesktopNotificationCapability(resolved, True, provider="Shell_NotifyIconW")
    return DesktopNotificationCapability(
        resolved,
        False,
        unsupported_reason="Native desktop notifications are unsupported on this platform.",
    )


__all__ = ["DesktopNotificationCapability", "desktop_notification_capability"]

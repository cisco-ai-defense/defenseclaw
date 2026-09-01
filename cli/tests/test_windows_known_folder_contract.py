# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Keep Python connector trust roots outside packaged-host redirection."""

from __future__ import annotations

import inspect

from defenseclaw import agent_selection, connector_paths, doctor_hooks
from defenseclaw.inventory import agent_discovery


def test_current_token_known_folder_resolvers_disable_package_redirection() -> None:
    expected = 0x00010000
    resolvers = (
        (agent_discovery, agent_discovery._windows_current_user_known_folder),
        (connector_paths, connector_paths._windows_current_user_local_app_data),
        (agent_selection, agent_selection._windows_known_folder),
        (doctor_hooks, doctor_hooks._windows_known_folder_path),
    )

    for module, resolver in resolvers:
        assert module._WINDOWS_KF_FLAG_NO_PACKAGE_REDIRECTION == expected
        assert "_WINDOWS_KF_FLAG_NO_PACKAGE_REDIRECTION" in inspect.getsource(resolver)

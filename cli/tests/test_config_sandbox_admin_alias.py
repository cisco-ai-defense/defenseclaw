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

"""SandboxAdminConfig is the runtime-neutral name; OpenShellAdminConfig its alias."""

import dataclasses

from defenseclaw import config as cfgmod


def test_openshell_admin_config_is_an_alias():
    assert cfgmod.OpenShellAdminConfig is cfgmod.SandboxAdminConfig


def test_admin_fields_keep_their_yaml_names():
    names = {f.name for f in dataclasses.fields(cfgmod.SandboxAdminConfig)}
    for key in ("required_pack", "min_profile", "allow_host_ports", "egress_block", "egress_allow_only", "user_approvals"):
        assert key in names


def test_openshell_admin_section_loads_as_sandbox_admin():
    loaded = cfgmod._merge_openshell_admin({"min_profile": "strict", "allow_host_ports": False})
    assert isinstance(loaded, cfgmod.SandboxAdminConfig)
    assert loaded.min_profile == "strict"
    assert loaded.allow_host_ports is False

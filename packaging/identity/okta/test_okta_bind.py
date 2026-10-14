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

"""Okta LDAP bind regression."""
import importlib.util
import pathlib

KIT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("okta_ldap_setup", KIT / "okta-ldap-setup.py")
okta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(okta)


def test_suspended_bind_user_is_not_ready(monkeypatch):
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind", "status": "SUSPENDED"})
    client = type("Client", (), {
        "org_url": "https://example.okta.com",
        "must": lambda self, method, path: (
            [{"type": "CUSTOM", "role": "role", "resource-set": "set"}] if path.endswith("/roles")
            else {"permissions": [{"label": name} for name in okta.BIND_PERMISSIONS]}
        ),
        "get_all": lambda self, path, key=None: [
            {"_links": {"self": {"href": f"https://example.okta.com/api/v1/{kind}"}}}
            for kind in ("users", "groups")
        ],
    })()
    report = okta.Report(False)
    okta.check_bind_user(client, report, "bind@example.com")
    assert report.problems == 1

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

"""``defenseclaw`` console entry point.

``upgrade`` and ``rollback`` are dispatched before the CLI is imported, so a
release whose CLI cannot even start can still be upgraded or rolled back.
"""

from __future__ import annotations

import os
import sys

# Cloud instance-metadata and container-credential endpoints (EC2 IMDS over
# IPv4 and IPv6, ECS task credentials). AWS asks that they bypass any proxy.
_INSTANCE_METADATA_HOSTS = ("169.254.169.254", "169.254.170.2", "fd00:ec2::254")
_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


def exempt_instance_metadata_from_proxy(environ=None) -> None:
    """Add the instance-metadata endpoints to NO_PROXY when a proxy is set.

    botocore (Bedrock ``instance_role``) honors the proxy variables for its
    IMDS credential lookup, so without this the token request and the role
    credentials went through the proxy in clear HTTP (GAP-1655). Existing
    entries are kept, ``NO_PROXY=*`` is left alone, and child processes (the
    gateway this CLI starts) inherit the result. The gateway applies the same
    rule itself (netguard.ExemptInstanceMetadataFromProxy).
    """
    env = os.environ if environ is None else environ
    if not any(str(env.get(key) or "").strip() for key in _PROXY_VARS):
        return
    for key, other in (("NO_PROXY", "no_proxy"), ("no_proxy", "NO_PROXY")):
        current = str(env.get(key) or "").strip() or str(env.get(other) or "").strip()
        if current == "*":
            continue
        present = {entry.strip().lower() for entry in current.split(",")}
        missing = [host for host in _INSTANCE_METADATA_HOSTS if host not in present]
        updated = ",".join(part for part in (current, *missing) if part)
        if updated != str(env.get(key) or ""):
            env[key] = updated


def use_bundled_litellm_cost_map(environ=None) -> None:
    """Make LiteLLM use its bundled model price list.

    Importing litellm fetches the price list from GitHub. Behind a dead or
    silent proxy that cost up to 5 s and printed a raw ANSI-coloured
    "LiteLLM:WARNING ... Failed to fetch remote model cost map" line in
    doctor output (GAP-2451). The CLI never needs the remote copy. An
    explicit LITELLM_LOCAL_MODEL_COST_MAP setting is kept.
    """
    env = os.environ if environ is None else environ
    env.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")


def main() -> None:
    exempt_instance_metadata_from_proxy()
    use_bundled_litellm_cost_map()
    from defenseclaw.config import ignore_unmanaged_deployment_pins

    ignore_unmanaged_deployment_pins()
    argv = sys.argv[1:]
    if argv and argv[0] in ("upgrade", "rollback"):
        from defenseclaw.upgrade_shim import run

        sys.exit(run(argv))

    from defenseclaw.main import main as cli_main

    try:
        cli_main()
    except SystemExit as exc:
        if exc.code in (0, None):
            _notice(argv)
        raise
    _notice(argv)


def _notice(argv: list[str]) -> None:
    # `uninstall --binaries` removes the environment this process runs from,
    # so the notice module may be gone by now: a finished uninstall printed a
    # ModuleNotFoundError traceback and exited 1.
    if argv and argv[0] == "uninstall":
        return
    try:
        from defenseclaw.update_notice import maybe_print
    except ImportError:
        return

    maybe_print(argv)


if __name__ == "__main__":
    main()

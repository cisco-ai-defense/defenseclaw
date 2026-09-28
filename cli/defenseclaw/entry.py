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

import sys


def main() -> None:
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
    from defenseclaw.update_notice import maybe_print

    maybe_print(argv)


if __name__ == "__main__":
    main()

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

"""``defenseclaw status`` builds its override line without importing the TUI (about 45 ms)."""

import subprocess
import sys
import textwrap

from defenseclaw.enforce import admission_overrides
from defenseclaw.tui.services import overview_state


def test_overview_reexports_the_shared_helpers() -> None:
    assert overview_state.admission_action_overrides is admission_overrides.admission_action_overrides
    assert overview_state.format_scanner_overrides_summary is admission_overrides.format_scanner_overrides_summary


def test_status_override_line_does_not_import_the_tui() -> None:
    code = textwrap.dedent(
        """
        import sys
        from defenseclaw.commands import cmd_status
        from defenseclaw.config import Config

        assert cmd_status._scanner_overrides_summary(Config()) == ""
        loaded = sorted(name for name in sys.modules if name.startswith("defenseclaw.tui"))
        print(",".join(loaded))
        """
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ""

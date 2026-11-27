# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-2148: the doctor's POSIX hooks-dir claim resolves . and .. as Setup does."""

import pytest
from defenseclaw import hook_integrity

HOOKS = "/home/u/.defenseclaw/hooks"


@pytest.mark.parametrize(
    ("word", "owned"),
    [
        (HOOKS + "/claude-code-hook.sh", True),
        (HOOKS + "/./claude-code-hook.sh", True),
        (HOOKS + "/sub/../claude-code-hook.sh", True),
        (HOOKS + "/../../bin/x", False),
        (HOOKS + "/../hooks-other/claude-code-hook.sh", False),
        (HOOKS + "/sub/../../x", False),
        # The whole path is resolved (CHK-RF-ENTWIN): a doubled separator
        # roots the rest, and a way back into the hooks dir is still ours.
        (HOOKS + "//../../bin/x", False),
        (HOOKS + "///../x", False),
        (HOOKS + "/../hooks/claude-code-hook.sh", True),
    ],
)
def test_gap2148_claude_hooks_dir_claim_resolves_dotdot(word: str, owned: bool) -> None:
    claimed = hook_integrity._setup_claims_edited_entry(
        "claudecode", word + " --event PreToolUse", HOOKS + "/claude-code-hook.sh", word, " --event PreToolUse", "", False, False
    )
    assert claimed is owned

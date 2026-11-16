# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""One-line cause text that keeps every path exactly as it is on disk.

A cause the gateway or a probe recorded names folders and accounts as plain
text, without quotes, so a run of spaces inside it can belong to a folder
name (an account named ``a  b`` has a profile folder of the same name). Cause
text is folded to one line by joining its lines; the spaces inside a line are
never touched, so the folder shown is the folder named in the fix command.
"""

from __future__ import annotations


def single_line(text: object) -> str:
    """*text* on one line: line breaks and tabs become one space, spaces are kept."""
    lines = (line.strip() for line in str(text).replace("\t", " ").splitlines())
    return " ".join(line for line in lines if line)

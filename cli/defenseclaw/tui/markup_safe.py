# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Escape host text for the TUI's markup sinks."""

from __future__ import annotations

import re

# Zero-width space: invisible, zero cells wide in Rich and Textual.
_BREAK = "\u200b"
# A run of backslashes right before a "[" or at the end of the text.
_BACKSLASH_RUN = re.compile(r"\\+(?=\[|\Z)")


def escape(text: object) -> str:
    """Escape ``text`` so neither Textual nor Rich reads any of it as markup.

    ``rich.markup.escape`` only escapes a ``[`` followed by a letter, ``#``,
    ``/`` or ``@``. Textual's parser reads any ``[`` as a tag, so host text such
    as ``[90m a=b-c`` (a colour code that lost its ESC) raised MarkupError
    (GAP-1675). Both parsers print ``\\[`` as ``[``.

    The two parsers disagree on backslashes in front of ``[``: Rich halves a
    run of them, Textual strips one. No backslash count is right for both, so a
    host backslash before ``[`` (``C:\\work\\[/old]``) or at the end of the text
    (``C:\\tmp\\`` followed by our closing tag) is separated from the next
    ``[`` by a zero-width space. Then every backslash stays literal in both.
    """

    value = _BACKSLASH_RUN.sub(lambda match: match.group(0) + _BREAK, str(text))
    return value.replace("[", "\\[")

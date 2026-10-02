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


def escape(text: object) -> str:
    """Escape every ``[`` so neither Textual nor Rich reads ``text`` as markup.

    ``rich.markup.escape`` only escapes a ``[`` followed by a letter, ``#``,
    ``/`` or ``@``. Textual's parser reads any ``[`` as a tag, so host text such
    as ``[90m a=b-c`` (a colour code that lost its ESC) raised MarkupError
    (GAP-1675). Both parsers print ``\\[`` as ``[``.
    """

    return str(text).replace("[", "\\[")

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The upgrade and rollback status lines where a stream cannot show their glyphs."""

from __future__ import annotations

import io
import os
import sys

import pytest
from defenseclaw import upgrade_shim


class _Stream(io.TextIOWrapper):
    def __init__(self, encoding: str, tty: bool) -> None:
        # newline="\n": the assertions compare the bytes print() wrote, so the
        # wrapper must not turn "\n" into os.linesep ("\r\n" on Windows).
        super().__init__(io.BytesIO(), encoding=encoding, newline="\n")
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def text(self) -> str:
        self.flush()
        return self.buffer.getvalue().decode(self.encoding)


@pytest.mark.parametrize(("encoding", "tty", "shown"), [("cp1252", True, "OK"), ("utf-8", True, "✓")])
def test_status_glyphs_are_ascii_where_the_stream_cannot_show_them(monkeypatch, encoding, tty, shown) -> None:
    # rel-1-0-1:GAP-0002: PowerShell 7 showed "?" at the start of the upgrade
    # and rollback lines: the glyph was replaced on a cp1252 stream.
    out, err = _Stream(encoding, tty), _Stream(encoding, tty)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    upgrade_shim._tolerant_output()
    print("  ✓ DefenseClaw 1.0.1 is up to date")
    print("  → Installing DefenseClaw 1.0.2", file=sys.stderr)
    assert out.text() == f"  {shown} DefenseClaw 1.0.1 is up to date\n"
    assert "?" not in err.text()


def test_redirected_windows_output_is_ascii(monkeypatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    assert not upgrade_shim._shows_glyphs(_Stream("utf-8", tty=False))
    assert upgrade_shim._shows_glyphs(_Stream("utf-8", tty=True))

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Base class for every TUI modal: a modal closes at most once."""

from __future__ import annotations

from textual.await_complete import AwaitComplete
from textual.screen import ModalScreen, ScreenResultType


class GuardedModalScreen(ModalScreen[ScreenResultType]):
    """A ``ModalScreen`` that ignores every ``dismiss`` after the first.

    Keys are read faster than the screen stack changes. A quick second Enter
    in a picker or action menu queues a second activation before the first
    ``dismiss`` has popped the screen. The second ``dismiss`` then ran the
    result callback again and popped the screen underneath, and on the last
    screen it raised ``ScreenStackError`` and ended the app
    (rel-1-0-6:GAP-0479). Every modal derives from this class so no screen
    needs its own guard.
    """

    _modal_closed: bool = False

    def dismiss(self, result: ScreenResultType | None = None) -> AwaitComplete:
        if self._modal_closed:
            return AwaitComplete.nothing()
        self._modal_closed = True
        return super().dismiss(result)

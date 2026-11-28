# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-0894: retired-key counts are per gateway process; doctor names the replica."""

from defenseclaw.commands import cmd_routing


def _view(waiting: int, dropped: int = 0, replica: str | None = None) -> dict:
    r = {"waiting": waiting, "dropped": dropped, "cap": 4096}
    if replica is not None:
        r["replica"] = replica
    return {"id": "nightly", "scope": "batch", "retired_keys": r}


def test_retired_rows_name_the_replica() -> None:
    rows = cmd_routing.retired_key_rows([_view(3000, replica="gw-7f9c")])
    assert rows and "on this replica (gw-7f9c)" in rows[0][1]
    rows = cmd_routing.retired_key_rows([_view(10, dropped=2, replica="gw-7f9c")])
    assert rows and "on this replica (gw-7f9c), the spend of 2 retired key(s) was dropped" in rows[0][1]


def test_retired_rows_without_a_name_say_this_replica() -> None:
    rows = cmd_routing.retired_key_rows([_view(3000)])
    assert rows and "on this replica, 3000 of 4096" in rows[0][1]

# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Exact SQLite audit time ordering for read-only compatibility views."""


def audit_time_order(db, alias: str = "", *, newest: bool = True) -> str:
    columns = {row[1] for row in db.execute("PRAGMA table_info(audit_events)")}
    prefix = f"{alias}." if alias else ""
    instant = (
        f"{prefix}retention_timestamp_unix_nano"
        if "retention_timestamp_unix_nano" in columns
        else f"julianday({prefix}timestamp)"
    )
    direction = "DESC" if newest else "ASC"
    return f"{instant} {direction}, {prefix}rowid {direction}"

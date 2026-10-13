# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Decode Codex TOML, including the UTF-8 BOM written by PowerShell 5.1."""

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def loads(raw: bytes) -> dict:
    return tomllib.loads(raw.decode("utf-8-sig"))

# Copyright 2026 Cisco Systems, Inc. and its affiliates
# Licensed under the Apache License, Version 2.0 (the "License").
# SPDX-License-Identifier: Apache-2.0
"""Trusted connector implementations; add config and register checks here."""

from . import claudecode, codex

CONNECTORS = {"codex": codex, "claudecode": claudecode}

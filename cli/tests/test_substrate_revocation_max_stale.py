# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""RV1-09: the Python mirror of substrate.identity.revocation max_stale."""

from defenseclaw.config import SubstrateRevocationConfig

S = 10**9


def test_effective_max_stale_default_follows_sync_interval() -> None:
    assert SubstrateRevocationConfig().effective_max_stale_ns() == 60 * S
    assert SubstrateRevocationConfig(sync_interval="40s").effective_max_stale_ns() == 80 * S
    assert SubstrateRevocationConfig(sync_interval="2s", max_stale="30s").effective_max_stale_ns() == 30 * S


def test_max_stale_must_be_twice_sync_interval() -> None:
    assert SubstrateRevocationConfig(sync_interval="5s", max_stale="5s").max_stale_error()
    assert SubstrateRevocationConfig(sync_interval="5s", max_stale="9s").max_stale_error()
    assert SubstrateRevocationConfig(max_stale="2h").max_stale_error()
    assert SubstrateRevocationConfig(sync_interval="5s", max_stale="10s").max_stale_error() is None
    assert SubstrateRevocationConfig().max_stale_error() is None

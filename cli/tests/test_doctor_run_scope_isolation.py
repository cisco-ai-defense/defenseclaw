# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""A test that opens the Doctor run scope without a Click context to close it does
not leave the scope open for the tests after it (they run in file order)."""

from __future__ import annotations

from defenseclaw import doctor_health


def test_a_test_may_open_the_doctor_run_scope_and_never_close_it():
    doctor_health.begin_installed_version_run()

    assert doctor_health._probe_run_scoped


def test_the_next_test_finds_the_doctor_run_scope_closed():
    assert not doctor_health._probe_run_scoped

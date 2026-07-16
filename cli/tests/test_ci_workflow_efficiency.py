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

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_shards_python_once_and_does_not_repeat_unified_corpus() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "name: Python Test (shard ${{ matrix.shard }})" in workflow
    assert "shard: [0, 1, 2, 3]" in workflow
    assert "python3 scripts/python_test_shards.py" in workflow
    assert "name: Python Lint & Test" in workflow
    assert "needs: python-test" in workflow
    assert ".venv/bin/coverage combine" in workflow
    assert "name: make test (unified)" not in workflow
    assert "run: make test" not in workflow


def test_ci_shards_slow_gateway_package_and_combines_go_coverage() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "name: Go Gateway Test (shard ${{ matrix.shard }})" in workflow
    assert "python3 scripts/go_test_shards.py" in workflow
    assert "name: Go Test (remaining packages)" in workflow
    assert "needs: [go-test-gateway, go-test-other]" in workflow
    assert "python3 scripts/merge_go_coverage.py" in workflow
    assert "go tool cover -func=coverage.out" in workflow
    assert "run: make go-test-cov" not in workflow

    sharder = (ROOT / "scripts/go_test_shards.py").read_text(encoding="utf-8")
    assert "Test|Fuzz|Example" in sharder


def test_release_validates_reviewed_macos_pin_without_freshness_block() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")

    assert "python3 scripts/check-macos-upstream.py --offline" in workflow
    assert "Require latest stable macOS app source" not in workflow


def test_release_dispatch_version_is_stamped_without_a_version_only_pr() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")

    assert workflow.count('scripts/stamp-version.sh "$RELEASE_TAG"') >= 2
    assert "Require reviewed source release identity" not in workflow
    assert "GitHub source snapshot uses development version" in workflow
    first_stamp = workflow.index('scripts/stamp-version.sh "$RELEASE_TAG"')
    build_stamp = workflow.index('scripts/stamp-version.sh "$RELEASE_TAG"', first_stamp + 1)
    identity_check = workflow.index(
        "python3 scripts/source_release_identity.py check", build_stamp
    )
    assert build_stamp < identity_check

    macos_build = (ROOT / "scripts/build-macos-app-release.sh").read_text(
        encoding="utf-8"
    )
    assert 'MARKETING_VERSION="${VERSION}"' in macos_build
    assert '-X main.version=${VERSION}' in macos_build

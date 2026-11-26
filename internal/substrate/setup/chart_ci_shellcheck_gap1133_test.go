// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// substrate-1:GAP-1133: the Kind E2E scripts (test/substrate-e2e/*.sh) run
// only in the Kind workflow, so the substrate-chart job lints them with
// shellcheck; without the step a script mistake first shows up in the slow
// Kind run.
func TestChartJobLintsTheKindE2EScripts(t *testing.T) {
	ci, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	job := ciJob(t, strings.ReplaceAll(string(ci), "\r\n", "\n"), "substrate-chart")
	if !strings.Contains(job, "shellcheck -S warning test/substrate-e2e/*.sh") {
		t.Fatal("the CI job substrate-chart does not run shellcheck on test/substrate-e2e/*.sh")
	}
}

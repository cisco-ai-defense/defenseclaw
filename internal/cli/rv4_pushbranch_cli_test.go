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

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// RV6-4 (GAP-0767, GAP-0772): pull --push-branch is refused, before the
// relay opens, for a copy this computer sent with credentials replaced;
// the answer points at pull --branch.
func TestRV4PushBranchRefusesAReplacedCopy(t *testing.T) {
	dir := t.TempDir()
	rec := func(name, body string) {
		p := filepath.Join(dir, "sandboxes", name, "copy", "copy.json")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A tracked file had credentials replaced: the sandbox starts at the
	// placeholder commit (sandbox_head differs from head).
	rec("sub-aaaaaaaaaaaa", `{"name":"sub-aaaaaaaaaaaa","base_git":"","baseline":"","head":"1111111111111111111111111111111111111111","sandbox_head":"2222222222222222222222222222222222222222","secret_lines":[{"rel":"config/app.env","rule":"r","line":1,"lines":1,"placeholder":"DC_SECRET_1"}]}`)
	rec("sub-bbbbbbbbbbbb", `{"name":"sub-bbbbbbbbbbbb","base_git":"","baseline":""}`)
	// Only an untracked file had credentials replaced: no placeholder
	// commit, so the push goes on to the review (RV6-4 ruling).
	rec("sub-dddddddddddd", `{"name":"sub-dddddddddddd","base_git":"","baseline":"","head":"1111111111111111111111111111111111111111","sandbox_head":"1111111111111111111111111111111111111111","secret_lines":[{"rel":"notes/local.env","rule":"r","line":1,"lines":1,"placeholder":"DC_SECRET_1"}]}`)
	err := substratePushBranchReplaced(dir, "sub-aaaaaaaaaaaa", "claude-1", "agent/x")
	if cliusage.ExitCode(err) != substrateExitRefused || !errors.Is(err, osw.ErrPlaceholderCommit) ||
		!strings.Contains(err.Error(), "substrate pull claude-1 --branch agent/x") {
		t.Errorf("replaced copy: %v (exit %d)", err, cliusage.ExitCode(err))
	}
	for _, name := range []string{"sub-bbbbbbbbbbbb", "sub-cccccccccccc", "sub-dddddddddddd"} {
		if err := substratePushBranchReplaced(dir, name, "claude-1", "agent/x"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

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

//go:build !windows

package workspace

import (
	"strings"
	"testing"
)

// RV8-5: with uncommitted changes in the sandbox, the branch message lists
// the agent's commits only, not DefenseClaw's own commits on top of them.
func TestRV8BranchLeavesOutOurCommits(t *testing.T) {
	e, fs, _ := s9aCopy(t, "rv8b")
	fs.write(remoteRepo+"/agent.txt", "agent work\n")
	fs.agent(remoteRepo, "add", "agent.txt")
	fs.agent(remoteRepo, "commit", "-q", "-m", "agent: add work")
	fs.write(remoteRepo+"/more.txt", "not committed\n")
	pull(t, e, fs, "rv8b")
	if _, err := apply(e, "rv8b", ApplyBranch, func(o *ApplyOptions) { o.AcceptSensitive = true }); err != nil {
		t.Fatal(err)
	}
	msg := e.git(e.project, "log", "-1", "--format=%B", "dc/rv8b")
	if !strings.Contains(msg, "- agent: add work") {
		t.Errorf("branch message lacks the agent's commit:\n%s", msg)
	}
	if strings.Contains(msg, "- defenseclaw:") {
		t.Errorf("branch message lists a DefenseClaw commit:\n%s", msg)
	}
}

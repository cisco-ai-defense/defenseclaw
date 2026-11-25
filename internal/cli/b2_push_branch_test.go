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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// B2 2.4: pull --push-branch is a pull mode of its own: it is refused
// with another mode before anything is read, and it takes --allow-flagged.
func TestB2PullPushBranchIsAMode(t *testing.T) {
	_, _, err := runSubstrate(t, newSubstratePullCmd(), "a1", "--push-branch", "agent/x", "--apply")
	if cliusage.ExitCode(err) != 2 || !strings.Contains(err.Error(), "--push-branch NAME") {
		t.Fatalf("err = %v (exit %d)", err, cliusage.ExitCode(err))
	}
	f := newSubstratePullCmd().Flags().Lookup("allow-flagged")
	if f == nil || !strings.Contains(f.Usage, "--push-branch") {
		t.Fatal("--allow-flagged does not name --push-branch")
	}
}

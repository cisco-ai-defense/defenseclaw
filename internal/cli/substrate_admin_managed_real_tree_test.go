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

//go:build linux || darwin

package cli

import (
	"strings"
	"testing"
)

// The real tree, as the launcher cuts it: the group lists the user's commands
// and none of the administrator tools, and a refused tool answers with the
// launcher's refusal.
func TestSubstrate_Admin_ManagedLauncherTree(t *testing.T) {
	stdout, stderr, code := runLauncherRealTree(t, "substrate", "--help")
	if code != 0 {
		t.Fatalf("substrate --help: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, name := range []string{"login", "run", "list", "doctor", "policy", "secrets"} {
		if !strings.Contains(stdout, "  "+name+" ") {
			t.Errorf("the managed substrate help lacks %q:\n%s", name, stdout)
		}
	}
	for _, name := range []string{"setup", "bundle", "template"} {
		if strings.Contains(stdout, "  "+name+" ") {
			t.Errorf("the managed substrate help lists the administrator tool %q:\n%s", name, stdout)
		}
	}
	_, stderr, code = runLauncherRealTree(t, "substrate", "setup", "--help")
	if code != 2 || !strings.Contains(stderr, "This computer is managed") {
		t.Errorf("substrate setup: exit %d, stderr %q", code, stderr)
	}
}

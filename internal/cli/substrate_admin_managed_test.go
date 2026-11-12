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
)

// E26: the substrate launcher only talks to a cluster, so a managed computer
// offers the user's commands and refuses the administrator tools.
func TestSubstrate_Admin_ManagedTableOffersTheUserCommands(t *testing.T) {
	offered := [][]string{
		{"substrate"}, {"substrate", "--help"}, {"substrate", "-h"},
		{"substrate", "login"}, {"substrate", "login", "--admin-url", "https://admin.example.test:9443"},
		{"substrate", "logout"}, {"substrate", "whoami", "--json"},
		{"substrate", "run", "claude"}, {"substrate", "connect", "fix-tests"}, {"substrate", "list"}, {"substrate", "status"},
		{"substrate", "logs", "fix-tests", "-f"}, {"substrate", "pull", "fix-tests"}, {"substrate", "checkpoint", "fix-tests"},
		{"substrate", "undo", "fix-tests"}, {"substrate", "delete", "fix-tests"}, {"substrate", "migrate", "fix-tests"},
		{"substrate", "approvals"}, {"substrate", "approve", "ask-1"}, {"substrate", "reject", "ask-1"}, {"substrate", "usage"},
		{"substrate", "secrets", "list"}, {"substrate", "policy", "explain"}, {"substrate", "doctor", "--json"},
	}
	for _, args := range offered {
		if !launcherOffers(args) {
			t.Errorf("the launcher refuses %q", args)
		}
	}
	refused := [][]string{
		{"substrate", "setup"}, {"substrate", "setup", "--install-file", "install.yaml"},
		{"substrate", "bundle"}, {"substrate", "bundle", "apply", "policy.bundle"}, {"substrate", "bundle", "status"},
		{"substrate", "template", "build"}, {"substrate", "template", "keygen", "--out", "keys"},
		{"substrate", "logins"}, {"substrate", "-x"}, {"substrates"}, {"substrate", "serve"}, {"substrate-chart"},
		{"help", "substrate"},
	}
	for _, args := range refused {
		if launcherOffers(args) {
			t.Errorf("the launcher offers %q", args)
		}
	}
}

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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// One Devin Local process serves every Devin Desktop tab, so a Devin
// session block under Desktop asks for a Desktop restart.
func TestDevinDesktopBlockSaysQuitAndReopenDesktop(t *testing.T) {
	reason := "enterprise_foreign_hook_blocked: ... after removing the hook, restart the agent."
	if got := withDesktopRestartNote("devin", "devin helper (plugin)", reason); !strings.HasSuffix(got, devinDesktopRestartNote) {
		t.Fatalf("a block under Devin Desktop must say quit and reopen Desktop: %q", got)
	}
	for _, tc := range []struct{ name, host string }{{"devin", "tmux"}, {"cursor", "devin helper (plugin)"}} {
		if got := withDesktopRestartNote(tc.name, tc.host, reason); got != reason {
			t.Fatalf("%s under %s keeps its reason: %q", tc.name, tc.host, got)
		}
	}
}

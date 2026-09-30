// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import "testing"

func TestHostNamesTheProcessThatStartedTheAgent(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  string
	}{
		{"Devin Local under Devin Desktop", []string{"defenseclaw-hook", "sh", "devin", "Devin Helper (Plugin)", "Devin"}, "devin helper (plugin)"},
		{"the CLI in a terminal", []string{"defenseclaw-hook", "devin", "-zsh", "tmux"}, "tmux"},
		{"no agent", []string{"defenseclaw-hook", "bash", "sshd"}, ""},
	}
	for _, tc := range cases {
		if got := hostFrom(chain(tc.names...).lookup, 100); got != tc.want {
			t.Errorf("%s: host = %q, want %q", tc.name, got, tc.want)
		}
	}
}

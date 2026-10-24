// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHermesNativeExecutionProbeRequiresExactRegisteredCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"exact", []string{"--connector", "hermes", "--defenseclaw-execution-probe"}, true},
		{"other connector", []string{"--connector", "codex", "--defenseclaw-execution-probe"}, false},
		{"extra event", []string{"--connector", "hermes", "--event", "pre_tool_use", "--defenseclaw-execution-probe"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newHookCmd()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if tc.want && (err != nil || output.String() != "defenseclaw-execution-probe-ok\n") {
				t.Fatalf("probe error=%v output=%q", err, output.String())
			}
			if !tc.want && (err == nil || strings.Contains(output.String(), "defenseclaw-execution-probe-ok")) {
				t.Fatalf("unexpected proof error=%v output=%q", err, output.String())
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"strings"
	"testing"
)

// GAP-0375: the shell banner describes the saved launch, while the shell
// invocation must never receive those harness arguments.
func TestConnectShellBannerKeepsTheRunsModel(t *testing.T) {
	for _, tc := range []struct {
		harness string
		args    []string
	}{
		{"claude", []string{"--model", "anthropic.claude-haiku-4-5"}},
		{"codex", []string{"-m", "openai.gpt-5.4"}},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.env[EnvBedrockToken] = "test credential value"
			noChanges(ta)
			ta.ok(t, ta.Run(bg, RunOptions{Harness: tc.harness, Name: "shell-model", LLM: LLMBedrock, Args: tc.args}))
			runOutput := ta.output()
			ta.out.Reset()
			ta.term.runs = nil
			ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "shell-model", Shell: true}))
			for _, line := range strings.Split(runOutput, "\n") {
				if strings.Contains(line, "Model     ") {
					has(t, ta.output(), line)
				}
			}
			has(t, ta.output(), "Model     "+tc.args[1])
			if len(ta.term.runs) != 1 {
				t.Fatalf("shell runs = %q", ta.term.runs)
			}
			for _, arg := range ta.term.runs[0] {
				if arg == tc.args[0] || strings.Contains(arg, tc.args[1]) {
					t.Fatalf("shell inherited a harness option: %q", ta.term.runs[0])
				}
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// GAP-0929 (reopened): a Codex or Claude Code configuration that reaches,
// through a link, a file the account does not own was named only in the
// guardian log; status and verify said nothing. The guardian reports it as
// an agent config notice, which they word with the remedy and no path.
func TestANativeOTLPConfigTheAccountDoesNotOwnIsWorded(t *testing.T) {
	if !ValidAgentConfigStatus(AgentConfigNativeOTLPUnchecked) {
		t.Fatal("the guardian's record drops the native OTLP notice")
	}
	for name, file := range map[string]string{"codex": "Codex config.toml", "claudecode": "Claude Code settings.json"} {
		message, ok := AgentConfigNotice(name, "dcw-std1", AgentConfigNativeOTLPUnchecked)
		if !ok {
			t.Fatalf("%s: no notice", name)
		}
		for _, want := range []string{name + " for user dcw-std1", file, "does not own", "remove the link", "next repair checks it"} {
			if !strings.Contains(message, want) {
				t.Fatalf("%s notice %q lacks %q", name, message, want)
			}
		}
		if strings.Contains(message, `\`) || strings.Contains(message, ":\\") {
			t.Fatalf("%s notice names a path: %q", name, message)
		}
	}
	if _, ok := AgentConfigNotice("hermes", "dcw-std1", AgentConfigNativeOTLPUnchecked); ok {
		t.Fatal("a notice for a connector without a native OTLP exporter")
	}
}

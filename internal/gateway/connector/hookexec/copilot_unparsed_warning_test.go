// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

func TestCopilotUnparsedObserveAnswerIsVisibleWithoutDeny(t *testing.T) {
	const warning = "DefenseClaw could not read this Copilot tool call; it was allowed in observe mode and recorded for review."
	for _, event := range []string{"preToolUse", "permissionRequest"} {
		result := run(t, "copilot", ok(`{"action":"allow","reason":"`+warning+`","rule_ids":["HOOK-TOOL-CALL-UNPARSED"]}`),
			func(opts *Options) { opts.Event = event; opts.FailMode = "closed" })
		if result.code != 0 || result.stdout != "" || !strings.Contains(result.stderr, warning) {
			t.Fatalf("%s code=%d stdout=%q stderr=%q", event, result.code, result.stdout, result.stderr)
		}
	}
	ordinary := run(t, "copilot", ok(`{"action":"allow","reason":"ordinary"}`),
		func(opts *Options) { opts.Event = "preToolUse"; opts.FailMode = "closed" })
	if ordinary.code != 0 || strings.Contains(ordinary.stderr, "ordinary") {
		t.Fatalf("ordinary allow got warning: %+v", ordinary)
	}
}

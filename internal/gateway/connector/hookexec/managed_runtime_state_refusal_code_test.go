// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// rel-1-0-3 GAP-0303: a managed Claude Code hook whose runtime descriptor is
// missing (an uninstall and reinstall under a cached hook registration)
// blocked with "DefenseClaw is not set up correctly on this computer.
// Contact your administrator." and no code, so the documented
// enterprise_managed_runtime_descriptor_missing could not be counted. The
// refusal still blocks and now ends with its documented code, outside and
// inside an enterprise lifecycle run.
func TestManagedRuntimeStateRefusalEndsWithItsCode(t *testing.T) {
	previous := managedLifecycleHeld
	t.Cleanup(func() { managedLifecycleHeld = previous })
	for _, held := range []bool{false, true} {
		managedLifecycleHeld = func(Options) bool { return held }
		for _, reason := range []string{
			"enterprise_managed_runtime_descriptor_missing", "enterprise_managed_runtime_state_invalid",
			"enterprise_managed_hook_socket_missing", "enterprise_machine_policy_summary_untrusted",
		} {
			opts := Options{
				Connector:          "claudecode",
				APIAddr:            "127.0.0.1:1",
				ManagedEnterprise:  true,
				ManagedStandalone:  true,
				StrictAvailability: true,
				FailMode:           "closed",
				Home:               t.TempDir(),
			}
			opts.ManagedRuntimeFailure = reason
			opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
			var out, errb bytes.Buffer
			opts.Stdout, opts.Stderr = &out, &errb
			code := Run(context.Background(), opts)
			stdout := out.String()
			if code != 0 || !strings.Contains(stdout, `"permissionDecision":"deny"`) {
				t.Fatalf("held=%v %s: not a structured deny: code=%d stdout=%q stderr=%q", held, reason, code, stdout, errb.String())
			}
			if !strings.Contains(stdout, "("+reason+")") {
				t.Fatalf("held=%v %s: the refusal does not end with its code: %q", held, reason, stdout)
			}
		}
	}
	// A refusal with a cause and code of its own is unchanged.
	if got := managedStandaloneFailClosedText("PreToolUse", "transport", managedRuntimeHomeMissingReason); !strings.HasSuffix(got, " ("+managedRuntimeHomeMissingReason+")") {
		t.Fatalf("home missing text = %q", got)
	}
}

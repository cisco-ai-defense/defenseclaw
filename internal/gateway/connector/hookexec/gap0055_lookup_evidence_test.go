// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

// TestGAP0055ManagedHookResolvesCommandLookups is gas-ux-r1 GAP-0055 in the
// managed hook client: it reads the call's write evidence before it asks
// the gateway, and on 1.0.7 and 1.0.8 that reading panicked on an unzip with
// no arguments, so the client failed closed ("Cisco AI Defense could not
// verify this request") for command -v unzip && command -v tar. Each form
// now yields the request facts without a panic, for each managed connector.
func TestGAP0055ManagedHookResolvesCommandLookups(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"command -v unzip && command -v tar",
		"command -v unzip",
		"command -v unzip; command -v tar",
		"command -v unzip || exit 1",
		"env unzip",
		"command unzip",
		"unzip",
		"command -V unzip",
		"type unzip && hash tar",
		"exec -a",
		"nice unzip",
	} {
		payload, err := json.Marshal(map[string]any{"session_id": "gap0055", "hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Errorf("%s %q: managed hook request facts panic: %v", connector, command, recovered)
					}
				}()
				setHookRequestFacts(http.Header{}, Options{Connector: connector, Event: "PreToolUse", ManagedEnterprise: true}, payload)
			}()
		}
	}
}

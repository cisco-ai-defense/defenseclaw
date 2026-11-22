// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package kitspec

import "testing"

// GAP-0116: a kit image runs the relay as root and names the agent's user;
// the relay starts the agent as that user.
func TestKitImageRunsTheRelayAsRootAndTheAgentAsItsUser(t *testing.T) {
	spec, _, err := Spec(Options{Connector: "codex", KitVersion: "1.0.10", Provider: "openai",
		HookBinary: []byte("hook"), RelayBinary: []byte("relay"), MetadataOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if spec.User != "0:0" || spec.AgentUser != "1000:1000" {
		t.Fatalf("User %q AgentUser %q", spec.User, spec.AgentUser)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// TestConfigChangeActivityNamesTheWriter pins the config.change.applied
// event (GAP-0005): the actor is the writer recorded in
// config.generation.json for the applied bytes, with the changed paths, the
// generation, the sha256 and the restart-required paths; bytes no writer
// recorded keep the plain action.
func TestConfigChangeActivityNamesTheWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	before := []byte("config_version: 9\nguardrail:\n  mode: observe\n  host: 127.0.0.1\n")
	after := []byte("config_version: 9\nguardrail:\n  mode: action\n  host: 0.0.0.0\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := configChangeActivity(path, before, before, []string{"guardrail"}); ok {
		t.Fatal("bytes no writer recorded produced a writer event")
	}
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "cli:alice", Reason: "defenseclaw config set",
	}, func() (bool, error) { return true, os.WriteFile(path, after, 0o600) }); err != nil {
		t.Fatalf("record the write: %v", err)
	}
	in, ok := configChangeActivity(path, before, after, []string{"guardrail"})
	if !ok {
		t.Fatal("recorded bytes produced no writer event")
	}
	if in.Actor != "cli:alice" || in.Reason != "defenseclaw config set" || in.TargetID != "config.yaml" {
		t.Fatalf("event = actor %q reason %q target %q", in.Actor, in.Reason, in.TargetID)
	}
	if len(in.Diff) != 2 || in.Diff[0].Path != "guardrail.host" || in.Diff[1].Path != "guardrail.mode" {
		t.Fatalf("diff = %+v, want guardrail.host and guardrail.mode", in.Diff)
	}
	restart, _ := in.After["restart_required"].([]string)
	if len(restart) != 1 || restart[0] != "guardrail.host" ||
		in.After["config_generation"] != uint64(1) || in.After["config_sha256"] != configwrite.SHA256Hex(after) {
		t.Fatalf("after = %+v, want generation 1, the sha256 and restart_required [guardrail.host]", in.After)
	}
}

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
	if _, _, ok := configChangeActivity(path, before, before, []string{"guardrail"}, 0, true); ok {
		t.Fatal("bytes no writer recorded produced a writer event")
	}
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "cli:alice", Reason: "defenseclaw config set",
	}, func() (bool, error) { return true, os.WriteFile(path, after, 0o600) }); err != nil {
		t.Fatalf("record the write: %v", err)
	}
	in, _, ok := configChangeActivity(path, before, after, []string{"guardrail"}, 0, true)
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

	// Two writers inside one reload (debounce, or while reloads are
	// rejected): the event names neither of them for both paths (GAP-0318).
	bob := []byte("config_version: 9\nguardrail:\n  mode: observe\n  host: 0.0.0.0\n")
	carol := []byte("config_version: 9\nguardrail:\n  mode: observe\n  host: 0.0.0.0\n  block_at: HIGH\n")
	for _, w := range []struct {
		actor string
		raw   []byte
	}{{"cli:bob", bob}, {"cli:carol", carol}} {
		if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{Actor: w.actor, Reason: "set"},
			func() (bool, error) { return true, os.WriteFile(path, w.raw, 0o600) }); err != nil {
			t.Fatalf("record the write of %s: %v", w.actor, err)
		}
	}
	in, generation, ok := configChangeActivity(path, after, carol, []string{"guardrail"}, 1, true)
	if !ok || generation != 3 || in.Actor != "unattributed" || in.After["last_actor"] != "cli:carol" ||
		in.After["first_generation"] != uint64(2) || in.After["config_generation"] != uint64(3) {
		t.Fatalf("coalesced event = actor %q after %+v (ok %v), want unattributed for generations 2-3, last cli:carol", in.Actor, in.After, ok)
	}
	if in, _, _ := configChangeActivity(path, bob, carol, []string{"guardrail"}, 2, true); in.Actor != "cli:carol" {
		t.Fatalf("a single generation names %q, want its writer cli:carol", in.Actor)
	}
	// A signed bundle finishing a coalesced burst names the enforcing
	// bundle, without assigning the earlier writer's path diff to it.
	bundleRaw := []byte("config_version: 9\nguardrail:\n  mode: action\n  host: 0.0.0.0\n  block_at: HIGH\n")
	const bundleID = "b-01JA0000000000000000000033"
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "operator:tip", LocalActor: "os:uid:0:root", Reason: configwrite.BundleReason(bundleID, 4, "enable action"), Lifecycle: true,
		Bundle: configwrite.BundleRef{ID: bundleID, Version: 4, SignerKeyID: "k1"},
	}, func() (bool, error) { return true, os.WriteFile(path, bundleRaw, 0o600) }); err != nil {
		t.Fatal(err)
	}
	in, _, ok = configChangeActivity(path, after, bundleRaw, []string{"guardrail"}, 1, true)
	if !ok || in.Actor != "os:uid:0:root" || in.Principal != "operator:tip" || in.Bundle == nil || in.Bundle.ID != bundleID ||
		in.Bundle.SignerKeyID != "k1" || in.Bundle.ChangeSummary != "enable action" || len(in.Diff) != 0 || in.After["coalesced"] != true {
		t.Fatalf("coalesced bundle activity = %+v (ok=%v)", in, ok)
	}
}

// An asset-only generation rebuild reuses config.yaml bytes and must not
// attribute another config change to the last writer.
func TestConfigChangeActivitySkipsUnchangedConfigBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\nguardrail:\n  mode: observe\n")
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "cli:alice", Reason: "defenseclaw config set",
	}, func() (bool, error) { return true, os.WriteFile(path, raw, 0o600) }); err != nil {
		t.Fatal(err)
	}
	if activity, _, ok := configChangeActivity(path, raw, raw, []string{configDiffAssets}, 1, true); ok {
		t.Fatalf("asset rebuild produced config change by %q", activity.Actor)
	}
	const bundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T7"
	if _, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "operator:root", Lifecycle: true,
		Reason: configwrite.BundleReason(bundleID, 2, "new custom pack"),
		Bundle: configwrite.BundleRef{ID: bundleID, Version: 2},
	}, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if activity, generation, ok := configChangeActivity(path, raw, raw, []string{configDiffAssets}, 1, true); !ok ||
		generation != 2 || activity.Bundle == nil || activity.Bundle.ID != bundleID ||
		len(activity.Diff) != 1 || activity.Diff[0].Path != configDiffAssets {
		t.Fatalf("new bundle with unchanged YAML had no asset change event: %+v, generation %d, ok %t", activity, generation, ok)
	}
	if activity, _, ok := configChangeActivity(path, raw, raw, []string{configDiffAssets}, 2, true); ok {
		t.Fatalf("repeat asset rebuild produced config change by %q", activity.Actor)
	}
}

func TestConfigChangeActivityAttributesRollbackToAttemptedBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	staged := []byte("config_version: 9\nguardrail:\n  mode: action\n")
	restored := []byte("config_version: 9\nguardrail:\n  mode: observe\n")
	if err := os.WriteFile(path, restored, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := configwrite.Locked(context.Background(), path, configwrite.Options{
		Actor: "operator:old", LocalActor: "os:uid:0:root", Lifecycle: true,
		Bundle:             configwrite.BundleRef{ID: "b-01JA0000000000000000000001", Version: 1, SignerKeyID: "old"},
		TransactionActor:   "operator:tip",
		TransactionBundle:  configwrite.BundleRef{ID: "b-01JA0000000000000000000002", Version: 2, SignerKeyID: "new"},
		TransactionSummary: "failed apply",
	}, func() (bool, error) { return true, nil })
	if err != nil {
		t.Fatal(err)
	}
	in, _, ok := configChangeActivity(path, staged, restored, []string{"guardrail"}, 0, true)
	if !ok || in.Actor != "os:uid:0:root" || in.Principal != "operator:tip" || in.Bundle == nil ||
		in.Bundle.ID != "b-01JA0000000000000000000002" || in.Bundle.ChangeSummary != "failed apply" {
		t.Fatalf("rollback audit attribution = %+v, %t", in, ok)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A bundle-mode config.yaml edited and then restored byte for byte by hand
// leaves config.generation.json calling the bundle bytes a hand edit: status
// and verify fail, and Setup /repair and the CLI repair each named the other
// while neither recovered, because the restore saw the right bytes and wrote
// nothing. The restore now records the bundle generation over the hand-edit
// record, with the bytes untouched; a bundle config the lifecycle recorded
// stays a no-op.
func TestBundleRestoreRecordsTheBundleOverAHandEditOfTheSameBytes(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	bundleConfig := []byte("config_version: 8\ndata_dir: " + dir + "\nenterprise:\n  profile: standalone\nobservability: {}\n")
	edited := append(append([]byte(nil), bundleConfig...), []byte("# appended by hand\n")...)
	bundle := configwrite.BundleRef{ID: "b-01J9ZZZZZZZZZZZZZZZZZZZZZZ", Version: 1, SignerKeyID: "k1"}
	opt := configwrite.Options{Actor: "control-plane:t1/alice", Reason: "apply the bundle", Lifecycle: true, Bundle: bundle}
	current := bundleEnforcement{
		Current:       &enterprisebundle.Ref{BundleID: bundle.ID, Version: bundle.Version},
		CurrentConfig: bundleConfig, InstalledConfig: bundleConfig,
	}

	if err := os.WriteFile(path, bundleConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(ctx, path, bundleConfig, opt); err != nil {
		t.Fatalf("apply the bundle: %v", err)
	}
	// Benign twin: a bundle config the lifecycle recorded needs no write.
	if plan, err := current.planRestore(bundleConfig, nil, bundleHandEditRecorded(path)); err != nil || plan != (bundleConfigRestore{}) {
		t.Fatalf("a recorded bundle config: plan=%+v err=%v", plan, err)
	}

	// The edit, then the byte-exact restore, each recorded by the guardian.
	guardian := configwrite.Options{Actor: configwrite.ActorUnattributedHandEdit, Reason: "edited outside the lifecycle", Timeout: 5 * time.Second}
	for _, body := range [][]byte{edited, bundleConfig} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := configwrite.RecordUnrecorded(ctx, path, body, guardian); err != nil {
			t.Fatal(err)
		}
	}
	if !bundleHandEditRecorded(path) {
		t.Fatal("setup: the generation record does not call the restored bytes a hand edit")
	}
	if _, err := readManagedConfigBoundToGeneration(path); err == nil {
		t.Fatal("a hand-edit record bound the restored bytes")
	}

	plan, err := current.planRestore(bundleConfig, nil, bundleHandEditRecorded(path))
	if err != nil || !plan.Write || !plan.Rerecord || plan.Missing {
		t.Fatalf("restore plan %+v, %v: want a record-only write", plan, err)
	}
	opt.ExpectSHA256 = plan.ExpectSHA256
	if _, err := configwrite.ReplaceDocument(ctx, path, current.CurrentConfig, opt); err != nil {
		t.Fatalf("record the bundle generation: %v", err)
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || configwrite.IsHandEditActor(state.Actor) || state.BundleID != bundle.ID || state.ConfigSHA256 != configwrite.SHA256Hex(bundleConfig) {
		t.Fatalf("generation after the restore: %+v, %v", state, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, bundleConfig) {
		t.Fatalf("the restore changed the bytes: %q", after)
	}
	if bundleHandEditRecorded(path) {
		t.Fatal("the hand-edit record is still there")
	}
	if plan, err := current.planRestore(bundleConfig, nil, bundleHandEditRecorded(path)); err != nil || plan != (bundleConfigRestore{}) {
		t.Fatalf("a second restore is not a no-op: plan=%+v err=%v", plan, err)
	}
}

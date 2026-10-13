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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// TestConfigWriterRefusesAnUnloadableRuleReference: a rule ID the generation
// build would refuse is refused by the writer, so it never reaches
// config.yaml and blocks the reloads after it.
func TestConfigWriterRefusesAnUnloadableRuleReference(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	// The installed layout: <data_dir>/policies holds the built-in packs.
	if err := os.Symlink(policies, filepath.Join(dir, "policies")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("config_version: 9\ndata_dir: "+dir+"\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := configwrite.Options{Actor: "cli:test"}
	ctx := context.Background()
	before, _ := os.ReadFile(path)
	if _, err := configwrite.Apply(ctx, path, []configwrite.Change{{Path: "guardrail.rules.disable", Value: []any{"SEC-NO-SUCH-RULE"}}}, opt); err == nil {
		t.Fatal("an unknown rule ID was written")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a refused change modified config.yaml")
	}
	// A webhook the dispatcher would drop is refused the same way, naming it
	// but not its URL (GAP-0094).
	for _, url := range []string{"not a url", "http://127.0.0.1:19999/hook?token=s3cret"} {
		hook := []any{map[string]any{"name": "p0bad", "url": url, "type": "generic", "enabled": true}}
		_, err := configwrite.Apply(ctx, path, []configwrite.Change{{Path: "webhooks", Value: hook}}, opt)
		if err == nil || !strings.Contains(err.Error(), `webhook "p0bad"`) || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("webhook url %q: err = %v, want a refusal naming the webhook and not the URL", url, err)
		}
	}
	if _, err := configwrite.Apply(ctx, path, []configwrite.Change{{Path: "guardrail.mode", Value: "action"}}, opt); err != nil {
		t.Fatalf("a valid change was refused: %v", err)
	}
}

// GAP-0363: a profile rule_pack_dir the gateway's reload refuses (written
// with ~, or naming a folder that does not exist) is refused by the
// validator too; a built-in pack folder that is not seeded yet is not.
func TestCandidateAssetsRefuseAProfileRulePackDirTheGatewayCannotOpen(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := func(packDir string) []byte {
		return []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  enabled: true\n  profiles:\n" +
			"    strict: {mode: action, block_at: medium, rule_pack_dir: '" + packDir + "'}\n" +
			"    watch: {mode: observe}\n  default_profile: watch\nobservability: {}\n")
	}
	for packDir, want := range map[string]string{
		"~/.defenseclaw/policies/guardrail/marker": "is not an absolute path",
		filepath.Join(dir, "no-such-pack"):         "directory_not_found",
	} {
		if err := config.ValidateCandidateAssets(path, raw(packDir)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("rule_pack_dir %q: err = %v, want %q", packDir, err, want)
		}
	}
	seeded := filepath.Join(dir, "policies", "guardrail", "default")
	if err := config.ValidateCandidateAssets(path, raw(seeded)); err != nil {
		t.Fatalf("an unseeded built-in pack folder was refused: %v", err)
	}
}

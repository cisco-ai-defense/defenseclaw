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
	"testing"

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
	if _, err := configwrite.Apply(ctx, path, []configwrite.Change{{Path: "guardrail.mode", Value: "action"}}, opt); err != nil {
		t.Fatalf("a valid change was refused: %v", err)
	}
}

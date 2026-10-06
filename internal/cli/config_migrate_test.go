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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// The Windows standalone config step migrates a v8 config in place with the
// lifecycle actor, then only records an unrecorded config.
func TestMigrateManagedStandaloneConfig(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v8 := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, v8, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if config.NeedsMigrationV9(raw) {
		t.Fatal("config.yaml is still config_version 8")
	}
	if backup, _ := os.ReadFile(path + config.ConfigV8BackupSuffix); string(backup) != string(v8) {
		t.Fatal("config.yaml.v8.bak does not hold the v8 bytes")
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Actor != configwrite.ActorLifecycle || state.ConfigSHA256 != configwrite.SHA256Hex(raw) {
		t.Fatalf("generation = %+v (%v)", state, err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again, _ := configwrite.ReadGenerationState(path); again.Generation != state.Generation {
		t.Fatalf("an unchanged config advanced the generation to %d", again.Generation)
	}
}

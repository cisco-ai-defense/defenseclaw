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

package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestPluginEnforcerQuarantineAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	quarantineDir := filepath.Join(tmpDir, "quarantine")
	pluginDir := filepath.Join(tmpDir, "test-plugin")

	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.py"), []byte("# plugin code"), 0o644); err != nil {
		t.Fatal(err)
	}

	pe := enforce.NewPluginEnforcer(quarantineDir)

	dest, err := pe.Quarantine(pluginDir)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Fatal("expected original plugin directory to be removed after quarantine")
	}

	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected quarantine destination to exist: %v", err)
	}

	if !pe.IsQuarantined("test-plugin") {
		t.Fatal("expected IsQuarantined to return true")
	}

	if err := pe.Restore("test-plugin", pluginDir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restoredFile := filepath.Join(pluginDir, "plugin.py")
	data, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
	if string(data) != "# plugin code" {
		t.Fatalf("restored content mismatch: %q", string(data))
	}

	if pe.IsQuarantined("test-plugin") {
		t.Fatal("expected IsQuarantined to return false after restore")
	}
}

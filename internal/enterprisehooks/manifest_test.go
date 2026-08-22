// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifestFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func TestLoadManifestRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets:\n  - user: alice\n    connector: codex\n    enabld: false\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "field enabld not found") {
		t.Fatalf("LoadManifest error = %v, want unknown-field rejection", err)
	}
}

func TestLoadManifestRejectsTrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets: []\n---\nversion: 1\ntargets: []\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("LoadManifest error = %v, want trailing-document rejection", err)
	}
}

func TestLoadManifestAcceptsEmptyDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte("# no managed targets yet\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if manifest.Version != 1 || len(manifest.Targets) != 0 {
		t.Fatalf("manifest = %+v, want version 1 with no targets", manifest)
	}
}

func TestLoadManifestAcceptsSIDOnlyTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	data := []byte("version: 1\ntargets:\n  - sid: S-1-5-21-111-222-333-1001\n    connector: claudecode\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != "S-1-5-21-111-222-333-1001" {
		t.Fatalf("targets = %+v, want SID-only target", manifest.Targets)
	}
}

func TestLoadManifestAcceptsExactAgentExecutable(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "codex")
	path := writeManifestFixture(t, fmt.Sprintf(
		`{"version":1,"targets":[{"user":"alice","connector":"codex","agent_version":"codex-cli 0.146.0","agent_executable":%q}]}`,
		executable,
	))
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if got := manifest.Targets[0].AgentExecutable; got != executable {
		t.Fatalf("agent_executable = %q, want %q", got, executable)
	}
}

func TestLoadManifestRejectsInvalidAgentExecutable(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "codex")
	unclean := absolute + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(absolute)
	for _, test := range []struct {
		name       string
		executable string
		version    string
	}{
		{name: "relative", executable: "bin/codex", version: "codex-cli 0.146.0"},
		{name: "unclean", executable: unclean, version: "codex-cli 0.146.0"},
		{name: "surrounding whitespace", executable: " " + absolute, version: "codex-cli 0.146.0"},
		{name: "line break", executable: absolute + "\nother", version: "codex-cli 0.146.0"},
		{name: "missing version", executable: absolute},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeManifestFixture(t, fmt.Sprintf(
				`{"version":1,"targets":[{"user":"alice","connector":"codex","agent_version":%q,"agent_executable":%q}]}`,
				test.version,
				test.executable,
			))
			_, err := LoadManifest(path)
			if err == nil || (!strings.Contains(err.Error(), "invalid agent_executable") &&
				!strings.Contains(err.Error(), "requires agent_version")) {
				t.Fatalf("LoadManifest error = %v, want strict agent_executable refusal", err)
			}
		})
	}
}

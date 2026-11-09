// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// dockerDotDotEvidence is the hook client evidence of body with the client's
// answer for operand (placed in project) set to physical.
func dockerDotDotEvidence(t *testing.T, body, project, operand, physical string) string {
	t.Helper()
	targets, ok := hookpaths.Decode(hookpaths.Resolve([]byte(body)))
	if !ok {
		t.Fatal("hook evidence is not readable")
	}
	targets[hookpaths.OperandPath(operand, project)] = physical
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// A relative name that steps up a directory after a link reaches the physical
// file the hook client answered with. Its lexical clean is a different path
// that happens to be the Docker configuration: balanced must judge the file the
// link reaches, so an ordinary file is never judged as daemon.json, and a
// protected file reached the same way stays blocked.
func TestDockerProofJudgesTheFileADotDotNameReachesNotItsLexicalClean(t *testing.T) {
	home, project := hermesPatchHome(t)
	up, err := filepath.Rel(project, "/etc/docker/daemon.json")
	if err != nil {
		t.Fatal(err)
	}
	target := "link/../" + filepath.ToSlash(up)
	deep := filepath.Join(project, "deep", "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deep, filepath.Join(project, "link")); err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Clean(filepath.Join(deep, "..", up))
	if err := os.MkdirAll(filepath.Dir(ordinary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinary, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if lexical := filepath.Clean(project + "/" + target); lexical != "/etc/docker/daemon.json" {
		t.Fatalf("lexical target = %q", lexical)
	}
	if reached, err := filepath.EvalSymlinks(project + "/" + target); err != nil || reached != ordinary {
		t.Fatalf("physical target = %q, err = %v, want %q", reached, err, ordinary)
	}
	const insecure = "{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n"
	const plain = "{\"log-level\":\"warn\"}\n"
	for _, row := range []struct {
		name, content, physical string
		block                   bool
	}{
		{"insecure document to an ordinary file", insecure, ordinary, false},
		{"ordinary document to an ordinary file", plain, ordinary, false},
		{"insecure document to the Docker configuration", insecure, "/etc/docker/daemon.json", true},
		{"ordinary document to the Docker configuration", plain, "/etc/docker/daemon.json", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := string(mustJSON(t, sudoersClaudeCall("Write", sudoersFixed(map[string]any{
				"file_path": target, "content": row.content,
			}))(project)))
			got := overLimitHostHookWithEvidence(t, "claudecode", home, body,
				dockerDotDotEvidence(t, body, project, target, row.physical))
			if blocked := strings.Contains(got, dockerInsecureHTTPRegistryRuleID) || overLimitHookAction(t, got) == "block"; blocked != row.block {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, row.block, got)
			}
		})
	}
}

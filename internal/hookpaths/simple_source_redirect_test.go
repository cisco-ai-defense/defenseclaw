// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSimpleSourceRedirectEvidence(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, source, want string
		valid              bool
	}{
		{"ordinary", "f=out.txt\n", filepath.Join(project, "out.txt"), true},
		{"protected", "f=keylink\n", keys, true},
		{"other effect", "f=out.txt; echo m >> keylink\n", "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(project, "setf.sh"), []byte(row.source), 0o600); err != nil {
				t.Fatal(err)
			}
			command := `f=a.txt; . ./setf.sh; echo m >> "$f"`
			if got, ok := SimpleSourceRedirectTarget(command, project, home); ok != row.valid || got != row.want {
				t.Fatalf("target = %q, valid=%v, want %q, valid=%v", got, ok, row.want, row.valid)
			}
		})
	}
}

func TestSourceRedirectFactDecodeRequiresAbsoluteTargetAndDigest(t *testing.T) {
	key := SimpleSourceRedirectFactKey(`f=a.txt; . ./setf.sh; echo m >> "$f"`)
	for _, row := range []struct {
		key, value string
		valid      bool
	}{
		{key, "/tmp/out.txt", true},
		{key, "out.txt", false},
		{key, "/tmp/out\n.txt", false},
		{SourceRedirectFactPrefix + "xyz", "/tmp/out.txt", false},
	} {
		encoded, err := json.Marshal(map[string]string{row.key: row.value})
		if err != nil {
			t.Fatal(err)
		}
		_, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded))
		if ok != row.valid {
			t.Errorf("fact %q = valid %v, want %v", row.key, ok, row.valid)
		}
	}
}

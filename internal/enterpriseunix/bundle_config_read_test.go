// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// The promoted assets and installed config must be readable by the Unix
// gateway identity, including after root creates and replaces config.yaml.
func TestRootPromotedBundleAndInstalledConfigReadableByGateway(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to switch to the gateway identity")
	}
	const serviceID = 65534
	base := t.TempDir()
	if err := os.Chmod(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	s := enterprisebundle.NewStore(filepath.Join(base, "etc", "bundles"), filepath.Join(base, "lifecycle"))
	s.SealVersion = func(root string) error { return enterprisebundle.SealVersionForGroup(root, serviceID, os.Lchown) }
	r, err := s.Receive("b-01JA0000000000000000000001", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Stage(r, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Advance(r, enterprisebundle.StateVerified, nil); err != nil {
		t.Fatal(err)
	}
	version, err := s.Promote(r)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Lchown: os.Lchown}
	config := filepath.Join(base, "etc", "config.yaml")
	if err := env.writeFileAtomic(config, []byte("config_version: 9\n"), 0o640, fileOwner{UID: 0, GID: serviceID}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config, filepath.Join(version, "config.yaml")} {
		cmd := exec.Command("/bin/cat", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: serviceID, Gid: serviceID}}
		if out, err := cmd.Output(); err != nil || string(out) != "config_version: 9\n" {
			t.Fatalf("gateway cannot read %s: %q, %v", path, out, err)
		}
	}
}

func TestConfigModeIsFinalizedAfterOwnershipChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	env := &Env{Lchown: func(name string, _, _ int) error {
		// Model a platform ownership change that clears the group-read bit.
		return os.Chmod(name, 0o600)
	}}
	owner := fileOwner{UID: 0, GID: 1234}
	if err := env.writeFileAtomic(path, []byte("config_version: 9\n"), 0o640, owner); err != nil {
		t.Fatal(err)
	}
	if mode, err := os.Stat(path); err != nil || mode.Mode().Perm() != 0o640 {
		t.Fatalf("published config mode = %v, %v", mode, err)
	}
	if err := env.fixMetadata(path, 0o640, owner); err != nil {
		t.Fatal(err)
	}
	if mode, err := os.Stat(path); err != nil || mode.Mode().Perm() != 0o640 {
		t.Fatalf("restored config mode = %v, %v", mode, err)
	}
}

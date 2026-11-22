// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// On a POSIX host scp and rsync to host:///abs/path name the local /abs/path
// when the host is this machine: the key file stays a protected target, as at
// rel 8e58b26846 (rel-1-0-10:GAP-1665). A drive-letter spelling is no URL
// either (rel-1-0-10:GAP-1661).
func TestGAP1665HostTripleSlashKeyStaysProtected(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, f := range []string{".ssh/authorized_keys", "proj/x.json"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, f)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, f), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key := home + "/.ssh/authorized_keys"
	for _, command := range []string{
		"scp x.json localhost://" + key,
		"rsync x.json localhost://" + key,
		"scp x.json u@localhost://" + key,
		"rsync -a x.json localhost://" + key,
		"cp x.json C://" + key,
		// The controls (protected at rel, the parent and the GAP-0926 fix).
		"scp x.json localhost:" + key,
		"scp x.json localhost:/" + key,
		"cp x.json /" + key,
		"cp x.json " + key,
	} {
		if got := ActionCommandDecisionInShell(command, cwd, home, nil, true); got != "protected-target" {
			t.Errorf("%q: %q, want protected-target", command, got)
		}
	}
}

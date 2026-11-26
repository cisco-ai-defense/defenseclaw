// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0795 H1, H2: the environment of the relay's own git runs is an
// allow-list. PATH keeps only folders only root can write (a folder anyone
// can write, a sticky one and a relative name go), and no HOME, XDG_* or
// GIT_* of the relay's environment is passed on.
func TestGAP0795RelayEnvIsAnAllowList(t *testing.T) {
	if _, ok := rootOnlyDir("/usr/bin"); !ok {
		t.Skip("/usr/bin is not root-only here")
	}
	open := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{open, "/tmp", "bin", "/usr/bin", "/bin"}, ":"))
	t.Setenv("HOME", open)
	t.Setenv("XDG_CONFIG_HOME", open)
	t.Setenv("GIT_ATTR_SOURCE", "HEAD")
	env, err := gitRelayEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case k == "PATH":
			path = v
		case k == "HOME" || strings.HasPrefix(k, "XDG_") || strings.HasPrefix(k, "GIT_") && k != "GIT_TERMINAL_PROMPT":
			t.Errorf("the relay passes %s on to its root runs", k)
		}
	}
	for _, d := range filepath.SplitList(path) {
		if d == open || d == "/tmp" || !filepath.IsAbs(d) {
			t.Errorf("PATH %q names %q, a folder root does not own alone", path, d)
		}
		if _, ok := rootOnlyDir(d); !ok {
			t.Errorf("PATH %q names %q, not root-only", path, d)
		}
	}
	if path == "" {
		t.Fatalf("no PATH in %v", env)
	}
}

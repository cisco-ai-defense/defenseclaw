// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// applyPackageTmpfiles applies the package's tmpfiles.d document inside the
// fake host's root the way systemd-tmpfiles --create does for its "d"
// lines, with --boot (boot) also for its boot-only "d!" lines: a missing
// folder is created and an existing one gets the line's mode back. Owners
// are not modeled.
func applyPackageTmpfiles(t *testing.T, env *Env, boot bool) {
	t.Helper()
	document, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(document), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[0] != "d" && fields[0] != "d!" || len(fields) < 3 {
			t.Fatalf("the test models only d and d! lines: %q", line)
		}
		if fields[0] == "d!" && !boot {
			continue
		}
		mode, err := strconv.ParseUint(fields[2], 8, 32)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		path := env.P(fields[1])
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
	}
}

// Kill switch (GAP-0352): tmpfiles creates the hook socket folder and the
// record folder at boot with their modes, and no key: only root makes one,
// with a random name, so after a boot outage allows block until the hook
// guardian's first pass makes it. A tmpfiles run on a live host (a package
// transaction) leaves the key alone.
func TestPackageTmpfilesCreateTheHookFoldersAndNoKey(t *testing.T) {
	withHookSessionTestKeys(t)
	h := newTestHost(t, "linux")
	applyPackageTmpfiles(t, h.env, true)
	for path, mode := range map[string]os.FileMode{h.env.Layout.HookSocketDir: 0o755, h.env.Layout.HookSessionDir: 0o711} {
		if info, err := os.Lstat(h.env.P(path)); err != nil || !info.IsDir() || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v", path, info, err)
		}
	}
	root := h.env.P(h.env.Layout.HookSessionDir)
	if hookSessionTestKeyID(root) != "" {
		t.Fatal("a boot must leave no key")
	}
	document, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(document), "\n") {
		if !strings.HasPrefix(line, "#") && strings.Contains(line, enterprisepolicy.PublishedSessionKeyInfix) {
			t.Fatalf("tmpfiles must not make a key: %q", line)
		}
	}
	if err := enterprisepolicy.EnsurePublishedSessionKey(root, hookSessionTestAccount, enterprisepolicy.PublishedSessionTrust{}); err != nil {
		t.Fatal(err)
	}
	key := hookSessionTestKeyID(root)
	applyPackageTmpfiles(t, h.env, false)
	if hookSessionTestKeyID(root) != key {
		t.Fatal("a tmpfiles run must leave the key alone")
	}
}

// Review P1 (1.0.4 guard loop round 1): a package transaction runs the
// tmpfiles document on a live host before the lifecycle's ensure removes
// the keys. It must not put back the trust of a folder the hook refuses
// (here the record folder and the hook socket folder, loosened to 0777, as
// a drift the hook blocks on) while the folder still holds an earlier key:
// every folder of the record tree is boot-only, so only the lifecycle,
// after it removed every key, gives a live folder its mode back.
func TestPackageTmpfilesOnALiveHostLeaveTheRecordTreeToTheLifecycle(t *testing.T) {
	withHookSessionTestKeys(t)
	h := newTestHost(t, "linux")
	applyPackageTmpfiles(t, h.env, true)
	root := h.env.P(h.env.Layout.HookSessionDir)
	if err := enterprisepolicy.EnsurePublishedSessionKey(root, hookSessionTestAccount, enterprisepolicy.PublishedSessionTrust{}); err != nil {
		t.Fatal(err)
	}
	keyDir, _ := enterprisepolicy.PublishedSessionKeyDir(root)
	trustTree := map[string]bool{}
	for dir := root; ; dir = filepath.Dir(dir) {
		trustTree[filepath.Clean(dir)] = true
		if dir == h.env.P("/run") || dir == filepath.Dir(dir) {
			break
		}
	}
	trustTree[filepath.Clean(keyDir)] = true
	document, err := systemdunits.ReadFile(systemdunits.TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(document), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if trustTree[filepath.Clean(h.env.P(fields[1]))] && !strings.Contains(fields[0], "!") {
			t.Fatalf("a folder of the record tree must be boot-only in tmpfiles: %q", line)
		}
	}
	for _, dir := range []string{root, keyDir} {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	applyPackageTmpfiles(t, h.env, false)
	for _, dir := range []string{root, keyDir} {
		if info, err := os.Lstat(dir); err != nil || info.Mode().Perm() != 0o777 {
			t.Fatalf("a live tmpfiles run must leave %s as the hook found it: %v %v", dir, info, err)
		}
	}
}

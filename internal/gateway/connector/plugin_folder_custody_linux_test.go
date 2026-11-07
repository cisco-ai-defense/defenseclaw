// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// GAP-0730: the gateway's refusal of an OpenCode plugin folder names the
// first folder to fix (the outermost one other accounts can write, the one the
// CLI names) and the one command, not the deepest folder. Fixing the leaf
// alone left the same refusal behind.
func TestGAP0730PluginFolderRefusalNamesTheOutermostFolderAndItsFix(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, ".config")
	leaf := filepath.Join(config, "opencode")
	plugins := filepath.Join(leaf, "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(plugins, "defenseclaw.js")
	dropInheritedACLs(t, root)

	// Benign twin: private folders pass.
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("private folders refused: %v", err)
	}

	for _, dir := range []string{config, leaf} {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	err := validatePluginArtifactDestination(plugin)
	if err == nil || !errors.Is(err, ErrAgentFolderCustody) {
		t.Fatalf("writable folders: err=%v, want ErrAgentFolderCustody", err)
	}
	if want := "fix: chmod go-w " + posixShellWord(config); !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("refusal %q does not end with %q (the outermost folder)", err, want)
	}
	if strings.Contains(err.Error(), "chmod go-w "+posixShellWord(leaf)) {
		t.Fatalf("refusal names the leaf folder as the fix: %v", err)
	}

	// After the outer fix the next one is named, and after both it passes.
	if err := os.Chmod(config, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(plugin); err == nil ||
		!strings.HasSuffix(err.Error(), "fix: chmod go-w "+posixShellWord(leaf)) {
		t.Fatalf("second refusal: %v", err)
	}
	if err := os.Chmod(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(plugin); err != nil {
		t.Fatalf("fixed folders refused: %v", err)
	}

	// The installed plugin file names its own fix.
	if err := os.WriteFile(plugin, []byte("// managed plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plugin, 0o602); err != nil {
		t.Fatal(err)
	}
	if err := validatePluginArtifactDestination(plugin); err == nil || !errors.Is(err, ErrAgentFolderCustody) ||
		!strings.HasSuffix(err.Error(), "fix: chmod go-w "+posixShellWord(plugin)) {
		t.Fatalf("writable plugin file: %v", err)
	}
}

// An access ACL entry on a folder needs setfacl, not chmod.
func TestGAP0730PluginFolderACLRefusalNamesSetfacl(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, ".config", "opencode")
	plugins := filepath.Join(leaf, "plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	dropInheritedACLs(t, root)
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl[:4], 2)
	for i, entry := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 7, ^uint32(0)}, {2, 2, 65534}, {4, 0, ^uint32(0)}, {16, 7, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:], entry.tag)
		binary.LittleEndian.PutUint16(acl[offset+2:], entry.perm)
		binary.LittleEndian.PutUint32(acl[offset+4:], entry.id)
	}
	if err := unix.Setxattr(leaf, "system.posix_acl_access", acl, 0); err != nil {
		t.Skipf("no POSIX ACL support here: %v", err)
	}
	err := validatePluginArtifactDestination(filepath.Join(plugins, "defenseclaw.js"))
	if err == nil || !errors.Is(err, ErrAgentFolderCustody) ||
		!strings.HasSuffix(err.Error(), "fix: setfacl -b "+posixShellWord(leaf)) {
		t.Fatalf("ACL on the folder: %v", err)
	}
}

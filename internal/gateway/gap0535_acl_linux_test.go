// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/unix"
)

func TestGAP0535ACLUnprovenDirectoryChecksBothTrees(t *testing.T) {
	root, err := os.MkdirTemp("/var/tmp", "gap0535-acl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, ".claude")
	other := filepath.Join(root, "other")
	for _, dir := range []string{filepath.Join(cwd, "skills", "folder"), filepath.Join(other, "skills", "folder")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A named user ACL denies search despite the other-user execute bit.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl[:4], 2)
	entries := [][3]uint32{{1, 7, ^uint32(0)}, {2, 0, 1001}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 5, ^uint32(0)}}
	for i, entry := range entries {
		offset := 4 + i*8
		binary.LittleEndian.PutUint16(acl[offset:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(acl[offset+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(acl[offset+4:], entry[2])
	}
	if err := unix.Setxattr(other, "system.posix_acl_access", acl, 0); err != nil {
		t.Skipf("POSIX ACL unavailable: %v", err)
	}
	info, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Skip("filesystem changed mode bits with ACL")
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, GID: 1001, Name: "fixture", Home: home})
	for _, deniedOriginal := range []bool{true, false} {
		originalName := "ordinary-name"
		if deniedOriginal {
			originalName = "listed-name"
		}
		for dir, name := range map[string]string{cwd: originalName, other: "ordinary-name"} {
			path := filepath.Join(dir, "skills", "folder", "SKILL.md")
			if err := os.WriteFile(path, []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
			ToolInput: map[string]interface{}{"command": "cd " + other + "; cat skills/folder/SKILL.md"},
		})
		if matched != deniedOriginal || matched && (decision.Action != "block" || decision.Source != "admin-deny") {
			t.Errorf("denied original=%t: decision=%+v matched=%t", deniedOriginal, decision, matched)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type settingsLinkOwnerInfo struct {
	os.FileInfo
	uid uint32
}

func (info settingsLinkOwnerInfo) Sys() any {
	return &syscall.Stat_t{Uid: info.uid}
}

func TestSettingsLinkAcceptsAdministratorButNotForeignAccount(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "settings.json")
	link := filepath.Join(root, "settings-link.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		uid         uint32
		wantRefusal bool
	}{
		{name: "gateway account", uid: uint32(pluginGetUID())},
		{name: "administrator", uid: 0},
		{name: "foreign unprivileged account", uid: uint32(pluginGetUID() + 1), wantRefusal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSettingsLinkOwnerFromInfo(link, settingsLinkOwnerInfo{FileInfo: info, uid: tc.uid})
			if tc.wantRefusal {
				if err == nil || !strings.Contains(err.Error(), "owner uid") {
					t.Fatalf("foreign settings link owner accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("safe settings link owner refused: %v", err)
			}
		})
	}
	if got, err := userOwnedSettingsReadPath(link); err != nil || got != target {
		t.Fatalf("user-owned target behind a settings link = %q, %v; want %q", got, err, target)
	}
}

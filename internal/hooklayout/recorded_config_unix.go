// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Package hooklayout resolves the per-user hook runtime's recorded layout.
package hooklayout

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const configRecordName = ".config-record"

// RecordedConfig is the account-owned config path the gateway recorded beside
// hooks. It is a layout hint; callers still validate the config or PID record
// for the decision they make with it.
func RecordedConfig(dataDir string) string {
	if !filepath.IsAbs(dataDir) {
		return ""
	}
	uid := os.Getuid()
	hookDir := filepath.Join(filepath.Clean(dataDir), "hooks")
	for _, dir := range []string{dataDir, hookDir} {
		if !privateOwnedDir(dir, uid) {
			return ""
		}
	}
	record := filepath.Join(hookDir, configRecordName)
	info, err := os.Lstat(record)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || !ownedByUID(info, uid) || info.Size() > 4096 {
		return ""
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(string(raw), "\n")
	if path == "" || strings.ContainsAny(path, "\n\r\x00") || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ""
	}
	if !privateOwnedDir(filepath.Dir(path), uid) {
		return ""
	}
	// The recorded config may be a link managed by the account; the file it
	// names still belongs to this account.
	if target, err := os.Stat(path); err != nil || !target.Mode().IsRegular() || !ownedByUID(target, uid) {
		return ""
	}
	return path
}

func ownedByUID(info os.FileInfo, uid int) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && uid >= 0 && int(st.Uid) == uid
}

func privateOwnedDir(dir string, uid int) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir() && info.Mode().Perm()&0o022 == 0 && ownedByUID(info, uid)
}

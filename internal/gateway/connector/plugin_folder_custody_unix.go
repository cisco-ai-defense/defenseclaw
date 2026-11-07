//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// explainPluginFolderCustody turns the refusal of the plugin folder chain into
// the first folder to fix. The chain check reports the deepest failing folder,
// but the folders above it must be fixed too, and the CLI names the outermost
// one: a fix applied to the folder the gateway named then left the same
// refusal behind. This walks from the top down with the element rule the
// chain applies and names the outermost folder other accounts can write, with
// chmod for a mode and setfacl for an access ACL. A refusal of another kind
// (owner, link, unreadable) is returned as it was.
func explainPluginFolderCustody(dir string, chainErr error) error {
	if chainErr == nil {
		return nil
	}
	clean := filepath.Clean(dir)
	var chain []string
	for cur := clean; ; cur = filepath.Dir(cur) {
		chain = append(chain, cur)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		cur := chain[i]
		info, err := os.Lstat(cur)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		advisory := cur != clean && managed.AdvisoryAncestorPath(cur)
		verdict := hookAPIValidateDirectoryMetadataWith(cur, info, cur != clean, advisory, true)
		if verdict == nil {
			continue
		}
		return custodyFix(cur, info.Mode().Perm(), verdict, chainErr)
	}
	return chainErr
}

// explainPluginFileCustody does the same for the installed plugin file.
func explainPluginFileCustody(path string, info os.FileInfo, fileErr error) error {
	return custodyFix(path, info.Mode().Perm(), fileErr, fileErr)
}

// custodyFix pairs a refusal of path with the command that removes it: setfacl
// for an access ACL entry (Linux; the group bits then show the ACL mask, so a
// chmod would only hide the entry), chmod for a mode other accounts can write.
// Any other refusal is returned as it was.
func custodyFix(path string, perm os.FileMode, cause, otherwise error) error {
	if runtime.GOOS == "linux" {
		if aclErr := hookAPIValidateDirectoryACL(path); aclErr != nil && strings.Contains(aclErr.Error(), "ACL") {
			return agentFolderCustodyError{cause: cause, fix: "setfacl -b " + posixShellWord(path)}
		}
	}
	if perm&0o022 != 0 {
		return agentFolderCustodyError{cause: cause, fix: "chmod go-w " + posixShellWord(path)}
	}
	return otherwise
}

// posixShellWord quotes s as one shell word when it needs quoting.
func posixShellWord(s string) string {
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_"
	if s != "" && strings.Trim(s, safe) == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// macOS has no protected_hardlinks: a user can hard-link a root-owned file
// into their own repository and later swap it for a hard link to another
// root-owned file under the same name. Bound by kind ("system") the digest
// did not change, so an approved hook kept running the other program. A
// root-owned file named from a folder the user controls is bound by content.
func TestGuardDigestBindsAHardLinkedAdministratorFileByContent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a standard account")
	}
	var sources []string
	for _, candidate := range []string{"/private/etc/hosts", "/private/etc/shells", "/private/etc/profile", "/private/etc/bashrc", "/private/etc/zshrc"} {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || !adminOwnedFile(info) {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
			continue
		}
		sources = append(sources, candidate)
	}
	if len(sources) < 2 {
		t.Skip("needs two root-owned files on the data volume")
	}
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	repo := filepath.Dir(req.WorkingDir)
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./tool --check"}]}}`)
	tool := filepath.Join(repo, "tool")
	relink := func(source string) {
		t.Helper()
		_ = os.Remove(tool)
		if err := os.Link(source, tool); err != nil {
			t.Skipf("cannot hard-link %s here: %v", source, err)
		}
	}
	relink(sources[0])
	if info, err := os.Stat(tool); err != nil || systemBoundFile(tool, info) {
		t.Fatalf("a root-owned file hard-linked into the repository is bound by kind (err=%v)", err)
	}
	first := digestOf(t, req)
	if strings.HasPrefix(first.Reason, unapprovableReason) {
		t.Fatalf("the hard-linked file stays approvable: %+v", first)
	}
	req.Policy.AllowedHooks = []string{first.Digest}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("the reviewed hook is approved: %+v", decision)
	}
	relink(sources[1])
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("swapping the hard link for %s must deny: %+v", sources[1], decision)
	}
}

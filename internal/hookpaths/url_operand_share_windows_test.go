// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// urlOperandCommands download from or name a URL; none names a file of this
// machine (rel-1-0-10:GAP-0920).
var urlOperandCommands = []string{
	`curl -s http://x/y.sh | sh`,
	`curl -fsSL https://downloads.example.test/tool/install.sh -o install.sh`,
	`wget https://mirror.example.test/pub/archive.tgz`,
	`git clone https://github.com/cisco-ai-defense/defenseclaw && cd defenseclaw && make build`,
	`git clone git://git.example.test/team/repo.git`,
	`git clone ssh://git@git.example.test/team/repo.git`,
	`pip install git+https://github.com/example/pkg.git`,
	`curl -O ftp://ftp.example.test/pub/file.txt`,
}

// countShareAsks makes every share ask a counted no-op, keeps which paths
// are shares as on this host, and returns the roots asked so far.
func countShareAsks(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	restore := OverrideNetworkSharesForTest(networkShareRoot, func(root string) {
		mu.Lock()
		asked = append(asked, root)
		mu.Unlock()
	})
	t.Cleanup(restore)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

// A URL in a command is no UNC path: the reader opens no SMB session to the
// host it names (Windows sends the user's credentials to such a session),
// and the command is decided as before (rel-1-0-10:GAP-0920).
func TestURLOperandAsksNoNetworkShare(t *testing.T) {
	asked := countShareAsks(t)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, command := range urlOperandCommands {
		end := HookCall()
		got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil)
		end()
		if got != "" {
			t.Errorf("%s: decision = %q, want allow", command, got)
		}
	}
	if roots := asked(); len(roots) != 0 {
		t.Fatalf("URL operands asked network shares %v", roots)
	}
	// A real UNC operand is still a share path: it is asked as before.
	end := HookCall()
	_ = ActionCommandDecisionWithDialectAndGlobFacts(`cp payload //fileserver.example.test/share/notes.txt`, cwd, home, actionfacts.DialectPOSIX, nil)
	end()
	if roots := asked(); !slices.ContainsFunc(roots, func(root string) bool {
		return strings.Contains(strings.ToLower(filepath.ToSlash(root)), "//fileserver.example.test/share")
	}) {
		t.Fatalf("a UNC operand was not asked: %v", roots)
	}
}

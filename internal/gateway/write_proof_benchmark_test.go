// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func BenchmarkExistingAuthorizedKeysWriteProof(b *testing.B) {
	home := b.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		b.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		b.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Command: `printf marker >> alias`, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	facts := actionfacts.Analyze(input)
	request := trustedActionRequest{Input: input}
	b.ResetTimer()
	for b.Loop() {
		trustedExistingAuthorizedKeysSymlinkWrite(request, facts)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP1025FindExecReadsPrivateKey(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	tests := []struct {
		command string
		want    bool
	}{
		{"find ~ -path *ssh* -exec cat {} +", true},
		{"find ~ -path '*ssh*' -exec cat {} +", true},
		{"find ~ -name .ssh -exec cat {} +", true},
		{"find ~/.ssh -exec cat {} +", true},
		{"find ~ -path '*/.ssh/*' -exec cat {} +", true},
		{"find ~ -name 'id_*' -exec cat {} +", true},
		{"find ~ -name '*.txt' -exec cat {} +", false},
		{"find ~ -name *.txt -exec cat {} +", false},
		{"find ~ -path *ssh*", false},
		{"find ~ -name '*ssh*' -exec cat {} \\;", true},
		{"find ~ -name 'auth*' -exec cat {} +", false},
		{"find . -path '*ssh*' -exec cat {} +", false},
		{"find ~ -path '*.txt' -exec cat {} +", false},
		{"find ~ -name '*' -exec cat {} +", true},
		{"find ~ -exec cat {} +", true},
		{`find ~ -path '*ssh*' -ok cat {} \;`, false},
		{`find ~ -path '*ssh*' -okdir cat {} \;`, false},
		{`find ~ -path '*ssh*' -execdir cat {} \;`, true},
		{`find ~ -path '*ssh*' -ok cat {} \; -exec cat {} \;`, true},
	}
	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			cwd := home
			if tc.command == tests[11].command {
				cwd = project
			}
			got := ActionPrivateKeyReadWithDialect(tc.command, cwd, home, actionfacts.DialectPOSIX)
			if got != tc.want {
				t.Fatalf("private-key read = %t, want %t", got, tc.want)
			}
		})
	}
}

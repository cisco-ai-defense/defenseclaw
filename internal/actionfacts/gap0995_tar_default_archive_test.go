// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestGAP0995TarCreateWithoutFileReadsMembers: a tar create with no -f or
// --file writes the archive to stdout, so it reads its members as a cat
// reads its operands, and the call is authoritative (substrate-1:GAP-0995,
// RV-0922 row s40: before, it was unknown grammar with no read, and the key
// file archive allowed where base64 of the key blocks). An explicit -f -
// reads them too, without the partial mark it had.
func TestGAP0995TarCreateWithoutFileReadsMembers(t *testing.T) {
	home := t.TempDir()
	key := filepath.ToSlash(filepath.Join(home, ".ssh", "id_ed25519"))
	for _, row := range []struct{ command, member string }{
		{"tar cz ~/.ssh/id_ed25519", key},
		{"tar -cz ~/.ssh/id_ed25519", key},
		{"tar --create --gzip ~/.ssh/id_ed25519", key},
		{"tar czf - ~/.ssh/id_ed25519", key},
		{"tar c src", "src"},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: home, ActiveHome: home, DialectHint: DialectPOSIX})
		read := slices.ContainsFunc(facts.Paths, func(p PathFact) bool {
			v := p.Resolved
			if v == "" {
				v = p.Value
			}
			return p.Access == PathAccessRead && (filepath.ToSlash(v) == row.member || filepath.Base(v) == row.member)
		})
		if !facts.Authoritative() || !read {
			t.Errorf("%s: authoritative %v, member %s read %v (issues %v)", row.command, facts.Authoritative(), row.member, read, facts.Parse.Issues)
		}
	}
}

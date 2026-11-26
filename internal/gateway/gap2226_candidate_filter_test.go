// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP2226CandidateFilterProgramNames guards what guestCandidateMayReadKey
// rests on (rel-1-0-10:GAP-2226, RV-2226 N2): every spelling of a reader the
// analysis names as that reader keeps the text, and a text the filter drops
// names no reader in the analysis.
func TestGAP2226CandidateFilterProgramNames(t *testing.T) {
	home := "/home/alice"
	readerOf := func(text string) bool {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: text, CWD: home + "/.ssh", ActiveHome: home})
		for _, command := range facts.Commands {
			if slices.Contains(sshPrivateKeyContentReaders, command.Program) {
				return true
			}
		}
		return false
	}
	for _, reader := range sshPrivateKeyContentReaders {
		for _, word := range []string{reader, strings.ToUpper(reader), "/usr/bin/" + reader, "/BIN/" + strings.ToUpper(reader),
			reader + ".exe", strings.ToUpper(reader) + ".EXE", reader + ".cmd"} {
			text := word + " id_ed25519"
			if readerOf(text) && !guestCandidateMayReadKey(text) {
				t.Errorf("%q names reader %q but the filter drops it", text, reader)
			}
		}
	}
	// Lookalike letters (fullwidth, Cyrillic, Kelvin sign, dotless i) are not
	// folded onto ASCII names: the filter may drop them because the analysis
	// names no reader for them.
	for _, text := range []string{"ｃat id_ed25519", "сat id_ed25519", "саt id_ed25519", "heаd id_ed25519",
		"Kat id_ed25519", "tаil id_ed25519", "base64 id_ed25519", "ınstall id_ed25519"} {
		if !guestCandidateMayReadKey(text) && readerOf(text) {
			t.Errorf("%q is dropped by the filter but the analysis names a reader", text)
		}
	}
	// A text of plain words that names no reader is dropped and has none.
	for _, text := range []string{"touch f1", "ls", "cd /tmp/x", "mkdir -p out", "rm -f a"} {
		if guestCandidateMayReadKey(text) || readerOf(text) {
			t.Errorf("%q: filter %v, reader %v; want both false", text, guestCandidateMayReadKey(text), readerOf(text))
		}
	}
}

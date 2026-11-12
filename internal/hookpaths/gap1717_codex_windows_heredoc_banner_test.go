// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWindowsHereDocBodyBannerAtHomeIsText is the Codex route of
// rel-1-0-4:GAP-1717 (still denied on 1.0.9, dc-win2): a Windows shell call
// of cat with a here-document whose body holds the apply_patch banner
// (*** Begin Patch) at cwd=home was denied as an authorized_keys command,
// because the *** word of the body read as a glob that matches .ssh in the
// home. The body of a here-document is text.
func TestWindowsHereDocBodyBannerAtHomeIsText(t *testing.T) {
	const home = `C:\Users\b00`
	for _, d := range []actionfacts.Dialect{actionfacts.DialectPowerShell, ""} {
		for _, command := range []string{
			"cat <<\"EOT\"\n*** Begin Patch\n*** End Patch\nEOT",
			"cat <<EOT\n*** Begin Patch\n*** End Patch\nEOT",
			"cat <<'EOT' > notes.txt\n*** Begin Patch\n*** End Patch\nEOT",
			"cat <<EOT && echo done\n*** Begin Patch\n*** End Patch\nEOT",
			"tee notes.txt <<EOT || true\n*** Begin Patch\nEOT",
		} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, d, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", d, command, got)
			}
		}
	}
}

// A here-document body keeps its verdict when its reader can run it, when an
// expansion inside it runs, or when the command writes a protected target.
func TestWindowsHereDocBodyStillScannedWhenItCanRun(t *testing.T) {
	const home = `C:\Users\b00`
	for _, d := range []actionfacts.Dialect{actionfacts.DialectPowerShell, ""} {
		for _, command := range []string{
			"bash <<EOT\ncp k ~/.ssh/authorized_keys\nEOT",
			"cat <<EOT | bash\ncp k ~/.ssh/authorized_keys\nEOT",
			"cat <<EOT\n$(cp k ~/.ssh/authorized_keys)\nEOT",
			"cat <<EOT\n*** Begin Patch\n$(cp k ~/.ssh/authorized_keys)\nEOT",
			"tee ~/.ssh/authorized_keys <<EOT\nssh-ed25519 AAAA\nEOT",
			"cat <<EOT > ~/.ssh/authorized_keys\n*** Begin Patch\nEOT",
		} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, d, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", d, command, got)
			}
		}
		// A body handed to a program that may run it (process substitution
		// as an output or an argument, a pipeline into a shell) is read as
		// before: its glob words stay scanned (T7 review P2).
		for _, command := range []string{
			"cat <<'EOT' > >(bash)\n*** Begin Patch\n*** End Patch\nEOT",
			"tee >(bash) <<EOT\n*** Begin Patch\n*** End Patch\nEOT",
			"cat <<EOT | sh\n*** Begin Patch\nEOT",
			"cat <<EOT > $(echo out)\n*** Begin Patch\nEOT",
		} {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, d, nil); got == "" {
				t.Errorf("dialect %q %q = %q, want protected-target", d, command, got)
			}
		}
	}
}

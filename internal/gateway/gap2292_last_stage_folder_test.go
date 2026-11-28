// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestGAP2292LastPipelineStageMayMoveTheShell: zsh (the login shell of
// macOS) and Bash with lastpipe run the last stage of a pipeline in the
// shell itself, so a cd in that stage, in a group it runs or in the text it
// sources moves the commands after the pipeline. They may run where the
// shell was (Bash) or where the stage left it (zsh), and the hook reads
// them in both: a later bare-name write to a protected file is answered as
// the write by its full name (rel-1-0-10:GAP-2292). A stage before the last
// runs in a copy under both shells and moves nothing; a harmless move stays
// allowed.
func TestGAP2292LastPipelineStageMayMoveTheShell(t *testing.T) {
	const direct = "printf changed >> ~/.defenseclaw/config.yaml"
	forms := []string{
		"echo x | cd ~/.defenseclaw; WRITE",
		"echo x | { cd ~/.defenseclaw; }; WRITE",
		"echo x | cd ~/.defenseclaw\nWRITE",
		"echo 'cd ~/.defenseclaw' | . /dev/stdin; WRITE",
		"echo 'cd ~/.defenseclaw' | source /dev/stdin\nWRITE",
		"cat <<'EOF' | . /dev/stdin; WRITE\ncd ~/.defenseclaw\nEOF",
		"echo x | cd ~/.defenseclaw && WRITE",
	}
	const write = "printf changed >> config.yaml"
	shellTextTiers(t, func(tier string, decide func(string) (string, []string), _ func(string, bool) (string, []string)) {
		want, wantFindings := decide(direct)
		if want == "allow" {
			t.Fatalf("%s: the direct write %q is allowed", tier, direct)
		}
		for _, form := range forms {
			command := strings.ReplaceAll(form, "WRITE", write)
			if got, findings := decide(command); gap1137Rank[got] < gap1137Rank[want] {
				t.Errorf("%s: %q is %s (%q), the write by its full name is %s (%q)", tier, command, got, findings, want, wantFindings)
			}
		}
		for _, command := range []string{
			// A stage before the last runs in a copy under every shell.
			"cd ~/.defenseclaw | cat; " + write,
			// A harmless move stays allowed.
			"echo x | cd build; printf x >> notes.txt",
			"echo 'cd build' | . /dev/stdin; make",
			"cat <<'EOF' | . /dev/stdin; make\ncd build\nEOF",
		} {
			if got, findings := decide(command); got != "allow" {
				t.Errorf("%s: %q is %s (%q), want allow", tier, command, got, findings)
			}
		}
	})
}

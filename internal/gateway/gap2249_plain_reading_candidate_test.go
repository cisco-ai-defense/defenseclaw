// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP2249PlainFolder pins the folders in which a plain reading stays a
// candidate after the call's own shell may stand there (guestPlainFolder,
// rel-1-0-10:GAP-2249): plain names below the home, the first of which may
// be .cache; never the home, a hidden folder or one below it, the macOS and
// Windows agent folders, ~/bin, a folder outside the home or a folder the
// credentials table keeps.
func TestGAP2249PlainFolder(t *testing.T) {
	const home = "/home/u"
	for _, dir := range []string{"/home/u/p", "/home/u/p/sub-1_x", "/home/u/.cache", "/home/u/.cache/s0", "/home/u/.cache/s0/s1/s2"} {
		if !guestPlainFolder(dir, home) {
			t.Errorf("guestPlainFolder(%q) = false, want true", dir)
		}
	}
	for _, dir := range []string{"/home/u", "/home/u/.ssh", "/home/u/.ssh/sub", "/home/u/p/.git", "/home/u/p/.git/hooks",
		"/home/u/.claude/hooks", "/home/u/.defenseclaw/x", "/home/u/.config/autostart", "/home/u/.cache/.x",
		"/home/u/p/.cache", "/home/u/.cache/huggingface", "/home/u/.cache/HuggingFace/x", "/home/u/Library/LaunchAgents",
		"/home/u/library", "/home/u/AppData/Roaming", "/home/u/bin", "/home/u/p/a b", "/home/u/p/-x", "/home/u/var/lib/jenkins/secrets",
		"/tmp/x", "/etc/cron.d", "/home/uv/x", "/"} {
		if guestPlainFolder(dir, home) {
			t.Errorf("guestPlainFolder(%q) = true, want false", dir)
		}
	}
	for _, home := range []string{"/", "", "u"} {
		if guestPlainFolder("/home/u/p", home) {
			t.Errorf("guestPlainFolder with home %q = true, want false", home)
		}
	}
	// The one protected file of the credentials table below ~/.cache, kept
	// out of the plain folders by name.
	if _, ok := actionfacts.MatchCredentialFileShape(home + "/.cache/huggingface/token"); !ok {
		t.Error("the credentials table no longer keeps .cache/huggingface/token: update guestPlainFolder")
	}
}

// TestGAP2249PlainReadingsStayCandidates: after $CMD a plain reading in a
// plain folder the call's own shell may stand in stays a candidate, as on
// the 1.0.10 line, while every other reading there (one the guest placement
// reads first, such as authorized_keys, or any reading in a hidden folder)
// is still judged as a placed child (substrate-1 GAP-0628,
// rel-1-0-10:GAP-2249). The shape is the fan-out of the GAP-2249 cost
// probes: 7 cds after $CMD give more folders than the placement keeps.
func TestGAP2249PlainReadingsStayCandidates(t *testing.T) {
	const home = "/home/u"
	var b strings.Builder
	b.WriteString("cd .cache\nbash <<< 'true'\n$CMD\n")
	for i := range 7 {
		fmt.Fprintf(&b, "cd s%d\n", i)
	}
	for i := range 20 {
		fmt.Fprintf(&b, "touch f%d\n", i)
	}
	b.WriteString("cd ../.ssh\ntouch k0\necho k >> authorized_keys\nls")
	input := actionfacts.Input{Tool: "Bash", Command: b.String(), CWD: home, ActiveHome: home}
	facts := actionfacts.Analyze(input)
	children, _, _ := sandboxGuestPlacedChildren(nil, input, facts)
	judged := map[string]bool{}
	for _, child := range children {
		for _, fact := range child.Paths {
			judged[path.Join(child.CWD, fact.Value)] = true
		}
	}
	placements, _ := (*guestReadingMemo)(nil).plan(input, facts).placements(true)
	folders := guestOwnShellFolders(input.Command, input.CWD, home)
	kept, promoted := 0, 0
	for _, placement := range placements {
		operand, ok := strings.CutPrefix(placement.text, "touch ")
		if !ok {
			continue
		}
		dir := path.Clean(placement.cwd)
		file := path.Join(dir, operand)
		if !placement.candidate || !folders.has(placement.text, dir) {
			continue
		}
		if !guestReadingFirst(placement.text) && guestPlainFolder(dir, home) {
			kept++
			if judged[file] {
				t.Errorf("%q in %s is judged as a placed child: a plain reading in a plain folder stays a candidate", placement.text, dir)
			}
			continue
		}
		promoted++
		if !judged[file] {
			t.Errorf("%q in %s is not judged as a placed child: the call's own shell may stand there", placement.text, dir)
		}
	}
	if kept == 0 || promoted == 0 {
		t.Fatalf("the shape keeps %d plain readings and promotes %d others: want both", kept, promoted)
	}
	if !judged[home+"/.ssh/authorized_keys"] {
		t.Error("the authorized_keys write in ~/.ssh is not judged as a placed child (substrate-1 GAP-0628)")
	}
}

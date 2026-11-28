// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// patchDecoyEnvelope is one envelope of patchDecoyEnvelopes: the access of
// the placed file, and whether the tool writes text to it.
type patchDecoyEnvelope struct {
	text   string
	access PathAccess
	writes bool
}

// patchDecoyEnvelopes are the envelopes that hold the change of one directive
// of placed and one block of a file no reader places on any host (a home form
// the tool does not expand), before it or after it.
func patchDecoyEnvelopes(placed string) map[string]patchDecoyEnvelope {
	out := map[string]patchDecoyEnvelope{}
	for directive, envelope := range patchHeaderEnvelopes(placed) {
		body := strings.TrimSuffix(strings.TrimPrefix(envelope.text, patchBeginLine+"\n"), "\n"+patchEndLine)
		for _, decoy := range []string{"~/decoy.txt", `~\decoy.txt`} {
			block := "*** Add File: " + decoy + "\n+x"
			for order, text := range map[string]string{
				"first": patchBeginLine + "\n" + block + "\n" + body + "\n" + patchEndLine,
				"last":  patchBeginLine + "\n" + body + "\n" + block + "\n" + patchEndLine,
			} {
				out[directive+" "+order+" "+decoy] = patchDecoyEnvelope{text, envelope.access, directive != "delete"}
			}
		}
	}
	// A file no reader places moved to the placed one: the tool writes the
	// placed file.
	out["move from unplaced"] = patchDecoyEnvelope{patchBeginLine + "\n*** Update File: ~/decoy.txt\n*** Move to: " + placed + "\n@@\n-a\n+b\n" + patchEndLine,
		PathAccessWrite, true}
	return out
}

// An envelope whose headers name a placed file and a file no reader places
// keeps every placed change: the parse is complete, each placed header is the
// write or delete fact its single-header patch is, the content proofs read the
// placed file's text, and PatchNamesUnplacedTarget still reports the other
// header so the gateway adds the unknown-tier finding. The file no reader
// places is no fact and no content write (rel-1-0-10:GAP-1055). Before, one
// such header dropped every placed change, and the patch was judged at the
// unknown tier only, where its single-header patch blocks.
func TestPatchDecoyHeaderKeepsThePlacedChanges(t *testing.T) {
	const placed = "src/placed.txt"
	for name, envelope := range patchDecoyEnvelopes(placed) {
		for _, field := range patchHeaderFields {
			t.Run(name+" "+field, func(t *testing.T) {
				args, err := json.Marshal(map[string]string{field: envelope.text})
				if err != nil {
					t.Fatal(err)
				}
				input := Input{Tool: "apply_patch", Args: args, CWD: "/srv/app"}
				facts := Analyze(input)
				if facts.Parse.Status != StatusComplete || !facts.Authoritative() {
					t.Fatalf("parse = %#v", facts.Parse)
				}
				if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool {
					return path.Value == placed && path.Access == envelope.access
				}) {
					t.Fatalf("no %s fact for the placed header: %#v", envelope.access, facts.Paths)
				}
				if slices.ContainsFunc(facts.Paths, func(path PathFact) bool { return strings.Contains(path.Value, "decoy") }) {
					t.Fatalf("the unplaced header is a fact: %#v", facts.Paths)
				}
				if !PatchNamesUnplacedTarget(Input{Tool: "apply_patch", Args: args}) {
					t.Fatal("the unplaced header is not reported")
				}
				targets := NativeCallWriteTargets(input, facts)
				if slices.ContainsFunc(targets, func(target string) bool { return strings.Contains(target, "decoy") }) {
					t.Fatalf("the unplaced header is a content write: %v", targets)
				}
				if envelope.writes != slices.Contains(targets, placed) {
					t.Fatalf("content writes %v (want the placed file: %t)", targets, envelope.writes)
				}
			})
		}
		// The same envelope fed to apply_patch by a shell here-document, with a
		// quoted delimiter or with one the shell expands, is read as the tool
		// reads it: complete, the placed facts kept, and the command marked
		// so the gateway adds the unknown-tier finding (rel-1-0-10:GAP-1077).
		// Before, the shell reading stayed partial, which no path rule judges,
		// and had no unknown finding: allow in every tier.
		for delimiter, document := range patchDecoyHeredocs(envelope.text) {
			t.Run(name+" shell here-document "+delimiter, func(t *testing.T) {
				facts := patchDecoyShellFacts(t, document)
				if facts.Parse.Status != StatusComplete || !facts.Authoritative() {
					t.Fatalf("parse = %#v", facts.Parse)
				}
				if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool {
					return path.Value == placed && path.Access == envelope.access
				}) {
					t.Fatalf("no %s fact for the placed header: %#v", envelope.access, facts.Paths)
				}
				if slices.ContainsFunc(facts.Paths, func(path PathFact) bool { return strings.Contains(path.Value, "decoy") }) {
					t.Fatalf("the unplaced header is a fact: %#v", facts.Paths)
				}
				if !CommandPatchNamesUnplacedTarget(facts) {
					t.Fatal("the unplaced header is not reported")
				}
			})
		}
	}
}

// patchDecoyHeredocs are the shell commands that feed envelope to apply_patch
// by a here-document: with a quoted delimiter, and with an unquoted one and a
// first file whose text the shell expands.
func patchDecoyHeredocs(envelope string) map[string]string {
	expanding := strings.Replace(envelope, patchBeginLine+"\n", patchBeginLine+"\n*** Add File: notes0.txt\n+$PWD\n", 1)
	return map[string]string{
		"quoted":    "apply_patch <<'PATCH'\n" + envelope + "\nPATCH\n",
		"expanding": "apply_patch <<PATCH\n" + expanding + "\nPATCH\n",
	}
}

func patchDecoyShellFacts(t *testing.T, command string) Facts {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(Input{Tool: "Bash", Args: args, CWD: "/srv/app"})
}

// In a here-document the shell expands, a header whose name the shell may
// change (an expansion, an escaped character) names a file no
// reader places: the other headers are still read, and the command is marked
// (rel-1-0-10:GAP-1077). Before, any such header made the whole envelope
// unread, partial and allowed in every tier, whatever the placed headers
// wrote. A header the shell leaves as written (a backslash before an ordinary
// character) is the name as written.
func TestPatchHeredocHeaderTheShellExpandsIsUnplaced(t *testing.T) {
	const placed = "src/placed.txt"
	for _, name := range []string{"$HOME/decoy.txt", "${HOME}/decoy.txt", "decoy-$(id -u).txt", "decoy-`id -u`.txt",
		`decoy\$x.txt`, `decoy\\.txt`} {
		t.Run(name, func(t *testing.T) {
			facts := patchDecoyShellFacts(t, "apply_patch <<PATCH\n"+patchBeginLine+"\n*** Add File: "+name+
				"\n+x\n*** Add File: "+placed+"\n+y\n"+patchEndLine+"\nPATCH\n")
			if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool {
				return path.Value == placed && path.Access == PathAccessWrite
			}) {
				t.Fatalf("no write fact for the placed header: %#v", facts.Paths)
			}
			// A lone leading $HOME or ${HOME} is placed under the active home
			// (rel-1-0-10:GAP-1094); no other expanded header is a fact.
			homeHeader := strings.Contains(name, "HOME")
			placedHome := func(path PathFact) bool {
				return homeHeader && path.Access == PathAccessWrite && strings.HasSuffix(path.Value, "/decoy.txt") &&
					!strings.ContainsAny(path.Value, "$`{}")
			}
			if slices.ContainsFunc(facts.Paths, func(path PathFact) bool { return strings.Contains(path.Value, "decoy") && !placedHome(path) }) {
				t.Fatalf("the expanded header is a fact: %#v", facts.Paths)
			}
			if homeHeader && !slices.ContainsFunc(facts.Paths, placedHome) {
				t.Fatalf("the $HOME header is not placed under the home: %#v", facts.Paths)
			}
			if !CommandPatchNamesUnplacedTarget(facts) {
				t.Fatal("the expanded header is not reported")
			}
		})
	}
	// Quoted, the same name is a plain file name; and a backslash before an
	// ordinary character stays as written in an expanding body. The
	// expanding body is still marked: its expansion may add a header no
	// reader sees (rel-1-0-10:GAP-1093).
	for name, document := range map[string]struct {
		text   string
		marked bool
	}{
		"quoted": {"apply_patch <<'PATCH'\n" + patchBeginLine + "\n*** Add File: $HOME/decoy.txt\n+x\n" + patchEndLine + "\nPATCH\n", false},
		"plain backslash": {"apply_patch <<PATCH\n" + patchBeginLine + "\n*** Add File: notes0.txt\n+$PWD\n*** Add File: dir\\decoy.txt\n+x\n" +
			patchEndLine + "\nPATCH\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			facts := patchDecoyShellFacts(t, document.text)
			if facts.Parse.Status != StatusComplete || CommandPatchNamesUnplacedTarget(facts) != document.marked {
				t.Fatalf("parse = %#v, unplaced %t", facts.Parse, CommandPatchNamesUnplacedTarget(facts))
			}
			if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool { return strings.Contains(path.Value, "decoy") }) {
				t.Fatalf("no fact for the header as written: %#v", facts.Paths)
			}
		})
	}
	// An envelope whose only header no reader places writes nothing a rule
	// reads: still partial, and still marked, so the gateway judges it at the
	// unknown tier, as it judges the native tool's.
	facts := patchDecoyShellFacts(t, "apply_patch <<'PATCH'\n"+patchBeginLine+"\n*** Add File: ~/decoy.txt\n+x\n"+patchEndLine+"\nPATCH\n")
	if facts.Parse.Status == StatusComplete || !CommandPatchNamesUnplacedTarget(facts) {
		t.Fatalf("only header unplaced: parse = %#v, unplaced %t", facts.Parse, CommandPatchNamesUnplacedTarget(facts))
	}
}

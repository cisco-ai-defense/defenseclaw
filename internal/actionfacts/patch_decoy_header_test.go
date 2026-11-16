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
				if !PatchNamesUnplacedTarget("apply_patch", args) {
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
		// The same envelope fed to apply_patch by a shell here-document keeps
		// the placed facts too, and stays partial: the shell reading has no
		// unknown-tier finding of its own for the header no reader places.
		t.Run(name+" shell here-document", func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": "apply_patch <<'PATCH'\n" + envelope.text + "\nPATCH\n"})
			facts := Analyze(Input{Tool: "Bash", Args: args, CWD: "/srv/app"})
			if facts.Parse.Status == StatusComplete {
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
		})
	}
}

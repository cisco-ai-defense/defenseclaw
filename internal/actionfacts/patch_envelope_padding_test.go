// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

const paddedPatchBody = "*** Add File: /etc/ld.so.preload\n+/usr/local/lib/liblogger.so\n"

func paddedPatchCall(t *testing.T, tool, key, text string) (Input, Facts) {
	t.Helper()
	args, err := json.Marshal(map[string]any{key: text})
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Tool: tool, Args: args}
	return input, Analyze(input)
}

// TestPatchEnvelopePaddingIsReadLikeTheTool pins that the white space around
// a patch, its line end style and the white space around a file header do
// not change what the envelope is: the loader-preload content proof reads
// every spelling the patch tool applies, and a benign file stays unproven.
func TestPatchEnvelopePaddingIsReadLikeTheTool(t *testing.T) {
	plain := "*** Begin Patch\n" + paddedPatchBody + "*** End Patch"
	spaces := strings.Repeat(" ", 250000)
	for _, c := range []struct{ name, text string }{
		{"plain", plain},
		{"one newline", plain + "\n"},
		{"one trailing space", plain + " "},
		{"trailing tab", plain + "\t"},
		{"many trailing spaces", plain + spaces},
		{"many trailing tabs", plain + strings.Repeat("\t", 100000)},
		{"extra newlines", plain + "\n\n\n"},
		{"leading space", " " + plain},
		{"many leading spaces", spaces + plain},
		{"leading newline", "\n" + plain},
		{"CRLF", strings.ReplaceAll(plain+"\n", "\n", "\r\n")},
		{"CRLF and trailing spaces", strings.ReplaceAll(plain, "\n", "\r\n") + " \r\n \r\n"},
		{"header trailing space", strings.Replace(plain, "preload\n", "preload   \n", 1)},
		{"header leading tab", strings.Replace(plain, "*** Add File:", "\t*** Add File:", 1)},
		{"header leading space", strings.Replace(plain, "*** Add File:", " *** Add File:", 1)},
	} {
		for _, shape := range []struct{ tool, key string }{
			{"apply_patch", "command"}, {"apply_patch", "patch"}, {"apply_patch", "input"},
		} {
			t.Run(c.name+"/"+shape.key, func(t *testing.T) {
				input, facts := paddedPatchCall(t, shape.tool, shape.key, c.text)
				if !ExactGlobalLDPreloadFileWrite(input, facts) {
					t.Fatalf("no loader-preload proof: status %s", facts.Parse.Status)
				}
			})
		}
	}
}

// TestPatchEnvelopePaddingOfOrdinaryFileStaysOrdinary is the benign twin: a
// padded patch of an ordinary file is complete and proves nothing.
func TestPatchEnvelopePaddingOfOrdinaryFileStaysOrdinary(t *testing.T) {
	text := "*** Begin Patch\n*** Add File: /srv/app/a.txt\n+hello\n*** End Patch" + strings.Repeat(" ", 1000) + "\r\n\r\n"
	input, facts := paddedPatchCall(t, "apply_patch", "command", text)
	if facts.Parse.Status != StatusComplete || ExactGlobalLDPreloadFileWrite(input, facts) {
		t.Fatalf("status %s", facts.Parse.Status)
	}
}

// TestPatchEnvelopeOutsideTheMarkersStaysInvalid keeps the strict part: text
// beside the markers, a padded marker line, a carriage return inside a line of
// content (the tools take one only out of a file name, which GAP-1027 reads as
// the plain name) or a line of an update that only looks like a header is not
// read as a patch of a protected file.
func TestPatchEnvelopeOutsideTheMarkersStaysInvalid(t *testing.T) {
	plain := "*** Begin Patch\n" + paddedPatchBody + "*** End Patch"
	for name, text := range map[string]string{
		"text after":                             plain + "\ntrailing",
		"text before":                            "note\n" + plain,
		"begin marker with space":                strings.Replace(plain, "*** Begin Patch", "*** Begin Patch ", 1),
		"lone carriage return in a content line": strings.Replace(plain, "preload\n", "preload\n+a\rb\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, facts := paddedPatchCall(t, "apply_patch", "command", text)
			if facts.Parse.Status == StatusComplete {
				t.Fatalf("read as a complete patch")
			}
		})
	}
}

// TestPatchContextLineOfUpdateIsNotAHeader pins that a line of an update that
// starts with a space is text, even when it reads like a file header.
func TestPatchContextLineOfUpdateIsNotAHeader(t *testing.T) {
	text := "*** Begin Patch\n*** Update File: /srv/a.txt\n@@\n *** Add File: /etc/ld.so.preload\n+/usr/local/lib/liblogger.so\n*** End Patch"
	input, facts := paddedPatchCall(t, "apply_patch", "command", text)
	if facts.Parse.Status != StatusComplete || ExactGlobalLDPreloadFileWrite(input, facts) {
		t.Fatalf("a context line was read as a file header: %s", facts.Parse.Status)
	}
}

// TestPatchEnvelopeEmptyLineOfUpdateIsText pins that an empty line of an
// update hunk is a line of its text, as the tool reads it, so the patch is
// not left unread by it.
func TestPatchEnvelopeEmptyLineOfUpdateIsText(t *testing.T) {
	text := "*** Begin Patch\n*** Update File: /etc/ld.so.preload\n@@\n+/usr/local/lib/liblogger.so\n\n+/usr/local/lib/libother.so\n*** End Patch\n"
	input, facts := paddedPatchCall(t, "apply_patch", "command", text)
	if !ExactGlobalLDPreloadFileWrite(input, facts) {
		t.Fatalf("no loader-preload proof: status %s", facts.Parse.Status)
	}
}

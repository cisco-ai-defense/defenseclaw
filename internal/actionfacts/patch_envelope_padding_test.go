// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
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
// beside the markers, a marker the tool does not read as the marker, a
// carriage return inside a line of content (the tools take one only out of a file name, which GAP-1027 reads as
// the plain name) or a line of an update that only looks like a header is not
// read as a patch of a protected file.
func TestPatchEnvelopeOutsideTheMarkersStaysInvalid(t *testing.T) {
	plain := "*** Begin Patch\n" + paddedPatchBody + "*** End Patch"
	for name, text := range map[string]string{
		"text after":                             plain + "\ntrailing",
		"text before":                            "note\n" + plain,
		"marker with text":                       strings.Replace(plain, "*** Begin Patch", "*** Begin Patch x", 1),
		"marker with zero width space":           strings.Replace(plain, "*** Begin Patch", "*** Begin Patch\u200b", 1),
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

// patchToolTrimmedSpaces are the characters the patch tool trims from the ends
// of a patch text and of its first and last line (measured with the tool
// itself): every Unicode space.
func patchToolTrimmedSpaces() []string {
	spaces := []string{" ", "\t", "\v", "\f", "\r", "\u0085", "\u00a0", "\u1680", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"}
	for r := rune(0x2000); r <= 0x200a; r++ {
		spaces = append(spaces, string(r))
	}
	return spaces
}

// TestPatchEnvelopeEdgeSpacesAreTheSpacesTheToolTrims pins that every space the
// patch tool trims at the edge of the patch, or of its first or last line, is
// padding for the loader-preload proof too: a lone carriage return, U+00A0,
// U+202F and the other Unicode spaces do not take a protected patch out of
// the content rules, and an ordinary file stays complete and unproven.
func TestPatchEnvelopeEdgeSpacesAreTheSpacesTheToolTrims(t *testing.T) {
	plain := "*** Begin Patch\n" + paddedPatchBody + "*** End Patch"
	ordinary := "*** Begin Patch\n*** Add File: /srv/app/a.txt\n+hello\n*** End Patch"
	for _, space := range patchToolTrimmedSpaces() {
		for name, build := range map[string]func(string) string{
			"trailing":   func(p string) string { return p + space },
			"leading":    func(p string) string { return space + p },
			"both":       func(p string) string { return space + p + space },
			"begin line": func(p string) string { return strings.Replace(p, "*** Begin Patch", "*** Begin Patch"+space, 1) },
			"end line":   func(p string) string { return strings.Replace(p, "*** End Patch", space+"*** End Patch", 1) },
			"many":       func(p string) string { return p + strings.Repeat(space, 4096) },
		} {
			for _, key := range []string{"command", "patch", "input"} {
				t.Run(fmt.Sprintf("%U/%s/%s", []rune(space)[0], name, key), func(t *testing.T) {
					input, facts := paddedPatchCall(t, "apply_patch", key, build(plain))
					if !ExactGlobalLDPreloadFileWrite(input, facts) {
						t.Fatalf("no loader-preload proof: status %s", facts.Parse.Status)
					}
					input, facts = paddedPatchCall(t, "apply_patch", key, build(ordinary))
					if facts.Parse.Status != StatusComplete || ExactGlobalLDPreloadFileWrite(input, facts) {
						t.Fatalf("ordinary file: status %s", facts.Parse.Status)
					}
				})
			}
		}
	}
}

// TestPatchEnvelopeEdgeCharactersTheToolKeepsStayInvalid is the strict twin:
// characters the patch tool does not trim (zero width and control characters,
// a byte order mark) beside a marker leave the envelope unread, so they are
// never read as padding.
func TestPatchEnvelopeEdgeCharactersTheToolKeepsStayInvalid(t *testing.T) {
	plain := "*** Begin Patch\n" + paddedPatchBody + "*** End Patch"
	for _, char := range []string{"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u180e", "\u200e", "\x1c", "\x1f", "\x7f", "\x01"} {
		for name, text := range map[string]string{
			"trailing": plain + char, "leading": char + plain,
			"begin line": strings.Replace(plain, "*** Begin Patch", "*** Begin Patch"+char, 1),
		} {
			t.Run(fmt.Sprintf("%U/%s", []rune(char)[0], name), func(t *testing.T) {
				_, facts := paddedPatchCall(t, "apply_patch", "command", text)
				if facts.Parse.Status == StatusComplete {
					t.Fatalf("read as a complete patch")
				}
			})
		}
	}
}

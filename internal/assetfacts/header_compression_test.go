// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// noise is n letters that deflate to about three quarters of their size.
func noise(random *rand.Rand, n int) string {
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := range out {
		out[i] = letters[random.Intn(len(letters))]
	}
	return string(out)
}

func ordinaryDocument(owner, lines int) string {
	var doc strings.Builder
	for line := 0; line < lines; line++ {
		fmt.Fprintf(&doc, "Section %d.%d: ordinary documentation of option %d of the notes tool.\n", owner, line, line*7)
	}
	return doc.String()
}

// The candidate owners of one plugin tool name (a tool name of 64 characters
// has up to 23) keep their text when each is an ordinary document: the claim
// is judged on its deflated size, not on a text budget that would turn an
// ordinary call into a refusal.
func TestHeaderKeepsTheTextOfEveryOrdinaryCandidateOwner(t *testing.T) {
	var contents []Content
	for i := 0; i < 23; i++ {
		contents = append(contents, Content{Kind: ContentPlugin, Name: fmt.Sprintf("p%02d", i), Dir: "/plugins/" + fmt.Sprint(i),
			Files: []ContentFile{{Rel: "skills/notes/SKILL.md", Text: ordinaryDocument(i, 800)}}})
	}
	value := Encode(Facts{Contents: contents})
	if !strings.HasPrefix(value, compressedPrefix) || len(value) > maxHeaderBytes {
		t.Fatalf("large claim encoded as %d bytes with prefix %.2q, want a deflated value under %d", len(value), value, maxHeaderBytes)
	}
	facts, ok := Decode(value)
	if !ok || len(facts.Contents) != len(contents) {
		t.Fatalf("decoded %d contents (ok=%v), want %d", len(facts.Contents), ok, len(contents))
	}
	for _, content := range facts.Contents {
		if content.Truncated || len(content.Files) != 1 {
			t.Errorf("content %q lost its text: %+v", content.Name, content.Truncated)
		}
	}
}

// Small claims keep the plain form (and its cost), and a value in the plain
// form that an earlier hook produced still decodes.
func TestHeaderSmallClaimIsPlainAndPlainValuesDecode(t *testing.T) {
	facts := Facts{Contents: []Content{{Kind: ContentSkill, Name: "notes", Dir: "/skills/notes", Files: []ContentFile{{Rel: "SKILL.md", Text: "# notes\n"}}}}}
	value := Encode(facts)
	if value == "" || strings.HasPrefix(value, compressedPrefix) {
		t.Fatalf("small claim = %.20q, want the plain form", value)
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := Decode(base64.RawURLEncoding.EncodeToString(raw)); !ok || len(got.Contents) != 1 {
		t.Errorf("plain value from an earlier hook did not decode: ok=%v %+v", ok, got)
	}
}

// A small deflated value that expands past the decode bound is refused rather
// than allocated, and a corrupt one is refused.
func TestHeaderDeflatedValueCannotExpandWithoutBound(t *testing.T) {
	pack := func(raw []byte) string {
		var packed bytes.Buffer
		writer, _ := flate.NewWriter(&packed, flate.BestCompression)
		_, _ = writer.Write(raw)
		_ = writer.Close()
		return compressedPrefix + base64.RawURLEncoding.EncodeToString(packed.Bytes())
	}
	bomb := pack(bytes.Repeat([]byte{' '}, maxDecodedBytes+1024))
	if len(bomb) > maxHeaderBytes {
		t.Fatalf("test value is %d bytes", len(bomb))
	}
	if _, ok := Decode(bomb); ok {
		t.Error("a deflated value that expands past the bound was decoded")
	}
	if _, ok := Decode(compressedPrefix + "AAAA"); ok {
		t.Error("a corrupt deflated value was decoded")
	}
	ok := pack([]byte(`{"skill_dirs":["/skills/notes"]}`))
	if facts, accepted := Decode(ok); !accepted || len(facts.SkillDirs) != 1 {
		t.Errorf("a deflated value within the bound was refused: %v %+v", accepted, facts)
	}
}

// Text that does not shrink and does not fit keeps every content as a
// truncated one without text, which the gateway refuses: the asset never runs
// unjudged, and no content is dropped.
func TestHeaderTextThatCannotFitIsKeptAsTruncatedContents(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	var contents []Content
	for i := 0; i < 24; i++ {
		text := noise(random, 60<<10)
		contents = append(contents, Content{Kind: ContentPlugin, Name: fmt.Sprintf("p%02d", i), Dir: "/plugins/" + fmt.Sprint(i),
			Files: []ContentFile{{Rel: "SKILL.md", Text: text}}})
	}
	facts, ok := Decode(Encode(Facts{Contents: contents}))
	if !ok || len(facts.Contents) != len(contents) {
		t.Fatalf("decoded %d contents (ok=%v), want %d", len(facts.Contents), ok, len(contents))
	}
	for _, content := range facts.Contents {
		if !content.Truncated || len(content.Files) != 0 {
			t.Errorf("content %q = truncated %v with %d files, want a truncated content without text", content.Name, content.Truncated, len(content.Files))
		}
	}
}

// The tail keeps 65,536 digests of the width of the full ones, and the largest
// MCP definition fits the header with them.
func TestHeaderLargestArgumentListFitsWithItsWholeTail(t *testing.T) {
	args := make([]string, maxPinArgs+maxTailPins)
	for i := range args {
		args[i] = fmt.Sprintf("--argument-%d", i)
	}
	value := Encode(Facts{MCP: &MCPServer{Name: "notes", Command: "node", Args: args, ProjectScope: true, Digest: strings.Repeat("ab", 32)}})
	if value == "" || len(value) > maxHeaderBytes {
		t.Fatalf("encoded %d bytes, want 1..%d", len(value), maxHeaderBytes)
	}
	facts, ok := Decode(value)
	if !ok || facts.MCP == nil || facts.MCP.Pins == nil || facts.MCP.Pins.ArgCount != len(args) {
		t.Fatalf("pins lost: %+v", facts.MCP)
	}
	last := len(args) - 1
	if !bytes.Equal(facts.MCP.Pins.TailDigest(last-maxPinArgs), PinTailDigest(args[last])) {
		t.Error("the last argument has no tail digest")
	}
}

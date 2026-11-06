// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand"
	"regexp"
	"testing"
)

func TestUnprovenPathTokenScannerMatchesPriorPattern(t *testing.T) {
	prior := regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]-]+`)
	random := rand.New(rand.NewSource(534))
	alphabet := []byte("abAZ09_./~*?[]- ;|&#'\"$\\\n@é")
	for sample := 0; sample < 1000; sample++ {
		bytes := make([]byte, random.Intn(200))
		for i := range bytes {
			bytes[i] = alphabet[random.Intn(len(alphabet))]
		}
		text := string(bytes)
		for offset := 0; offset < len(text); {
			want := prior.FindStringIndex(text[offset:])
			start, end := nextUnprovenPathToken(text, offset)
			if want == nil {
				if start != -1 || end != -1 {
					t.Fatalf("sample %d offset %d: got token [%d:%d]", sample, offset, start, end)
				}
				break
			}
			if start != offset+want[0] || end != offset+want[1] {
				t.Fatalf("sample %d offset %d: got [%d:%d], want [%d:%d]", sample, offset, start, end, offset+want[0], offset+want[1])
			}
			if got := unprovenWholePathToken(text[start:end]); !got {
				t.Fatalf("sample %d: token %q was not whole", sample, text[start:end])
			}
			offset = end
		}
	}
}

func TestActionMentionTokenScannerMatchesPriorPattern(t *testing.T) {
	prior := regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]\x1e-]+`)
	random := rand.New(rand.NewSource(535))
	alphabet := []byte("abAZ09_./~*?[]-;|&#'\"$\\\n@é\x1e")
	for sample := 0; sample < 1000; sample++ {
		bytes := make([]byte, random.Intn(200))
		for i := range bytes {
			bytes[i] = alphabet[random.Intn(len(alphabet))]
		}
		text := string(bytes)
		for offset := 0; offset < len(text); {
			want := prior.FindStringIndex(text[offset:])
			start, end := nextActionMentionToken(text, offset)
			if want == nil {
				if start != -1 || end != -1 {
					t.Fatalf("sample %d offset %d: got token [%d:%d]", sample, offset, start, end)
				}
				break
			}
			if start != offset+want[0] || end != offset+want[1] {
				t.Fatalf("sample %d offset %d: got [%d:%d], want [%d:%d]", sample, offset, start, end, offset+want[0], offset+want[1])
			}
			offset = end
		}
	}
}

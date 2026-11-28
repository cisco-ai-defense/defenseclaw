// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestGAP0299ParseBashMatchesOwnBashParse is the oracle of ParseBash
// (rel-1-0-10:GAP-0299): for small and large commands, ones only Bash reads,
// ones neither grammar reads and random texts, on a cold cache, on its own
// kept tree and after Parse kept one, ParseBash gives the tree and the answer
// of the Bash parse each reader made on its own before.
func TestGAP0299ParseBashMatchesOwnBashParse(t *testing.T) {
	body := strings.Repeat("benign note line: nothing to see here\n", 2000)
	commands := []string{
		"echo hi",
		"cat > notes.txt <<'EOF'\n" + body + "EOF\n",
		"sh < <(cat <<'EOF'\ndefenseclaw stop\nEOF\n)\n#" + body,
		"x=( a b )\n[[ -f x ]] && echo ok\n#" + body,
		"if then fi\n" + body,
		"echo $((1+\n" + body,
		"f() { cat <<EOF\n$(id)\nEOF\n}\n" + body,
	}
	rng := rand.New(rand.NewPCG(2, 299))
	const alphabet = "ab $(){}[]'\"<>|&;\n#=-\\`"
	for i := 0; i < 24; i++ {
		var text strings.Builder
		size := 64 + rng.IntN(64)
		if i%2 == 1 {
			size += largeCommandMin
		}
		for text.Len() < size {
			text.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		commands = append(commands, text.String())
	}
	for _, command := range commands {
		want, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
		check := func(stage string) {
			t.Helper()
			got, ok := ParseBash(command)
			if ok != (err == nil) {
				t.Fatalf("%s %.40q: ParseBash ok=%v, own Bash parse err=%v", stage, command, ok, err)
			}
			if ok && !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %.40q: ParseBash tree differs from the own Bash parse", stage, command)
			}
		}
		parseCache.Lock()
		parseCache.entries = nil
		parseCache.Unlock()
		check("cold")
		check("kept")
		parseCache.Lock()
		parseCache.entries = nil
		parseCache.Unlock()
		Parse(command)
		check("after Parse")
	}
}

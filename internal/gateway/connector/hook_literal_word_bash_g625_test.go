package connector

import (
	"bytes"
	"math/rand"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// hookLiteralWord may only say a word is literal when the shell makes exactly
// that text of it. This builds words from the pieces that decided earlier
// reviews (escapes, quotes, braces, tilde, glob characters) and compares every
// word the reader accepts with what Bash makes of it. A word the reader
// refuses is not checked: it stays scanned as text, the protected direction.
func TestGAP0625LiteralWordMatchesBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs bash and POSIX quoting")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	pieces := []string{
		"a", "/x", "/", ".", "..", ",", "{", "}", "{a,b}", "{1..3}", "{a..c}", "{ab..cd}", "{1..}", "{-2..2..2}",
		"~", "~/", "*", "?", "[a]", `\*`, `\{`, `\~`, `\q`, `\ `, `\\`, `\"`, `\'`,
		`'s q'`, `'{'`, `'}'`, `'~'`, `"d q"`, `"{a,b}"`, `"\q"`, `"\$"`, `"\\"`, `"\""`,
		`$'\q'`, `$'\x'`, `$'\u'`, `$'\U'`, `$'\x41'`, `$'A'`, `$'\101'`, `$'\777'`, `$'\400'`, `$'\e'`, `$'\n'`,
		`$'\cA'`, `$'\0'`, `$'\x00'`, `$'\''`, `$'\"'`, `$'\?'`, `$'{a,b}'`, `$'{'`, `$'~'`, `$'*'`, `$'a b'`,
	}
	rng := rand.New(rand.NewSource(625))
	var words []string
	seen := map[string]bool{}
	for len(words) < 6000 {
		var word strings.Builder
		for n := 1 + rng.Intn(4); n > 0; n-- {
			word.WriteString(pieces[rng.Intn(len(pieces))])
		}
		if !seen[word.String()] {
			seen[word.String()] = true
			words = append(words, word.String())
		}
	}
	type accepted struct{ word, text string }
	var checked []accepted
	for _, word := range words {
		file, ok := shellparse.Parse(word)
		if !ok || len(file.Stmts) != 1 {
			continue
		}
		call, isCall := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall || len(call.Args) != 1 || len(call.Assigns) != 0 {
			continue
		}
		if text, ok := hookLiteralWord(call.Args[0], false); ok {
			checked = append(checked, accepted{word, text})
		}
	}
	if len(checked) < 500 {
		t.Fatalf("only %d of %d words read as literal; the generator no longer exercises the reader", len(checked), len(words))
	}
	dir := t.TempDir()
	for start := 0; start < len(checked); start += 250 {
		batch := checked[start:min(start+250, len(checked))]
		var script strings.Builder
		for _, item := range batch {
			script.WriteString("printf '%s\\0' " + item.word + "; printf '\\1'\n")
		}
		cmd := exec.Command(bash, "-c", script.String())
		cmd.Dir = dir
		cmd.Env = []string{"LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "HOME=/nonexistent-home"}
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		fields := bytes.Split(output, []byte{1})
		if len(fields) != len(batch)+1 {
			t.Fatalf("bash made %d answers for %d words", len(fields)-1, len(batch))
		}
		for i, item := range batch {
			if got := string(fields[i]); got != item.text+"\x00" {
				t.Errorf("hookLiteralWord(%s) = %q; bash makes %q", item.word, item.text, strings.TrimSuffix(got, "\x00"))
			}
		}
	}
}

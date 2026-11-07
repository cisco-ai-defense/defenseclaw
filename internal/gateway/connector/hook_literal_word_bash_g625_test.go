package connector

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// hookLiteralWord and Bash must agree both ways. A word the reader accepts is
// exactly the text Bash makes of it; a word Bash leaves as one plain, non-empty
// field, whatever the environment and the files in the directory, is accepted.
// The second direction is what keeps ordinary program names from reading as
// unknown (a refused word stays scanned as text and is claimed as a hook).
// Words are built from the pieces that decided earlier reviews (escapes,
// quotes, brace lists and sequences with mixed ends, tilde, glob characters).
// Bash runs twice per word: with globbing on in a directory holding matching
// files and one home, and with globbing off and another home, so a word whose
// text depends on files or on the home directory is told apart from a plain one.
func TestGAP0625LiteralWordMatchesBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs bash and POSIX quoting")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("needs bash")
	}
	pieces := []string{
		"a", "1", "b", "/x", "/", ".", "..", ",", "{", "}", "{a,b}", "{1..3}", "{a..c}", "{ab..cd}", "{1..}", "{-2..2..2}",
		"{1..a}", "{a..1}", "{1..a..2}", "{1..2..3..4}", "{1..2..0}", "{a..a}", "{1..1}", "{,}", "{}", "{a}",
		"~", "~/", "*", "?", "[a]", `\*`, `\{`, `\}`, `\,`, `\~`, `\q`, `\ `, `\\`, `\"`, `\'`, `\.`,
		`'s q'`, `'{'`, `'}'`, `'~'`, `"d q"`, `"{a,b}"`, `"\q"`, `"\$"`, `"\\"`, `"\""`, `"\{"`,
		`$'\q'`, `$'\x'`, `$'\u'`, `$'\U'`, `$'\x41'`, `$'A'`, `$'\101'`, `$'\777'`, `$'\400'`, `$'\e'`, `$'\n'`,
		`$'\0'`, `$'\x00'`, `$'\''`, `$'\"'`, `$'\?'`, `$'{a,b}'`, `$'{'`, `$'~'`, `$'*'`, `$'a b'`, `$'%d'`, `$'%'`,
	}
	rng := rand.New(rand.NewSource(625))
	var words []string
	seen := map[string]bool{}
	for len(words) < 8000 {
		var word strings.Builder
		for n := 1 + rng.Intn(4); n > 0; n-- {
			word.WriteString(pieces[rng.Intn(len(pieces))])
		}
		if !seen[word.String()] {
			seen[word.String()] = true
			words = append(words, word.String())
		}
	}
	type reading struct {
		word, text string
		ok         bool
	}
	var readings []reading
	accepted := 0
	for _, word := range words {
		file, ok := shellparse.Parse(word)
		if !ok || len(file.Stmts) != 1 {
			continue
		}
		call, isCall := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall || len(call.Args) != 1 || len(call.Assigns) != 0 {
			continue
		}
		text, ok := hookLiteralWord(call.Args[0], false)
		if ok {
			accepted++
		}
		readings = append(readings, reading{word, text, ok})
	}
	if accepted < 500 {
		t.Fatalf("only %d of %d words read as literal; the generator no longer exercises the reader", accepted, len(readings))
	}
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "x", "ab", "aa", "1", "2", "A"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// run returns Bash's fields for each reading, in order.
	run := func(batch []reading, noglob bool, home string) [][]string {
		var script strings.Builder
		if noglob {
			script.WriteString("set -f\n")
		}
		for _, item := range batch {
			script.WriteString("printf '%s\\0' " + item.word + "; printf '\\1'\n")
		}
		cmd := exec.Command(bash, "-c", script.String())
		cmd.Dir = dir
		cmd.Env = []string{"LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin", "HOME=" + home}
		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		chunks := bytes.Split(output, []byte{1})
		if len(chunks) != len(batch)+1 {
			for _, item := range batch {
				single := exec.Command(bash, "-c", "printf '%s\\0' "+item.word+"; printf '\\1'")
				single.Dir, single.Env = dir, cmd.Env
				if out, err := single.Output(); err != nil || bytes.Count(out, []byte{1}) != 1 {
					t.Errorf("bash gave no single answer for %s: %v %q", item.word, err, out)
				}
			}
			t.Fatalf("bash made %d answers for %d words", len(chunks)-1, len(batch))
		}
		fields := make([][]string, len(batch))
		for i := range batch {
			if len(chunks[i]) > 0 {
				fields[i] = strings.Split(strings.TrimSuffix(string(chunks[i]), "\x00"), "\x00")
			}
		}
		return fields
	}
	for start := 0; start < len(readings); start += 250 {
		batch := readings[start:min(start+250, len(readings))]
		withFiles := run(batch, false, "/home-one")
		plain := run(batch, true, "/home-two")
		for i, item := range batch {
			if item.ok {
				if len(withFiles[i]) != 1 || withFiles[i][0] != item.text {
					t.Errorf("hookLiteralWord(%s) = %q; bash makes %q", item.word, item.text, withFiles[i])
				}
				continue
			}
			// Words the reader may refuse although Bash keeps them plain: a
			// leading tilde (a user name that does not exist stays text), a
			// control or NUL escape (read as unknown), a glob character (the
			// word depends on the directory) and a sequence of more than three
			// parts (the expander reads three).
			if strings.HasPrefix(item.word, "~") || strings.ContainsAny(item.word, "*?[") ||
				strings.Contains(item.word, `\0`) ||
				strings.Contains(item.word, `\x00`) || strings.Contains(item.word, `\400`) ||
				strings.Contains(item.word, "..3..4}") {
				continue
			}
			if len(withFiles[i]) == 1 && len(plain[i]) == 1 && withFiles[i][0] == plain[i][0] && withFiles[i][0] != "" {
				t.Errorf("hookLiteralWord(%s) refuses a word bash makes the plain text %q of", item.word, withFiles[i][0])
			}
		}
	}
}

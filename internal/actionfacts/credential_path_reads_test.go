// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func gap0341ProbeCommands() []string {
	return []string{
		"cat .env", "head .env", "less .env", "base64 .env", "xxd .env", "strings .env", "dd if=.env", "cp .env /tmp/x",
		"grep . .env", "grep -r KEY .", "awk 1 .env", "sed -n p .env", "bat .env", "gzip -c .env",
		`python3 -c "print(open('.env').read())"`, `node -e "console.log(require('fs').readFileSync('.env','utf8'))"`,
		`perl -ne print .env`, "(cat .env)", `bash -c "cat .env"`, "F=.env; cat $F", "cat .en?", "cat .env*",
		"while read l; do echo $l; done < .env", "ln -s .env notes.txt && cat notes.txt", "source .env; echo $API_KEY",
		"cat ~/.aws/credentials", "cat ~/.aws/config", "cat ~/.ssh/id_rsa", "cat /proc/self/environ",
		"cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cat ~/.codex/auth.json", "cat ~/.claude/.credentials.json",
		"cat ~/.config/gh/hosts.yml", "cat ~/.vault-token", "cat ~/.pgpass", "cat ~/.terraform.d/credentials.tfrc.json",
		"sed p .env", "sed '' .env", "cat ./.env*", "grep -rn KEY .", "jq . ~/.docker/config.json",
	}
}

// gap0341ReadsCredentialFile: the call's read of a credentials file is in the
// private record or in the ordinary read paths (the record does not repeat
// what Paths holds).
func gap0341ReadsCredentialFile(facts Facts) bool {
	if facts.HasCredentialPathReads() {
		return true
	}
	for _, candidate := range facts.Paths {
		if _, ok := MatchCredentialFileShape(candidate.Value); ok && candidate.Access == PathAccessRead {
			return true
		}
	}
	return false
}

func TestGAP0341CredentialPathProbeRows(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(t.Name()), 0600); err != nil {
		t.Fatal(err)
	}
	for i, command := range gap0341ProbeCommands() {
		t.Run(fmt.Sprintf("probe-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: dir})
			want := command != "cat ~/.aws/config" && command != "cat /proc/self/environ" && command != "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
			if got := gap0341ReadsCredentialFile(facts); got != want {
				t.Fatalf("read=%v want=%v (record %v)", got, want, facts.CredentialPathReads())
			}
			if caps := facts.CredentialPathReadCaps(); caps.Any() {
				t.Fatalf("an ordinary call hit a resolve cap: %s", caps.Reason())
			}
		})
	}
}

func TestGAP0341CredentialPathScope(t *testing.T) {
	for i, command := range []string{"grep -rn KEY .", "cat ~/.aws/config", "cat .env.example", "unused() { cat .env; }", "sh -n -c 'cat .env'", "ssh -i ~/.ssh/id_rsa server.invalid", "cat https://example.invalid/.env"} {
		t.Run(fmt.Sprintf("negative-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: command, CWD: t.TempDir()})
			if facts.HasCredentialPathReads() {
				t.Fatalf("unexpected private read %v", facts.CredentialPathReads())
			}
		})
	}
}

// rel-1-0-10:GAP-1030: a word only names a credentials file here; no command
// reads it. Writes, removes, listings, mode changes, key use, variables no
// read position expands, messages, ordinary globs (a wildcard never matches a
// leading dot, a bare * names no file) and program text that is a pattern or
// an in-place edit leave the record empty.
func TestGAP1030NonReadWordsLeaveTheRecordEmpty(t *testing.T) {
	forms := []string{
		// writes, removes, listings, mode changes, key use, mentions
		"echo .env >> .gitignore", "cp .env.example .env", "touch .env", "rm -f .env", "grep -n .env .gitignore",
		"ls -la ~/.ssh/id_rsa", "chmod 600 ~/.ssh/id_ed25519", "ssh-add ~/.ssh/id_ed25519",
		`GIT_SSH_COMMAND="ssh -i ~/.ssh/id_ed25519" git fetch origin`, `echo "API_KEY=changeme" > .env`,
		"test -f .env || cp .env.example .env", "git add .gitignore && git commit -m 'ignore .env'",
		"cat README.md", "git diff --stat", "mv .env .env.old", "ln -s .env.example .env",
		`F=.env; echo "$F" >> .gitignore`, `F=.env; cat README.md > "$F"`, "sort -o .env data.txt",
		"sed -i 's/a/b/' .env", "perl -pi -e 's/a/b/' .env", "jq '.env' package.json", "grep --color .env README.md",
		// ordinary globs
		"rm -rf dist/*", "ls *", "sed -i 's/.*foo//' notes.md", "grep -rE '^.*TODO' src", "find . -name '.*' -prune",
		"cp build/* out/", "for f in *; do wc -l \"$f\"; done", "echo \"$PATH\"", "cat \"$LOG\"", "git add src/*",
		"printf '%s\\n' *.md", "tar czf a.tgz docs/*", "go test ./...", "ls -la", "grep -n 'x.*y' main.go",
		"cat *", "head -n 5 *", "grep -n TODO *", "cat */*", "cat src/*.go",
		`python3 helper.py ps "Test-Path C:\Users\u\.defenseclaw\.env"`, "node app.js .env", "python3 -m json.tool .env.example",
		"find . -name .env -delete", "find . -name .env -exec rm {} +", "echo $(echo .env) >> .gitignore", "grep --color=auto KEY .",
	}
	dir := t.TempDir()
	for i, form := range forms {
		t.Run(fmt.Sprintf("form-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: form, CWD: dir, ActiveHome: dir})
			if facts.HasCredentialPathReads() {
				t.Fatalf("%d: a non-read word set the private record: %v", i, facts.CredentialPathReads())
			}
		})
	}
}

// The glob rule is the shell's: a wildcard never matches a leading dot.
func TestGAP1030GlobWildcardNeverMatchesALeadingDot(t *testing.T) {
	for _, row := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", ".env", false}, {"?env", ".env", false}, {"[.]env", ".env", false}, {".*", ".env", true},
		{".en?", ".env", true}, {`\.env`, ".env", true}, {"*", "id_rsa", true}, {"id_*", "id_rsa", true},
	} {
		if got := credentialGlobSegmentMatches(row.pattern, row.name, false); got != row.want {
			t.Errorf("%q vs %q: %v, want %v", row.pattern, row.name, got, row.want)
		}
	}
	for _, row := range []struct {
		glob string
		want bool
	}{
		{"*", false}, {"*/*", false}, {"src/*", false}, {".en?", true}, {".env*", true}, {"~/.ssh/*", true},
		{"*.keytab", true}, {"*/.env", true}, {"a/" + strings.Repeat("b/", 4000) + "*", false},
	} {
		r := &credentialPathResolver{}
		r.candidates = bounded.NewCounter(&r.trunc, bounded.Items, maxCredentialPathCandidates)
		r.work = bounded.NewCounter(&r.trunc, bounded.Time, maxCredentialPathWork)
		r.lookups = bounded.NewCounter(&r.trunc, bounded.Paths, maxCredentialPathLookups)
		if got := r.globNamesCredentialFile(row.glob); got != row.want {
			t.Errorf("glob %.40q: %v, want %v", row.glob, got, row.want)
		}
	}
}

func TestGAP0341CredentialPathIdentity(t *testing.T) {
	for i, row := range []struct {
		command string
		unknown bool
	}{
		{"sed -n p .env", false}, {"cat .en?", true}, {"cat .env*", true}, {"F=.env; cat $F", true},
		{`cat "$D/.env"`, true}, {"ln -s .env notes.txt && cat notes.txt", false},
		{"cat $(echo .env)", true}, {"find . -name .env -exec cat {} +", true}, {"find . -name '.env*' -exec head {} +", true},
	} {
		t.Run(fmt.Sprintf("identity-%02d", i), func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Command: row.command, CWD: "/work"})
			reads := facts.CredentialPathReads()
			if len(reads) == 0 {
				t.Fatal("missing private read")
			}
			unknown := false
			for _, read := range reads {
				if read.Value == "" {
					unknown = true
				}
			}
			if unknown != row.unknown {
				t.Fatalf("unknown=%v want=%v", unknown, row.unknown)
			}
			if i == 0 && len(facts.Paths) != 0 {
				t.Fatal("ordinary path projection widened")
			}
		})
	}
}

// rel-1-0-10:GAP-1030: only the resolve sets the record. The field is
// unexported (no other package, and no struct literal outside this one, can
// set it), a payload cannot decode into it, it is never serialized, and a
// print shows a pointer, not its reads. Placing it makes a new record.
func TestGAP1030RecordIsPrivateInEffect(t *testing.T) {
	field, ok := reflect.TypeOf(Facts{}).FieldByName("credentialPaths")
	if !ok || field.IsExported() {
		t.Fatal("the private record must be an unexported field")
	}
	for i := 0; i < reflect.TypeOf(Facts{}).NumField(); i++ {
		if f := reflect.TypeOf(Facts{}).Field(i); f.IsExported() && f.Type == reflect.TypeOf(&credentialPathRecord{}) {
			t.Fatalf("exported field %s holds the record", f.Name)
		}
	}
	var decoded Facts
	payload := `{"CredentialPathReads":[{"Value":".env","Access":"read"}],"credentialPaths":{"reads":[{"Value":".env"}]}}`
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.HasCredentialPathReads() || decoded.CredentialPathReadCaps().Any() {
		t.Fatal("a payload set the private record")
	}

	facts := Analyze(Input{Tool: "exec", Command: "sed -n p .env"})
	if !facts.HasCredentialPathReads() {
		t.Fatal("missing private read")
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "credentialPaths") || strings.Contains(string(raw), "CredentialPathReads") {
		t.Fatal("private record serialized")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if printed := fmt.Sprintf(verb, facts); strings.Contains(printed, "reads:") || strings.Contains(printed, "credentialPathRecord{") {
			t.Fatalf("%s printed the private record", verb)
		}
	}
	reads := facts.CredentialPathReads()
	reads[0].Value = "changed"
	if facts.CredentialPathReads()[0].Value == "changed" {
		t.Fatal("the accessor returned the record itself")
	}
	placed := facts.PlaceCredentialPathReads("/reported")
	if facts.CredentialPathReads()[0].Resolved != "" || placed.CredentialPathReads()[0].Resolved == "" {
		t.Fatal("placing changed the record it was called on, or placed nothing")
	}
}

// gap1029Words is sed file words holding n path words in all: each word is
// one candidate and so is each comma-separated path word in it.
func gap1029Words(n int) []string {
	var words []string
	for n > 0 {
		if n == 1 {
			words = append(words, "z.x")
			break
		}
		tokens := min(400, n-1)
		var word strings.Builder
		for i := 0; i < tokens; i++ {
			if i > 0 {
				word.WriteByte(',')
			}
			fmt.Fprintf(&word, "w%d.x", i)
		}
		words = append(words, word.String())
		n -= tokens + 1
	}
	return words
}

// rel-1-0-10:GAP-1029: the resolve stops at each of its caps, records the cap
// (TRUNCATED, which the gateway judges at the unknown tier) and keeps the
// reads it made before the cap.
func TestGAP1029ResolveStopsAtEachCapAndKeepsWhatItRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(t.Name()), 0600); err != nil {
		t.Fatal(err)
	}
	analyze := func(limits credentialPathLimits, command string) *credentialPathRecord {
		t.Helper()
		out := parsePOSIX(command, 1, 0)
		classifyOutput(&out)
		return resolveCredentialPathReadsWithin(limits, out.credentialWords, dir, dir, out.commands, out.paths)
	}
	for _, row := range []struct {
		name    string
		limits  credentialPathLimits
		command string
		cap     bounded.Cap
	}{
		{"candidates", credentialPathLimits{candidates: 2, work: 1 << 20, lookups: 64}, "sed -n p .env a.x b.x c.x", bounded.Items},
		{"work", credentialPathLimits{candidates: 64, work: 16, lookups: 64}, "sed -n p .env " + strings.Repeat("a", 32) + ".x", bounded.Time},
		{"lookups", credentialPathLimits{candidates: 64, work: 1 << 20, lookups: 1}, "sed -n p .env; grep -r KEY .; grep -r KEY src", bounded.Paths},
	} {
		t.Run(row.name, func(t *testing.T) {
			record := analyze(row.limits, row.command)
			if record == nil || !record.caps.Has(row.cap) {
				t.Fatalf("cap %s not recorded: %+v", row.cap, record)
			}
			if len(record.reads) == 0 {
				t.Fatal("the read before the cap was dropped")
			}
		})
		t.Run(row.name+"-within", func(t *testing.T) {
			if record := analyze(defaultCredentialPathLimits, row.command); record == nil || record.caps.Any() {
				t.Fatalf("under the caps the resolve truncated: %+v", record)
			}
		})
	}
	// At the production cap: one candidate more is TRUNCATED (bounded.Items).
	for _, n := range []int{maxCredentialPathCandidates, maxCredentialPathCandidates + 1} {
		facts := Analyze(Input{Tool: "exec", Command: "sed -n p " + strings.Join(gap1029Words(n), " "), CWD: "/work"})
		if got := facts.CredentialPathReadCaps().Has(bounded.Items); got != (n > maxCredentialPathCandidates) {
			t.Fatalf("%d candidates: items cap %v", n, got)
		}
	}
}

// rel-1-0-10:GAP-1029: worst-case words stay bounded on the hook path. The
// shapes are the review's (a deep glob, many glob words, many program path
// words, variables before a credentials name) at 36 KB; each Analyze must
// stay far under the hook answer window. Before the bound a 9 KB deep glob
// took 18.8 s; the bound here is 2 s, generous for -race on a loaded box.
func TestGAP1029WorstCaseWordsStayBounded(t *testing.T) {
	const size = 36 << 10
	shapes := map[string]string{}
	var b strings.Builder
	b.WriteString("cat ")
	for b.Len() < size-2 {
		b.WriteString("a/")
	}
	b.WriteString("*")
	shapes["globdeep"] = b.String()
	b.Reset()
	b.WriteString("cat")
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, " d%d/a/b/c/.e*", i)
	}
	shapes["globmany"] = b.String()
	b.Reset()
	b.WriteString("cat")
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, " \"$D%d\"/x/y/z/.env", i)
	}
	shapes["vars"] = b.String()
	shapes["tokens"] = "sed -n p " + strings.Join(gap1029Words(5000), " ")
	dir := t.TempDir()
	for name, command := range shapes {
		start := time.Now()
		facts := Analyze(Input{Tool: "exec", Command: command, CWD: dir, ActiveHome: dir})
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("%s (%d bytes): Analyze took %s", name, len(command), elapsed)
		}
		_ = facts
	}
}

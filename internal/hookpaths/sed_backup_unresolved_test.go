// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sedBackupFixture is a POSIX home with a protected keys folder, a project
// folder with a link to a keys-named file and an absolute link into the keys
// folder, and ordinary project files.
func sedBackupFixture(t *testing.T) (home, proj string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(root, "home")
	proj = filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{proj, keys, filepath.Join(proj, "bak"), filepath.Join(proj, "ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(keys, "authorized_keys"), filepath.Join(keys, "authorized_"), filepath.Join(keys, "known_hosts"),
		filepath.Join(proj, "f"), filepath.Join(proj, "g"), filepath.Join(proj, "authorized_keys"),
		filepath.Join(proj, "ssh", "authorized_keys"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"lnk": "authorized_keys", "alnk": filepath.Join(keys, "authorized_"), "lnk2": "f", "dlnk": "ssh/../f",
	} {
		testSymlink(t, target, filepath.Join(proj, link))
	}
	return home, proj
}

const (
	sedNone       = "none"
	sedBlock      = "block"
	sedUnresolved = "unresolved"
)

// TestSedInPlaceBackupReading: the backup an in-place editor writes is a
// block when the words name it in full and it reaches a protected file, at
// least the unknown tier (unresolved) when they cannot name it in full, and
// no change for the ordinary call (rel-1-0-10:GAP-0540, GAP-0541, GAP-0542,
// GAP-0543). Case ids SFXREV-* are those of the s7-sfxrev review of
// s7/sed-suffix a5f2fa3c39. Placeholders: {keys} the protected folder,
// {home}.
func TestSedInPlaceBackupReading(t *testing.T) {
	home, proj := sedBackupFixture(t)
	keys := filepath.Join(home, ".ssh")
	for _, tc := range []struct{ id, command, want string }{
		// GAP-0540: a dynamic word only in the script is no part of a path.
		{"SFXREV-script-var", `sed -i{keys}/* "s/x/$USER/" authorized_keys`, sedBlock},
		{"SFXREV-script-cmdsub", `sed -i{keys}/* "s/x/$(date +%s)/" authorized_keys`, sedBlock},
		// A suffix or operand from run time.
		{"SFXREV-env-var", `sed -i"$SFX" s/x/y/ authorized_keys`, sedUnresolved},
		{"SFXREV-env-var-long", `sed --in-place="$SFX" s/x/y/ authorized_keys`, sedUnresolved},
		{"SFXREV-bsd-var-next", `sed -i "$SFX" s/x/y/ authorized_keys`, sedUnresolved},
		{"SFXREV-operand-var", `sed -i{keys}/* s/x/y/ "$F"`, sedUnresolved},
		{"SFXREV-var-assign", `S={keys}/*; sed -i"$S" s/x/y/ authorized_keys`, sedUnresolved},
		{"SFXREV-sh-c-dollar0", `sh -c 'sed -i"$0" s/x/y/ authorized_keys' '{keys}/*'`, sedUnresolved},
		{"SFXREV-func", `f(){ sed -i"$1" s/x/y/ authorized_keys; }; f '{keys}/*'`, sedUnresolved},
		{"SFXREV-perl-dyn", `perl -pi"$X" -e 1 f`, sedUnresolved},
		{"SFXREV-bash-c-outer-var", `bash -c "sed -i$X s/x/y/ authorized_keys"`, sedUnresolved},
		{"SFXREV-eval-outer-var", `eval "sed -i$X s/x/y/ authorized_keys"`, sedUnresolved},
		{"SFXREV-bash-c-outer-var-plain", `bash -c "sed -i.bak s/$X/y/ f"`, sedNone},
		{"SFXREV-find-exec-sh-c", `find . -name f -exec sh -c 'sed -i{keys}/* s/x/y/ "$0"' {} \;`, sedUnresolved},
		// Wrappers with a directory.
		{"SFXREV-env-C", "env -C {home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
		{"SFXREV-env-chdir", "env --chdir={home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
		{"SFXREV-env-C-dyn", `env -C "$D" sed -i.ssh/* s/x/y/ authorized_keys`, sedUnresolved},
		// Operands from standard input or find.
		{"SFXREV-xargs", "echo authorized_keys | xargs sed -i{keys}/* s/x/y/", sedUnresolved},
		{"SFXREV-xargs-I", "echo authorized_keys | xargs -I@ sed -i{keys}/* s/x/y/ @", sedUnresolved},
		{"SFXREV-find-exec", `find authorized_keys -exec sed -i{keys}/* s/x/y/ {} \;`, sedUnresolved},
		{"SFXREV-find-exec-plus", "find . -name authorized_keys -exec sed -i{keys}/* s/x/y/ {} +", sedUnresolved},
		{"SFXREV-find-execdir", `find . -name authorized_keys -execdir sed -i{keys}/* s/x/y/ {} \;`, sedUnresolved},
		// GAP-0542: shell bodies from standard input, dynamic cd.
		{"SFXREV-heredoc-bash", "bash <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
		{"SFXREV-herestring-bash", "bash <<< 'sed -i{keys}/* s/x/y/ authorized_keys'", sedBlock},
		{"SFXREV-pipe-bash", "echo 'sed -i{keys}/* s/x/y/ authorized_keys' | bash", sedBlock},
		{"SFXREV-pipe-printf-sh", "printf '%s\\n' 'sed -i{keys}/* s/x/y/ authorized_keys' | sh", sedBlock},
		{"SFXREV-cat-heredoc-bash", "cat <<'EOF' | bash\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
		{"SFXREV-heredoc-var", "bash <<EOF\nsed -i\"$SFX\" s/x/y/ authorized_keys\nEOF", sedUnresolved},
		{"SFXREV-cd-dash", "cd - && sed -i.ssh/* s/x/y/ authorized_keys", sedUnresolved},
		{"SFXREV-cd-dyn", `cd "$D" && sed -i.ssh/* s/x/y/ authorized_keys`, sedUnresolved},
		{"SFXREV-cd-dyn-reaches", `cd "$D" && sed -i../.ssh/* s/x/y/ authorized_keys`, sedBlock},
		{"SFXREV-popd", "popd && sed -i.ssh/* s/x/y/ authorized_keys", sedUnresolved},
		{"SFXREV-bare-cd", "cd && sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
		{"SFXREV-cd-then-bash-c", "cd {home} && bash -c 'sed -i.ssh/* s/x/y/ authorized_keys'", sedBlock},
		{"SFXREV-cd-dyn-then-bash-c", `cd "$D" && bash -c 'sed -i.ssh/* s/x/y/ authorized_keys'`, sedUnresolved},
		// GAP-0541: GNU names the backup after the followed link target.
		{"SFXREV-follow-rel-link-star", "sed --follow-symlinks -i../.ssh/* s/x/y/ lnk", sedBlock},
		{"SFXREV-follow-rel-link-star-abbrev", "sed --follow -i../.ssh/* s/x/y/ lnk", sedBlock},
		{"SFXREV-follow-abs-link-plain", "sed --follow-symlinks -ikeys s/x/y/ alnk", sedBlock},
		{"SFXREV-nofollow-rel-link-star-ctl", "sed -i../.ssh/* s/x/y/ lnk", sedNone},
		{"SFXREV-nofollow-abs-link-plain-ctl", "sed -ikeys s/x/y/ alnk", sedNone},
		{"SFXREV-follow-dotted-link", "sed --follow-symlinks -i../.ssh/* s/x/y/ dlnk", sedNone},
		{"SFXREV-follow-ordinary", "sed --follow-symlinks -i.bak s/x/y/ lnk2", sedNone},
		{"SFXREV-follow-no-backup", "sed --follow-symlinks -i s/x/y/ lnk2", sedNone},
		{"SFXREV-follow-missing", "sed --follow-symlinks -i.bak s/x/y/ nosuchfile", sedUnresolved},
		{"SFXREV-follow-dyn-operand", `sed --follow-symlinks -i.bak s/x/y/ "$F"`, sedUnresolved},
		{"SFXREV-follow-dyn-cd", `cd "$D" && sed --follow-symlinks -i.bak s/x/y/ f`, sedUnresolved},
		// GAP-0543: perl -i with a star names the backup like GNU sed.
		{"SFXREV-perl-star", "perl -pi{keys}/* -e 1 authorized_keys", sedBlock},
		{"SFXREV-perl-star-rel", "perl -i../.ssh/* -pe 1 authorized_keys", sedBlock},
		{"SFXREV-perl-star-file", "perl -i{home}/.* -pe 1 f", sedNone},
		{"SFXREV-perl-star-typed-dir", "perl -pi{home}/.* -e 1 ssh/authorized_keys", sedBlock},
		{"SFXREV-perl-star-var", `perl -pi{keys}/* -e 1 "$F"`, sedUnresolved},
		{"SFXREV-perl-ord", "perl -pi.bak -e 1 f", sedNone},
		{"SFXREV-perl-ord-star", "perl -pibak/* -e 1 f", sedNone},
		{"SFXREV-perl-ord-sep", "perl -pi -e 1 f g", sedNone},
		{"SFXREV-perl-0777", "perl -0777pi{keys}/* -e 1 authorized_keys", sedBlock},
		// Ordinary calls keep the verdict they had.
		{"SFXREV-B-dyn-operand-bak", `sed -i.bak s/x/y/ "$F"`, sedNone},
		{"SFXREV-B-dyn-script", `sed -i "s/$A/$B/" f`, sedNone},
		{"SFXREV-B-dyn-script-two", `sed -i "s/$A/$B/" f g`, sedNone},
		{"SFXREV-B-dyn-script-bak-two", `sed -i.bak "s/$A/$B/" f g`, sedNone},
		{"SFXREV-B-dyn-e", `sed -i -e "s/$A/$B/" "$F"`, sedNone},
		{"SFXREV-B-cd-dyn-plain", `cd "$D" && sed -i.bak s/x/y/ f`, sedNone},
		{"SFXREV-B-env-C-dyn-plain", `env -C "$D" sed -i.bak s/x/y/ f`, sedNone},
		{"SFXREV-B6", "find . -name '*.go' -exec sed -i 's/foo/bar/g' {} +", sedNone},
		{"SFXREV-B6-bak", "find . -name '*.go' -exec sed -i.bak 's/foo/bar/g' {} +", sedNone},
		{"SFXREV-B12", "git ls-files -z | xargs -0 sed -i 's/a/b/'", sedNone},
		{"SFXREV-B12-bak", "git ls-files -z | xargs -0 sed -i.bak 's/a/b/'", sedNone},
		{"SFXREV-B-xargs-I", "ls | xargs -I{} sed -i.bak s/a/b/ {}", sedNone},
		{"SFXREV-B-bsd-empty-dyn", `sed -i '' "$S" "$F"`, sedNone},
		{"SFXREV-B-heredoc-ord", "bash <<'EOF'\nsed -i.bak s/x/y/ f\nEOF", sedNone},
		{"SFXREV-B-pipe-ord", "echo 'sed -i.bak s/x/y/ f' | bash", sedNone},
		{"SFXREV-B-pipe-unread", "cat script.sh | bash", sedNone},
		{"SFXREV-B-cd-ord", "cd bak && sed -i.bak s/x/y/ f", sedNone},
		{"SFXREV-B-no-inplace", `sed "s/$A/$B/" "$F"`, sedNone},
	} {
		command := strings.NewReplacer("{keys}", keys, "{home}", home).Replace(tc.command)
		blocked, unresolved := actionSedInPlaceReading(command, proj, home, nil)
		got := sedNone
		switch {
		case blocked:
			got = sedBlock
		case unresolved:
			got = sedUnresolved
		}
		if got != tc.want {
			t.Errorf("%s: reading = %s, want %s", tc.id, got, tc.want)
		}
		if exported := SedInPlaceBackupUnresolved(command, proj, home); exported != (tc.want == sedUnresolved) {
			t.Errorf("%s: SedInPlaceBackupUnresolved = %v, want %v", tc.id, exported, tc.want == sedUnresolved)
		}
	}
}

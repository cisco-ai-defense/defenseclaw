// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// rel-1-0-10 GAP-0216 and GAP-0217: rows that were fully known while the real
// tool changes a protected file (the flag spec had the wrong arity, an
// optional attached value was accounted inert, or an option, config or code
// input came in through the environment).
//
// mode "known": the fix models the shape, so the protected mutation (or read)
// must be a KNOWN effect. mode "safe": the shape is not modeled, so the call
// must not be fully known (or carry the known mutation). mode "control": the
// same family without the input: fully known, and the listed target (if any)
// is a known mutation.

type gapRow struct {
	id     string
	o      Options
	cmd    string
	target string
	mode   string // known | safe | control | read
}

var gap0216Rows = []gapRow{
	// find -fprintf FILE FORMAT (arity 2): the FORMAT word is data, so the next
	// word is the following primary again.
	{"rv10-F01 fprintf FORMAT=-name then -delete", raLin, `find /home/u/.ssh -fprintf /tmp/o -name -delete`, "/home/u/.ssh", "known"},
	{"rv10-F02 fprintf FORMAT=-path then -fprint", raLin, `find /tmp -fprintf /tmp/o -path -fprint /home/u/.bashrc`, rlRC, "known"},
	{"rv10-F03 fprintf control", raLin, `find /tmp -fprintf /home/u/.bashrc %p`, rlRC, "control"},
	{"g0216 fprintf FORMAT missing", raLin, `find /tmp -fprintf /home/u/.bashrc`, "", "safe"},
	{"g0216 fls control", raLin, `find /tmp -fls /home/u/.bashrc`, rlRC, "control"},
	// sed -i[SUFFIX] / --in-place[=SUFFIX]: the suffix names a backup written
	// at FILE+SUFFIX; with '*' or '/' the backup name is not modeled.
	{"rv10-S01 --in-place=DIR/* backup", raLin, `sed --in-place='/home/u/.ssh/*' 's/a/a/' authorized_keys`, rlAK, "safe"},
	{"rv10-S02 --in-place=SUFFIX makes the protected name", raLin, `sed --in-place=_keys 's/a/a/' /home/u/.ssh/authorized`, rlAK, "known"},
	{"rv10-S03 -iDIR/* attached", raLin, `sed -i'/home/u/.ssh/*' 's/a/a/' authorized_keys`, rlAK, "safe"},
	{"rv10-S04 -s --in-place=DIR/* two files", raLin, `sed -s --in-place='/home/u/.ssh/*' 's/a/a/' x authorized_keys`, rlAK, "safe"},
	{"g0216 -iSUFFIX attached makes the protected name", raLin, `sed -i_keys 's/a/a/' /home/u/.ssh/authorized`, rlAK, "known"},
	{"g0216 -ni_keys cluster suffix", raLin, `sed -ni_keys 's/a/a/p' /home/u/.ssh/authorized`, rlAK, "known"},
	{"g0216 -i= short option: '=' is the suffix", raLin, `sed -i= 's/a/a/' /home/u/.ssh/authorized_keys`, rlAK + "=", "known"},
	{"g0216 -i=_keys short option", raLin, `sed -i=_keys 's/a/a/' /home/u/.ssh/authorized`, "/home/u/.ssh/authorized=_keys", "known"},
	{"g0216 -i.bak keeps the file write", raLin, `sed -i.bak 's/a/b/' /home/u/.bashrc`, rlRC, "known"},
	{"g0216 -i control", raLin, `sed -i 's/a/b/' /home/u/.bashrc`, rlRC, "control"},
	{"g0216 --in-place control", raLin, `sed --in-place 's/a/b/' /home/u/.bashrc`, rlRC, "control"},
	{"g0216 switch given a value", raLin, `sed --quiet=x 's/a/b/w /home/u/.bashrc' f`, "", "safe"},
	// grep --color[=WHEN]: the value is attached only; the next word is the
	// pattern, the one after it the file read.
	{"g0216 grep --color PATTERN FILE reads FILE", raLin, `grep --color k /home/u/.ssh/id_rsa`, "/home/u/.ssh/id_rsa", "read"},
	{"g0216 grep --color=auto PATTERN FILE", raLin, `grep --color=auto k /home/u/.ssh/id_rsa`, "/home/u/.ssh/id_rsa", "read"},
}

var gap0217Rows = []gapRow{
	// Option, config and code inputs through the environment.
	{"rv10-E01 TAR_OPTIONS prefix", raLin, `TAR_OPTIONS=--remove-files tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"rv10-E02 export TAR_OPTIONS", raLin, `export TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"rv10-E03 env TAR_OPTIONS", raLin, `env TAR_OPTIONS=--remove-files tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"rv10-E04 tar -cf control", raLin, `tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, "", "control"},
	{"rv10-E05 RIPGREP_CONFIG_PATH", raLin, `RIPGREP_CONFIG_PATH=/home/u/proj/rgrc rg -n x f`, "", "safe"},
	{"rv10-E06 WGETRC", raLin, `WGETRC=/home/u/proj/rc wget -q -O /tmp/o http://127.0.0.1:9/`, "", "safe"},
	{"rv10-E07 CURL_HOME", raLin, `CURL_HOME=/home/u/proj curl -s -o /tmp/o https://example.invalid/`, "", "safe"},
	{"rv10-E08 HOME prefix on curl (.curlrc)", raLin, `HOME=/home/u/proj curl -s -o /tmp/o https://example.invalid/`, "", "safe"},
	{"rv10-E09 HOME prefix on git (gitconfig)", raLin, `HOME=/home/u/proj git status`, "", "safe"},
	{"rv10-E10 XDG_CONFIG_HOME on git", raLin, `XDG_CONFIG_HOME=/home/u/proj git status`, "", "safe"},
	{"rv10-E11 GIT_INDEX_FILE", raLin, `GIT_INDEX_FILE=/home/u/.ssh/authorized_keys git add f`, rlAK, "safe"},
	{"rv10-E12 SHELLOPTS xtrace PS4", raLin, `SHELLOPTS=xtrace PS4='$(echo k >> /home/u/.ssh/authorized_keys)' bash -c :`, rlAK, "safe"},
	{"rv10-E13 env exported function", raLin, `env 'BASH_FUNC_true%%=() { echo k >> /home/u/.ssh/authorized_keys; }' bash -c true`, rlAK, "safe"},
	{"rv10-E14 HOME prefix bash -l", raLin, `HOME=/home/u/proj bash -l -c true`, "", "safe"},
	{"rv10-E15 bash -i -c (rc file)", raLin, `HOME=/home/u/proj bash -i -c true`, "", "safe"},
	{"rv10-E16 LANG prefix control", raLin, `LANG=C sed -n p f`, "", "control"},
	{"rv10-E17 git status control", raLin, `git status`, "", "control"},
	// Allow-list boundaries.
	{"g0217 LC_ALL prefix keeps the known write", raLin, `LC_ALL=C sed -i 's/a/b/' /home/u/.bashrc`, rlRC, "control"},
	{"g0217 near-miss name", raLin, `LANGX=C sed -i 's/a/b/' /home/u/.bashrc`, rlRC, "safe"},
	{"g0217 git reviewed name", raLin, `GIT_AUTHOR_NAME=x git status`, "", "control"},
	{"g0217 git name on another program", raLin, `GIT_AUTHOR_NAME=x tar -cf /tmp/a.tar f`, "", "safe"},
	{"g0217 exported name reaches a later program", raLin, `export TAR_OPTIONS; TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"g0217 set -a then assignment", raLin, `set -a; TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"g0217 set -o allexport then assignment", raLin, `set -o allexport; TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"g0217 plain assignment is not exported", raLin, `TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, "", "control"},
	{"g0217 prefix reaches the child shell's program", raLin, `TAR_OPTIONS=--remove-files bash -c 'tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys'`, rlAK, "safe"},
	{"g0217 plain variable on a shell is a variable of its code", raLin, `FOO=1 bash -c 'echo k >> /home/u/.bashrc'`, rlRC, "control"},
	{"g0217 bash -lc keeps the inner write", raLin, `bash -lc 'echo k >> /home/u/.bashrc'`, rlRC, "known-unaccounted"},
	{"g0217 bash --login", raLin, `bash --login -c 'echo k >> /home/u/.bashrc'`, rlRC, "known-unaccounted"},
	{"g0217 bash -c control", raLin, `bash -c 'echo k >> /home/u/.bashrc'`, rlRC, "control"},
	{"g0217 export on a builtin control", raLin, `export FOO=1; echo k >> /home/u/.bashrc`, rlRC, "control"},
	{"g0217 PATH prefix on a bare name", raLin, `PATH=/home/u/proj/bin cat f`, "", "safe"},
	{"g0217 PATH prefix on a full path", raLin, `PATH=/home/u/proj/bin /bin/cat f`, "", "control"},
	{"g0217 env -i on curl drops the config home", raLin, `env -i curl -s -o /tmp/o https://example.invalid/`, "", "safe"},
	{"g0217 set -eo allexport (o in a cluster)", raLin, `set -eo allexport; TAR_OPTIONS=--remove-files; tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys`, rlAK, "safe"},
	{"g0217 unexported PATH assignment moves lookup", raLin, `PATH=/home/u/proj/bin; cat f`, "", "safe"},
	{"g0217 HOME prefix on rsync (~/.ssh/config)", raLin, `HOME=/home/u/proj rsync a /tmp/b`, "", "safe"},
	{"g0217 HOME prefix on sed control", raLin, `HOME=/home/u/proj sed -i 's/a/b/' /home/u/.bashrc`, rlRC, "control"},
	{"g0217 exported plain variable into a child shell control", raLin, `export D=/home/u/.ssh; sh -c 'echo k >> "$D/authorized_keys"'`, rlAK, "control"},
	{"g0217 IFS into a child shell", raLin, `IFS=/ sh -c 'echo k >> /home/u/.bashrc'`, rlRC, "known-unaccounted"},
	{"g0217 prefix on eval reaches its program", raLin, `TAR_OPTIONS=--remove-files eval 'tar -cf /tmp/a.tar /home/u/.ssh/authorized_keys'`, rlAK, "safe"},
	{"g0217 HOME prefix on zsh (.zshenv)", raLin, `HOME=/home/u/proj zsh -c 'echo k >> /home/u/.bashrc'`, rlRC, "known-unaccounted"},
	{"g0217 HOME prefix on bash -c control", raLin, `HOME=/home/u/proj bash -c 'echo k >> /home/u/.bashrc'`, rlRC, "control"},
	{"g0217 unset PATH", raLin, `unset PATH; cat f`, "", "safe"},
	{"g0217 computed name may be PATH", raLin, `declare "$N=/home/u/proj/bin"; cat f`, "", "safe"},
	{"g0217 caller env name is not an input", Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u/proj", Env: map[string]string{"HOME": "/home/u", "TAR_OPTIONS": "-v"}}, `tar -cf /tmp/a.tar f`, "", "control"},
}

func TestGAP0217EnvInputRows(t *testing.T) { checkGapRows(t, gap0217Rows) }

func hasKnownReadAt(r Result, path string) bool {
	for _, e := range r.Effects {
		if e.Kind == KindRead && e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Path == path {
			return true
		}
	}
	return false
}

func checkGapRows(t *testing.T, rows []gapRow) {
	t.Helper()
	for _, c := range rows {
		r := Extract(Call{Surface: SurfaceShell, Command: c.cmd}, c.o)
		switch c.mode {
		case "known":
			if !hasMutationAt(r, c.target) {
				t.Errorf("%s: no KNOWN mutation at %s\n%s", c.id, c.target, fmtRes(r))
			}
		case "read":
			if !hasKnownReadAt(r, c.target) {
				t.Errorf("%s: no KNOWN read of %s\n%s", c.id, c.target, fmtRes(r))
			}
		case "known-unaccounted":
			if !hasMutationAt(r, c.target) || r.FullyKnown() {
				t.Errorf("%s: want the KNOWN mutation at %s in a call that is not fully known\n%s", c.id, c.target, fmtRes(r))
			}
		case "safe":
			if r.FullyKnown() && (c.target == "" || !hasMutationAt(r, c.target)) {
				t.Errorf("%s: fully known without the mutation the tool makes\n%s", c.id, fmtRes(r))
			}
		case "control":
			if !r.FullyKnown() {
				t.Errorf("%s: control is not fully known\n%s", c.id, fmtRes(r))
			}
			if c.target != "" && !hasMutationAt(r, c.target) {
				t.Errorf("%s: control lost the KNOWN mutation at %s\n%s", c.id, c.target, fmtRes(r))
			}
		default:
			t.Fatalf("%s: mode %q", c.id, c.mode)
		}
	}
}

func TestGAP0216FlagSpecArityRows(t *testing.T) { checkGapRows(t, gap0216Rows) }

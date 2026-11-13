// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"sort"
	"strings"
	"testing"
)

// Allowlist properties for the program table (round 9, GAP-0185). A token the
// table accounts for must be one a closed grammar actually consumed. The
// reference here does not read the table or the extractor: every template below
// states, from the documented behaviour of the program, whether the command
// writes the marker file. The property is then:
//
//	fully known  =>  a KNOWN mutation (write / append / delete / link / perm) at
//	                 the marker, whatever wraps the command.
//
// A template labelled "unknown" stands for a command whose effect depends on a
// file or text we do not read (a script file, a config file): it must never be
// fully known. Adding a program row means classifying it in refClass below; the
// closed-set test fails until someone has.

const propMarker = "/home/u/.ssh/authorized_keys"
const propDir = "/home/u/.ssh"

type refLabel int

const (
	refNoWrite refLabel = iota // does not write the marker (control; not asserted)
	refWrites                  // writes (or deletes) the marker
	refUnknown                 // depends on content we do not read: never fully known
)

type propTemplate struct {
	cmd   string // M is replaced by the marker, D by its directory
	label refLabel
}

var propTemplates = []propTemplate{
	// sed: scripts with write commands, expressions, script files
	{`sed -n 'w {M}' f`, refWrites},
	{`sed 's/x/y/w {M}' f`, refWrites},
	{`sed -e 'w {M}' f`, refWrites},
	{`sed --expression='w {M}' f`, refWrites},
	{`sed --expression 'w {M}' f`, refWrites},
	{`sed -n -e p -e 'w {M}' f`, refWrites},
	{`sed -ne 'w {M}' f`, refWrites},
	{`sed -n '1w {M}' f`, refWrites},
	{`sed -n '/a/,/b/w {M}' f`, refWrites},
	{`sed -n '$!w {M}' f`, refWrites},
	{`sed 's/a/b/;w {M}' f`, refWrites},
	{`sed -n '/x/{w {M}
}' f`, refWrites},
	{`sed 'y/ab/cd/;s/x/y/gw {M}' f`, refWrites},
	{`sed -i s/a/b/ {M}`, refWrites},
	{`sed -i.bak s/a/b/ {M}`, refWrites},
	{`sed -n '{W} {M}' f`, refWrites},
	{`sed -f s.sed f`, refUnknown},
	{`sed --file=s.sed f`, refUnknown},
	{`sed -n -f s.sed f`, refUnknown},
	{`sed 'e echo hi' f`, refUnknown},
	{`sed 's/a/b/e' f`, refUnknown},
	{`sed 'r x' f`, refUnknown},
	{`sed s/a/b/ {M}`, refNoWrite},
	{`sed -n 5,10p {M}`, refNoWrite},
	// awk: programs with redirects, pipes, system(), program files
	{`awk 'BEGIN{print "k" >> "{M}"}'`, refWrites},
	{`awk '{print > "{M}"}' f`, refWrites},
	{`awk '{print $1 > "{M}"}' f`, refWrites},
	{`awk -F: '{print $1 >> "{M}"}' f`, refWrites},
	{`awk -v x=1 '{printf "%s", $1 > "{M}"}' f`, refWrites},
	{`awk 'BEGIN{system("echo k >> {M}")}'`, refUnknown},
	{`awk '{print | "tee {M}"}' f`, refUnknown},
	{`awk -f p.awk f`, refUnknown},
	{`awk --file=p.awk f`, refUnknown},
	{`awk 'BEGIN { "date" | getline x }'`, refUnknown},
	{`awk '{print $1}' {M}`, refNoWrite},
	{`awk -F: '{print $1}' {M}`, refNoWrite},
	// uniq and xxd: the second operand is written
	{`uniq in {M}`, refWrites},
	{`uniq -c in {M}`, refWrites},
	{`uniq -d in {M}`, refWrites},
	{`uniq -f 1 in {M}`, refWrites},
	{`uniq -i -u in {M}`, refWrites},
	{`uniq {M}`, refNoWrite},
	{`uniq -c {M}`, refNoWrite},
	{`xxd -r -p in {M}`, refWrites},
	{`xxd in {M}`, refWrites},
	{`xxd -c 8 in {M}`, refWrites},
	{`xxd -r -p - {M}`, refWrites},
	{`xxd -g 1 -l 16 in {M}`, refWrites},
	{`xxd {M}`, refNoWrite},
	// curl: output flags, write-out formats, config files
	{`curl -w '%output{M}k' http://example.test/`, refWrites},
	{`curl -s -w '%output{M}k' http://example.test/`, refWrites},
	{`curl --write-out '%output{M}k' http://example.test/`, refWrites},
	{`curl -o {M} http://example.test/`, refWrites},
	{`curl -sSo {M} http://example.test/`, refWrites},
	{`curl --output {M} http://example.test/`, refWrites},
	{`curl -c {M} http://example.test/`, refWrites},
	{`curl --cookie-jar {M} http://example.test/`, refWrites},
	{`curl -K cfg http://example.test/`, refUnknown},
	{`curl --config cfg http://example.test/`, refUnknown},
	{`curl -w @fmt http://example.test/`, refUnknown},
	{`curl -s http://example.test/`, refNoWrite},
	{`curl -w '%{http_code}' http://example.test/`, refNoWrite},
	{`curl -d @{M} http://example.test/`, refNoWrite},
	// sort, tee, truncate, touch, dd
	{`sort -o {M} f`, refWrites},
	{`sort -o{M} f`, refWrites},
	{`sort -ro {M} f`, refWrites},
	{`sort --output={M} f`, refWrites},
	{`sort --output {M} f`, refWrites},
	{`sort {M}`, refNoWrite},
	{`tee {M}`, refWrites},
	{`tee -a {M}`, refWrites},
	{`tee -ai {M}`, refWrites},
	{`tee -p {M}`, refWrites},
	{`tee f {M}`, refWrites},
	{`touch {M}`, refWrites},
	{`touch -c {M}`, refWrites},
	{`truncate -s 0 {M}`, refWrites},
	{`dd if=f of={M}`, refWrites},
	{`dd of={M}`, refWrites},
	{`dd if={M} of=f`, refNoWrite},
	// cp / mv / install / ln: destinations, target directories, fused values
	{`cp f {M}`, refWrites},
	{`cp -p f {M}`, refWrites},
	{`cp -t {D} authorized_keys`, refWrites},
	{`cp -t {D} f authorized_keys`, refWrites},
	{`cp -t{D} authorized_keys`, refWrites},
	{`cp -pt {D} authorized_keys`, refWrites},
	{`cp -pt{D} authorized_keys`, refWrites},
	{`cp --target-directory={D} authorized_keys`, refWrites},
	{`cp --target-directory {D} authorized_keys`, refWrites},
	{`cp f {D}/authorized_keys`, refWrites},
	{`cp {M} f`, refNoWrite},
	{`mv f {M}`, refWrites},
	{`mv -t {D} authorized_keys`, refWrites},
	{`mv -t{D} authorized_keys`, refWrites},
	{`install -m600 f {M}`, refWrites},
	{`install -m 600 f {M}`, refWrites},
	{`install -D f {M}`, refWrites},
	{`install -t {D} authorized_keys`, refWrites},
	{`install -t{D} authorized_keys`, refWrites},
	{`ln -sf f {M}`, refWrites},
	{`rm {M}`, refWrites},
	{`rm -f {M}`, refWrites},
	{`unlink {M}`, refWrites},
	// archives and compressors
	{`gzip {M}`, refWrites},
	{`gzip -f {M}`, refWrites},
	{`gzip -d {M}.gz`, refWrites},
	{`gunzip {M}.gz`, refWrites},
	{`xz -d {M}.xz`, refWrites},
	{`bzip2 {M}`, refWrites},
	{`zip {M}.zip f`, refUnknown},
	{`gzip -c {M}`, refNoWrite},
	{`zcat {M}.gz`, refNoWrite},
	// git
	{`git clone http://example.test/r {D}`, refWrites},
	{`git -C {D} reset --hard`, refUnknown},
	{`git -C {D} filter-branch --force HEAD`, refUnknown},
	{`git -C {D} status`, refNoWrite},
}

// propWrappers wrap a command the way a hook sees it; a wrapper must not change
// the verdict.
var propWrappers = []string{
	"%s",
	"nice -n 5 %s",
	"timeout 5 %s",
	"nohup %s",
	"command %s",
	"exec %s",
	"sudo %s",
	"env FOO=1 %s",
	"cd /home/u/proj && %s",
	"cd /t/none || %s",
	"true; %s",
	"sh -c \"%s\"",
	"bash -c \"cd /t/a && %s\"",
	"if true; then %s; fi",
}

func expandProp(t propTemplate, wrap string) string {
	c := strings.ReplaceAll(strings.ReplaceAll(t.cmd, "{M}", propMarker), "{D}", propDir)
	if strings.HasPrefix(wrap, "sh -c") || strings.HasPrefix(wrap, "bash -c") {
		if strings.ContainsAny(c, "\"$`\\\n") {
			return "" // cannot be double-quoted unchanged
		}
	}
	return strings.Replace(wrap, "%s", c, 1)
}

func hasMutationAt(r Result, path string) bool {
	for _, e := range r.Effects {
		if !isMutation(e.Kind) || e.TargetState != TargetStateKnown || e.Target.Type != TargetPath {
			continue
		}
		if e.Target.Key() == path || e.Target.Path == path || (e.Target.Subtree && strings.HasPrefix(path, e.Target.Path+"/")) {
			return true
		}
	}
	return false
}

// TestPropertyKnownImpliesWritten: for every template under every wrapper, a fully
// known result carries a KNOWN mutation at the marker when the reference says
// the command writes it; and a template whose effect depends on unread content is
// never fully known.
func TestPropertyKnownImpliesWritten(t *testing.T) {
	n := 0
	for _, tpl := range propTemplates {
		for _, wrap := range propWrappers {
			cmd := expandProp(tpl, wrap)
			if cmd == "" {
				continue
			}
			n++
			r := Extract(Call{Surface: SurfaceShell, Command: cmd}, raLinHome)
			switch tpl.label {
			case refWrites:
				if r.FullyKnown() && !hasMutationAt(r, propMarker) {
					t.Errorf("fully known without a KNOWN mutation at the marker: %q\n%s", cmd, fmtRes(r))
				}
			case refUnknown:
				if r.FullyKnown() {
					t.Errorf("fully known although its effect depends on content we do not read: %q\n%s", cmd, fmtRes(r))
				}
			}
		}
	}
	if n < 800 {
		t.Errorf("only %d generated commands: the generator shrank", n)
	}
}

// refClass classifies every program-table program by what its documented
// behaviour can do. It is deliberately a second list: a new table row without an
// entry here fails TestPropertyEveryProgramIsClassified.
var refClass = func() map[string]string {
	m := map[string]string{}
	add := func(class string, names ...string) {
		for _, n := range names {
			m[n] = class
		}
	}
	// pure readers: no flag or operand of these writes a file
	add("reads", "cat", "tac", "less", "more", "bat", "nl", "head", "tail", "wc", "cut", "comm", "join", "paste", "fold", "fmt", "rev",
		"column", "expand", "unexpand", "strings", "od", "hexdump", "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum",
		"du", "df", "stat", "file", "readlink", "realpath", "diff", "cmp", "look", "shasum", "grep", "egrep", "fgrep", "ag",
		"ls", "ll", "la", "dir", "vdir", "exa", "eza", "lsd")
	// operands are messages, names or shell state, not files they act on
	add("inert", "echo", "printf", "true", "false", "pwd", "cd", "pushd", "popd", "export", "set", "unset", "test", "[", "alias", "unalias",
		"ps", "env", "date", "whoami", "id", "uname", "hostname", "which", "command", "type", "basename", "dirname", "sleep", "kill",
		"killall", "pkill", "jobs", "wait", "clear", "umask", "ulimit", "hash", "getconf", "tty", "tput", "seq", "yes", "expr", "let",
		"read", "printenv", "logname", "groups", "nproc", "arch", "tr")
	// writers of their file operands
	add("writes", "cp", "install", "mv", "rm", "unlink", "shred", "ln", "mkdir", "touch", "mkfifo", "mknod", "chmod", "chown", "chgrp",
		"setfacl", "dd", "tee", "truncate", "sort", "split", "csplit", "uniq", "xxd", "zip", "gzip", "gunzip", "zcat", "bzip2", "bunzip2",
		"bzcat", "xz", "unxz", "xzcat", "unzip", "tar", "scp", "rsync")
	// carry a script, program, format or config in an operand
	add("text", "sed", "awk", "curl", "wget", "find", "fd", "rg") // rg --pre runs a preprocessor
	add("shell", "bash", "sh", "zsh", "dash", "ksh", "eval", "source", ".", "su", "runuser", "python", "python3", "node", "nodejs", "ruby", "perl", "php", "go")
	add("special", "git")
	// Windows table (lower case)
	add("writes", "copy", "xcopy", "robocopy", "move", "ren", "rename", "del", "erase", "rd", "rmdir", "mklink", "icacls", "cacls", "takeown",
		"attrib", "certutil", "bitsadmin", "set-content", "add-content", "out-file", "copy-item", "cpi", "move-item", "mi", "remove-item", "ri",
		"new-item", "ni", "set-acl", "invoke-webrequest", "invoke-restmethod", "iwr", "irm")
	add("reads", "type", "get-content", "gc")
	add("shell", "cmd", "powershell", "pwsh", "invoke-expression", "iex", "start-process", "saps")
	return m
}()

func TestPropertyEveryProgramIsClassified(t *testing.T) {
	var missing []string
	for _, tbl := range []map[string]Program{posixTable, windowsTable} {
		for name := range tbl {
			if _, ok := refClass[strings.ToLower(name)]; !ok {
				if _, ok := refClass[name]; !ok {
					missing = append(missing, name)
				}
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("program-table programs with no reference class (classify them in refClass): %v", missing)
	}
}

// A pure reader's row must not carry anything that writes: no write-ish
// positional mode, no flag with a write-ish role, no grammar-checked text.
func TestPropertyReadersCannotWrite(t *testing.T) {
	writish := map[Role]bool{RoleWrite: true, RoleAppend: true, RoleDelete: true, RoleLink: true, RoleLinkTarget: true, RoleOutput: true, RolePerm: true,
		RoleExecProgram: true, RoleExecCode: true, RoleUploadFile: true, RoleSendData: true, RoleURLUpload: true}
	badPos := map[PosMode]bool{PosAllDelete: true, PosAllWrite: true, PosAllPerm: true, PosSourcesDest: true, PosLinkTargetLink: true, PosReverseLink: true,
		PosFirstWrite: true, PosInOut: true, PosZip: true, PosCompress: true, PosBits: true, PosRobocopy: true}
	for _, tbl := range []map[string]Program{posixTable, windowsTable} {
		for name, p := range tbl {
			if refClass[strings.ToLower(name)] != "reads" {
				continue
			}
			if badPos[p.Pos] {
				t.Errorf("%s is a reader in the reference but its row has a writing positional mode %s", name, p.Pos)
			}
			if p.InPlace != "" || p.DeleteFlag != "" || p.AppendFlag != "" {
				t.Errorf("%s is a reader in the reference but its row can write in place / delete", name)
			}
			for fname, fl := range p.Flags {
				if writish[fl.Role] {
					t.Errorf("%s is a reader in the reference but flag %s has role %s", name, fname, fl.Role)
				}
			}
		}
	}
}

// The grammars themselves: accepted scripts never write; rejected ones include
// every construct that can.
func TestClosedGrammars(t *testing.T) {
	for _, s := range []string{`p`, `s/a/b/`, `s/a/b/g`, `s|a|b|gi`, `5,10p`, `$d`, `/x/d`, `/x/!d`, `1!G;h;$!d`, `y/abc/xyz/`, `n;n;d`, `s/\//x/`, `/a/,/b/{p;d}`, `s,a,b,;p`} {
		if !sedScriptOK(s) {
			t.Errorf("sed script %q rejected", s)
		}
	}
	for _, s := range []string{`w f`, `s/a/b/w f`, `s/a/b/e`, `r f`, `R f`, `W f`, `e id`, `1w f`, `/a/w f`, `p;w f`, `{w f}`, `s/a/b/gw f`, `s/[/]/x/`, `s/a/b`, `y/ab/c/x`, ``, `zz`, `s/a/b/;q;w f`} {
		if s == `` {
			continue
		}
		if sedScriptOK(s) {
			t.Errorf("sed script %q accepted", s)
		}
	}
	for _, s := range []string{`{print $1}`, `{print $1, $2}`, `NR==1`, `{ n++ } END { print n }`, `BEGIN { x = 1 }`, `{print "a>b"}`} {
		if !awkProgramOK(s) {
			t.Errorf("awk program %q rejected", s)
		}
	}
	for _, s := range []string{`{print > "f"}`, `{print >> "f"}`, `{print | "cmd"}`, `BEGIN{system("x")}`, `BEGIN{"x" | getline}`, `{print} # c`, `/"/ {print > "f"}`, `{print "a`, `@include "x"`} {
		if awkProgramOK(s) {
			t.Errorf("awk program %q accepted", s)
		}
	}
	for _, s := range []string{`%{http_code}`, `%{url_effective}\n`, ``} {
		if !curlFormatOK(s) {
			t.Errorf("curl format %q rejected", s)
		}
	}
	for _, s := range []string{`%output{f}x`, `@fmt`, `%{output}`} {
		if curlFormatOK(s) {
			t.Errorf("curl format %q accepted", s)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-2005 RV9-1: the interpreter key-path class rule read the code operand
// only when the interpreter was the program word and, for node/perl/ruby,
// only when -e was its first argument. Inline code that names both key-path
// parts and writes was allowed through a wrapper program (env, command,
// timeout, nice, ...) or behind another interpreter option.
func TestActionInterpreterKeyPathThroughWrapperOrOption(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	py := `'h="` + home + `"; open("{}/.ssh/{}".format(h, "authorized_keys"),"a").write("x")'`
	node := `"require('fs').appendFileSync(require('path').join(require('os').homedir(),'.ssh','authorized_keys'),'x')"`
	perl := `'open(my $f, ">>", $ENV{HOME}."/.ssh/"."authorized_keys"); print $f "x"'`
	ruby := `'File.open(File.join(Dir.home,".ssh","authorized_keys"),"a") { |f| f.write("x") }'`
	for _, command := range []string{
		"env python3 -c " + py,
		"/usr/bin/env python3 -c " + py,
		"env -i PATH=/usr/bin LC_ALL=C python3 -c " + py,
		"command python3 -c " + py,
		"exec python3 -c " + py,
		"timeout 5 python3 -c " + py,
		"timeout -k 2 10s python3 -c " + py,
		"nice python3 -c " + py,
		"nice -n 10 python3 -c " + py,
		"nohup python3 -c " + py,
		"stdbuf -oL python3 -c " + py,
		"python3 -X utf8 -c " + py,
		"python3 -W ignore -c " + py,
		"python3 -Ic " + py,
		"python3 --check-hash-based-pycs never -c " + py,
		"node --no-warnings -e " + node,
		"node -r fs -e " + node,
		"node --require fs -e " + node,
		"env node -e " + node,
		"perl -w -e " + perl,
		"perl -we " + perl,
		"perl -I lib -e " + perl,
		"perl -Ilib -e " + perl,
		"perl -Mstrict -e " + perl,
		"ruby -w -e " + ruby,
		"ruby -I lib -e " + ruby,
		"ruby -r json -e " + ruby,
		"env ruby -e " + ruby,
	} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("posixShellDecision(%q) = %q, want protected-target", command, got)
		}
	}
	for _, command := range []string{
		`env python3 -c 'open("notes.txt","a").write("x")'`,
		`timeout 5 python3 -c 'print("see .ssh/authorized_keys")'`,
		`nice -n 10 python3 -m pytest -q`,
		`python3 --check-hash-based-pycs never -c 'open("notes.txt","a").write("x")'`,
		`perl -w -e 'print "x"'`,
		`perl -I lib -e 'open(my $f, ">>", "notes.txt"); print $f "x"'`,
		`node --no-warnings -e "console.log(1)"`,
		`node -r fs -e "require('fs').writeFileSync('out.txt','x')"`,
		`ruby -w -e 'File.write("notes.txt", "x")'`,
		`env FOO=1 make test`,
	} {
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("posixShellDecision(%q) = %q, want allow", command, got)
		}
	}
}

// The same rows in the Windows readings (PowerShell and a Git Bash script).
func TestActionWindowsInterpreterKeyPathThroughOption(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows readings run on a Windows home on a Windows host")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{proj, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	msys := filepath.ToSlash(home)
	if volume := filepath.VolumeName(home); len(volume) == 2 && volume[1] == ':' {
		msys = "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(home[2:])
	}
	py := `"import os; open(os.path.join(os.environ['USERPROFILE'],'.ssh','authorized_keys'),'a').write('x')"`
	node := `"require('fs').appendFileSync(require('path').join(require('os').homedir(),'.ssh','authorized_keys'),'x')"`
	for _, command := range []string{
		"python -X utf8 -c " + py,
		"python -W ignore -c " + py,
		"python --check-hash-based-pycs never -c " + py,
		"node -r fs -e " + node,
		"node --require fs -e " + node,
		`perl -I lib -e "open(my $f, '>>', $ENV{USERPROFILE}.'/.ssh/'.'authorized_keys'); print $f 'x'"`,
		"& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc @'\nenv python3 -c 'h=\"" + msys + "\"; open(\"{}/.ssh/{}\".format(h, \"authorized_keys\"),\"a\").write(\"x\")'\n'@",
	} {
		if got := ActionCommandDecision(command, proj, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	for _, command := range []string{
		`python -X utf8 -c "open('notes.txt','a').write('x')"`,
		`node -r fs -e "console.log(1)"`,
		`perl -I lib -e "print 'x'"`,
	} {
		if got := ActionCommandDecision(command, proj, home); got != "" {
			t.Errorf("ActionCommandDecision(%q) = %q, want allow", command, got)
		}
	}
}

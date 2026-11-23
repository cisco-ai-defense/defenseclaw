// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"testing"
)

// Round 10 (review 9, section 2): the allowlist property gets
//   1. its trusted lists from a reviewed spec file (testdata/flagspec.tsv), not
//      from a list written next to the table;
//   2. switches as well as valued flags;
//   3. templates for every program class, POSIX and Windows;
//   4. a placement axis: relative and ~ targets under state-setting prefixes
//      (+=, declare attributes, nameref, export prefix, nested cd), labelled by
//      what the shell does.

type specFlag struct {
	arity  int
	effect string
}

func loadFlagSpec(t *testing.T) map[string]map[string]specFlag {
	t.Helper()
	f, err := os.Open("testdata/flagspec.tsv")
	if err != nil {
		t.Fatalf("flag spec: %v", err)
	}
	defer f.Close()
	spec := map[string]map[string]specFlag{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 4 {
			t.Fatalf("flag spec: bad line %q", line)
		}
		if spec[p[0]] == nil {
			spec[p[0]] = map[string]specFlag{}
		}
		ar := 0
		if p[2] == "1" {
			ar = 1
		}
		if _, dup := spec[p[0]][p[1]]; dup {
			t.Fatalf("flag spec: duplicate %s %s", p[0], p[1])
		}
		spec[p[0]][p[1]] = specFlag{arity: ar, effect: p[3]}
	}
	return spec
}

// TestFlagSpecMatchesTable: for the text-class programs the table accepts exactly
// the reviewed flags, with the reviewed arity and effect.
func TestFlagSpecMatchesTable(t *testing.T) {
	spec := loadFlagSpec(t)
	for prog, flags := range spec {
		p, ok := posixTable[prog]
		if !ok {
			t.Errorf("%s: in the spec but not in the table", prog)
			continue
		}
		for name, sf := range flags {
			fl, ok := p.Flags[name]
			if !ok {
				t.Errorf("%s %s: reviewed in the spec but missing from the table", prog, name)
				continue
			}
			ar := 0
			if fl.Value {
				ar = 1
			}
			if ar != sf.arity {
				t.Errorf("%s %s: arity %d in the table, %d in the spec", prog, name, ar, sf.arity)
			}
			if got := tableEffect(p, name, fl); !effectMatches(got, sf.effect) {
				t.Errorf("%s %s: effect %q in the table, %q in the spec", prog, name, got, sf.effect)
			}
		}
		for name := range p.Flags {
			if _, ok := flags[name]; !ok {
				t.Errorf("%s %s: in the table but not reviewed in the spec (add a line to testdata/flagspec.tsv)", prog, name)
			}
		}
	}
	for _, prog := range []string{"sed", "awk", "curl", "wget", "find", "fd", "rg", "grep"} {
		if spec[prog] == nil {
			t.Errorf("%s: no spec entries", prog)
		}
	}
}

func tableEffect(p Program, name string, fl Flag) string {
	switch {
	case fl.Text == TextScriptFile:
		return "file:script"
	case fl.Text == TextConfigFile:
		return "file:config"
	case fl.Text != TextNone:
		return "text:" + string(fl.Text)
	case p.DeleteFlag == name:
		return "delete"
	case p.InPlace == name || name == "--in-place":
		return "inplace"
	}
	switch fl.Role {
	case RoleNone, RoleIgnore:
		if p.DownloadRemote && (name == "-O" || name == "-J" || name == "-OJ" || name == "--remote-name" || name == "--remote-header-name") {
			return "download"
		}
		return "inert"
	case RoleRead:
		return "read"
	case RoleWrite, RoleOutput:
		return "output"
	case RoleSendData:
		return "send"
	case RoleUploadFile:
		return "upload"
	case RoleURL:
		return "url"
	case RoleExecProgram, RoleExecCode:
		return "exec"
	}
	return string(fl.Role)
}

func effectMatches(got, want string) bool { return got == want }

// A flag that writes, moves an output, runs a program or reads a config must
// never be reviewed as inert, whatever the table says. The names are the
// documented side-effect options of these programs; the table must either omit
// them (unaccounted) or give them the effect.
func TestFlagSpecDeniesKnownEffects(t *testing.T) {
	spec := loadFlagSpec(t)
	deny := map[string]map[string]string{
		"curl": {"--output-dir": "", "-D": "output", "--dump-header": "output", "--libcurl": "output", "--trace": "output", "--trace-ascii": "output",
			"--stderr": "output", "--etag-save": "output", "--hsts": "output", "--alt-svc": "output", "--create-file-mode": "", "-:": "", "--next": "",
			"--variable": "", "--proxy-header": "inert", "--netrc-file": "read"},
		"wget": {"-o": "output", "--output-file": "output", "-a": "output", "--append-output": "output", "--save-cookies": "output", "--rejected-log": "output",
			"--execute": "", "-e": "", "--config": "", "--use-askpass": ""},
		"awk":  {"-W": "", "-i": "", "-l": "", "--include": "", "--load": "", "-e": "", "--source": "", "--dump-variables": "output", "-d": "output", "--profile": "output", "-p": "output"},
		"sed":  {"--debug": "", "--sandbox": "", "-b": ""},
		"find": {"-fprint0": "output"},
		"rg":   {"--hostname-bin": "", "--pre-glob": "", "--search-zip": "", "--type-add": "", "--no-config": ""},
	}
	for prog, flags := range deny {
		for name, want := range flags {
			sf, ok := spec[prog][name]
			if want == "" {
				if ok {
					t.Errorf("%s %s: must stay unaccounted (absent from the spec), found as %s", prog, name, sf.effect)
				}
				continue
			}
			if ok && sf.effect != want {
				t.Errorf("%s %s: reviewed as %s, must be %s or absent", prog, name, sf.effect, want)
			}
		}
	}
}

// TestPropertySwitchesDoNotChangeTheVerdict inserts every reviewed flag of a
// text-class program -- switches included -- into the write templates for that
// program. A fully known result must still carry the KNOWN mutation.
func TestPropertySwitchesDoNotChangeTheVerdict(t *testing.T) {
	spec := loadFlagSpec(t)
	n := 0
	for _, tpl := range propTemplates {
		if tpl.label != refWrites {
			continue
		}
		prog := strings.Fields(tpl.cmd)[0]
		flags := spec[prog]
		if flags == nil {
			continue
		}
		names := make([]string, 0, len(flags))
		for f := range flags {
			names = append(names, f)
		}
		sort.Strings(names)
		for _, f := range names {
			sf := flags[f]
			switch sf.effect {
			case "output", "text:sed", "text:awk", "text:curl_format", "file:script", "file:config", "inplace", "delete", "exec", "url", "upload", "send":
				continue // these change which operand is written or read: covered by their own templates
			}
			ins := f
			if sf.arity == 1 {
				ins += " 1"
			}
			cmd := strings.Replace(expandProp(tpl, "%s"), prog+" ", prog+" "+ins+" ", 1)
			n++
			r := Extract(Call{Surface: SurfaceShell, Command: cmd}, raLinHome)
			if r.FullyKnown() && !hasMutationAt(r, propMarker) {
				t.Errorf("a reviewed flag changed the verdict: %q fully known without a KNOWN mutation at the marker\n%s", cmd, fmtRes(r))
			}
		}
	}
	if n < 200 {
		t.Errorf("only %d flag-insertion commands: the generator shrank", n)
	}
}

// Broad templates: every program class not covered in property_test.go, POSIX
// and Windows. The label states the documented behaviour.
type broadTemplate struct {
	cmd   string
	label refLabel
	dia   string // "posix", "cmd", "ps"
}

const propWinMarker = `C:\Users\u\.ssh\authorized_keys`
const propWinDir = `C:\Users\u\.ssh`

var broadTemplates = []broadTemplate{
	// base64 (macOS -o / --output writes its output file; GNU has no such flag)
	{`base64 -o {M} f`, refWrites, "posix"},
	{`base64 --output {M} f`, refWrites, "posix"},
	{`base64 -i f -o {M}`, refWrites, "posix"},
	{`base64 --input f --output {M}`, refWrites, "posix"},
	{`base64 {M}`, refNoWrite, "posix"},
	{`base64 -d {M}`, refNoWrite, "posix"},
	// wget
	{`wget -O {M} http://example.test/`, refWrites, "posix"},
	{`wget --output-document {M} http://example.test/`, refWrites, "posix"},
	{`wget -qO {M} http://example.test/`, refWrites, "posix"},
	{`wget -o {M} http://example.test/`, refWrites, "posix"},
	{`wget -a {M} http://example.test/`, refWrites, "posix"},
	{`wget --append-output {M} http://example.test/`, refWrites, "posix"},
	{`wget --save-cookies {M} http://example.test/`, refWrites, "posix"},
	{`wget -P {D} http://example.test/`, refUnknown, "posix"},
	{`wget http://example.test/`, refUnknown, "posix"},
	{`wget -r http://example.test/`, refUnknown, "posix"},
	{`wget --post-file {M} http://example.test/`, refNoWrite, "posix"},
	// find and fd
	{`find . -fprint {M}`, refWrites, "posix"},
	{`find . -fprintf {M} %p`, refWrites, "posix"},
	{`find . -fls {M}`, refWrites, "posix"},
	{`find {M} -delete`, refWrites, "posix"},
	{`find . -name x -exec tee {M} ;`, refWrites, "posix"},
	{`find . -exec rm {} ;`, refUnknown, "posix"},
	{`find . -name x -print`, refNoWrite, "posix"},
	{`fd x -x rm {}`, refUnknown, "posix"},
	// grep and rg
	{`grep -f {M} x`, refNoWrite, "posix"},
	{`grep -r x {D}`, refNoWrite, "posix"},
	{`rg --pre ./p x {D}`, refUnknown, "posix"},
	{`rg x {M}`, refNoWrite, "posix"},
	// tar, unzip, scp, rsync, shred, perms, mkdir family, links
	{`tar -cf {M} d`, refWrites, "posix"},
	{`tar czf {M} d`, refWrites, "posix"},
	{`tar -rf {M} f`, refWrites, "posix"},
	{`tar -xf a.tar -C {D}`, refUnknown, "posix"},
	{`tar --to-command=cmd -xf a.tar`, refUnknown, "posix"},
	{`tar -tf {M}`, refNoWrite, "posix"},
	{`unzip -o a.zip -d {D}`, refUnknown, "posix"},
	{`scp f {M}`, refWrites, "posix"},
	{`scp host:f {M}`, refWrites, "posix"},
	{`scp {M} host:/x`, refNoWrite, "posix"},
	{`rsync -a f {M}`, refWrites, "posix"},
	{`rsync -a authorized_keys {D}/`, refWrites, "posix"},
	{`shred {M}`, refWrites, "posix"},
	{`shred -u {M}`, refWrites, "posix"},
	{`chmod 600 {M}`, refWrites, "posix"},
	{`chmod -R 600 {M}`, refWrites, "posix"},
	{`chown u {M}`, refWrites, "posix"},
	{`chgrp g {M}`, refWrites, "posix"},
	{`setfacl -m u:x:r {M}`, refWrites, "posix"},
	{`mkdir {M}`, refWrites, "posix"},
	{`mkdir -p {M}`, refWrites, "posix"},
	{`mkfifo {M}`, refWrites, "posix"},
	{`mknod {M} p`, refWrites, "posix"},
	{`ln f {M}`, refWrites, "posix"},
	{`ln -s f {M}`, refWrites, "posix"},
	// moving a file away is a mutation of the file moved: its source goes
	{`mv {M} f`, refWrites, "posix"},
	{`mv -f {M} f`, refWrites, "posix"},
	{`mv {M} {D}/x`, refWrites, "posix"},
	{`mv {M} /t/a/`, refWrites, "posix"},
	{`mv -t /t/a {M}`, refWrites, "posix"},
	{`mv {M} /t/a/x`, refWrites, "posix"},
	// redirects, shells, interpreters
	{`cat f > {M}`, refWrites, "posix"},
	{`echo k >> {M}`, refWrites, "posix"},
	{`echo k | tee -a {M}`, refWrites, "posix"},
	{`printf k > {M}`, refWrites, "posix"},
	{`sh -c 'echo k >> {M}'`, refWrites, "posix"},
	{`bash -c 'cat f > {M}'`, refWrites, "posix"},
	{`eval 'echo k >> {M}'`, refWrites, "posix"},
	{`python3 -c 'open(1)'`, refUnknown, "posix"},
	{`node x.js`, refNoWrite, "posix"}, // a named script file is a known exec of that file; its content is the rules' business
	{`perl -e 1`, refUnknown, "posix"},
	{`ls {M}`, refNoWrite, "posix"},
	{`cat {M}`, refNoWrite, "posix"},
	{`head -n1 {M}`, refNoWrite, "posix"},
	{`wc -l {M}`, refNoWrite, "posix"},
	{`diff {M} f`, refNoWrite, "posix"},
	{`stat {M}`, refNoWrite, "posix"},
	{`cut -d: -f1 {M}`, refNoWrite, "posix"},
	{`sort {M}`, refNoWrite, "posix"},
	// the remaining programs of the table
	{`bunzip2 {M}.bz2`, refWrites, "posix"},
	{`unxz {M}.xz`, refWrites, "posix"},
	{`bzcat {M}.bz2`, refNoWrite, "posix"},
	{`xzcat {M}.xz`, refNoWrite, "posix"},
	{`split f {M}`, refNoWrite, "posix"},
	{`csplit f 2`, refNoWrite, "posix"},
	{`dash -c 'echo k >> {M}'`, refWrites, "posix"},
	{`ksh -c 'echo k >> {M}'`, refWrites, "posix"},
	{`zsh -c 'echo k >> {M}'`, refWrites, "posix"},
	{`su -c 'echo k >> {M}' u`, refWrites, "posix"},
	{`runuser -c 'echo k >> {M}' u`, refWrites, "posix"},
	{`source x.sh`, refNoWrite, "posix"},
	{`go run x.go`, refUnknown, "posix"},
	{`python -c 'open(1)'`, refUnknown, "posix"},
	{`nodejs -e 1`, refUnknown, "posix"},
	{`ruby -e 1`, refUnknown, "posix"},
	{`php -r 1`, refUnknown, "posix"},
	// Windows: cmd
	{`copy f {W}`, refWrites, "cmd"},
	{`xcopy f {W}`, refWrites, "cmd"},
	{`move f {W}`, refWrites, "cmd"},
	{`move {W} f`, refWrites, "cmd"},
	{`ren {W} x`, refWrites, "cmd"},
	{`move {W} C:\t\`, refWrites, "cmd"},
	{`move {W} C:\t\x`, refWrites, "cmd"},
	{`del {W}`, refWrites, "cmd"},
	{`erase {W}`, refWrites, "cmd"},
	{`del /f /q {W}`, refWrites, "cmd"},
	{`type f > {W}`, refWrites, "cmd"},
	{`echo k >> {W}`, refWrites, "cmd"},
	{`mklink {W} C:\t`, refWrites, "cmd"},
	{`icacls {W} /grant x:F`, refWrites, "cmd"},
	{`takeown /f {W}`, refWrites, "cmd"},
	{`attrib +h {W}`, refWrites, "cmd"},
	{`certutil -decode f {W}`, refWrites, "cmd"},
	{`certutil -urlcache -f http://example.test/ {W}`, refWrites, "cmd"},
	{`bitsadmin /transfer j http://example.test/ {W}`, refWrites, "cmd"},
	{`curl -o {W} http://example.test/`, refWrites, "cmd"},
	{`robocopy C:\src {WD} authorized_keys`, refWrites, "cmd"},
	{`type {W}`, refNoWrite, "cmd"},
	{`cmd /c del {W}`, refWrites, "cmd"},
	{`cacls {W} /g x:f`, refWrites, "cmd"},
	{`rename {W} x`, refWrites, "cmd"},
	{`rd /s /q {WD}`, refNoWrite, "cmd"},
	{`rmdir /s /q {WD}`, refNoWrite, "cmd"},
	{`pwsh -c "Remove-Item {W}"`, refWrites, "cmd"},
	// Windows: PowerShell
	{`Set-Content -Path {W} -Value k`, refWrites, "ps"},
	{`Add-Content {W} k`, refWrites, "ps"},
	{`Out-File -FilePath {W} -InputObject k`, refWrites, "ps"},
	{`Copy-Item f {W}`, refWrites, "ps"},
	{`Move-Item f {W}`, refWrites, "ps"},
	{`Move-Item {W} f`, refWrites, "ps"},
	{`Move-Item {W} C:\t\`, refWrites, "ps"},
	{`Move-Item -Path {W} -Destination C:\t\x`, refWrites, "ps"},
	{`Remove-Item {W}`, refWrites, "ps"},
	{`Remove-Item -Path {W} -Force`, refWrites, "ps"},
	{`New-Item -Path {W} -ItemType File`, refWrites, "ps"},
	{`New-Item -Path {WD} -Name authorized_keys`, refWrites, "ps"},
	{`Set-Acl -Path {W} -AclObject $a`, refWrites, "ps"},
	{`Invoke-WebRequest http://example.test/ -OutFile {W}`, refWrites, "ps"},
	{`iwr http://example.test/ -OutFile {W}`, refWrites, "ps"},
	{`Get-Content {W}`, refNoWrite, "ps"},
	{`powershell -c Remove-Item {W}`, refWrites, "ps"},
	{`Start-Process cmd -ArgumentList '/c','del',{W}`, refUnknown, "ps"},
	{`iex $x`, refUnknown, "ps"},
	{`cpi f {W}`, refWrites, "ps"},
	{`mi f {W}`, refWrites, "ps"},
	{`ni {W}`, refWrites, "ps"},
	{`ri {W}`, refWrites, "ps"},
	{`irm http://example.test/ -OutFile {W}`, refWrites, "ps"},
	{`Invoke-RestMethod http://example.test/ -OutFile {W}`, refWrites, "ps"},
	{`Invoke-Expression $x`, refUnknown, "ps"},
	{`saps cmd`, refUnknown, "ps"},
	{`pwsh -c 'Remove-Item {W}'`, refWrites, "ps"},
}

var winWrappers = map[string][]string{
	"cmd": {"%s", "cmd /c %s", `cd /d C:\work && %s`, `cd /d C:\t\none || %s`, `(%s)`, `if exist C:\x (%s)`},
	"ps":  {"%s", "& { %s }", "if ($true) { %s }", `Set-Location C:\work; %s`, `1 | ForEach-Object { %s }`},
}

func expandBroad(t broadTemplate, wrap string) string {
	c := t.cmd
	if t.dia == "posix" {
		c = strings.ReplaceAll(strings.ReplaceAll(c, "{M}", propMarker), "{D}", propDir)
	} else {
		c = strings.ReplaceAll(c, "{WD}", propWinDir)
		c = strings.ReplaceAll(c, "{W}", propWinMarker)
	}
	if strings.HasPrefix(wrap, "sh -c") || strings.HasPrefix(wrap, "bash -c") {
		if strings.ContainsAny(c, "\"$`\\\n") {
			return ""
		}
	}
	return strings.Replace(wrap, "%s", c, 1)
}

func TestPropertyBroadPrograms(t *testing.T) {
	n := 0
	for _, tpl := range broadTemplates {
		var wraps []string
		var o Options
		var marker string
		switch tpl.dia {
		case "posix":
			wraps, o, marker = propWrappers, raLinHome, propMarker
		case "cmd":
			wraps, o, marker = winWrappers["cmd"], raCmd, strings.ToLower(propWinMarker)
		default:
			wraps, o, marker = winWrappers["ps"], raPS, strings.ToLower(propWinMarker)
		}
		for _, wrap := range wraps {
			cmd := expandBroad(tpl, wrap)
			if cmd == "" {
				continue
			}
			n++
			r := Extract(Call{Surface: SurfaceShell, Command: cmd}, o)
			switch tpl.label {
			case refWrites:
				if r.FullyKnown() && !hasMutationAt(r, marker) {
					t.Errorf("fully known without a KNOWN mutation at the marker: %q\n%s", cmd, fmtRes(r))
				}
			case refUnknown:
				if r.FullyKnown() {
					t.Errorf("fully known although its effect depends on content we do not read: %q\n%s", cmd, fmtRes(r))
				}
			}
		}
	}
	if n < 700 {
		t.Errorf("only %d generated commands: the generator shrank", n)
	}
}

// The placement axis. Each template is a shell command whose real effect is known
// from the shell's own semantics: claimM = it writes the marker, noM = it never
// writes the marker (writes elsewhere), maybeM = the model may report the marker
// as one of several candidates. Properties: claimM => a fully known result has a
// KNOWN mutation at the marker; noM => a fully known result has none (the
// restricted tier must not name a protected file the command does not touch).
type placeLabel int

const (
	placeClaimM placeLabel = iota
	placeNoM
)

type placeTemplate struct {
	cmd   string
	label placeLabel
	opts  Options
}

var placeTemplates = []placeTemplate{
	// relative targets after a cd
	{`cd ~/.ssh && echo k >> authorized_keys`, placeClaimM, raLin},
	{`cd {D} && echo k >> authorized_keys`, placeClaimM, raLin},
	{`cd {D} && cd . && echo k >> authorized_keys`, placeClaimM, raLinHome},
	{`cd /t/none || echo k >> authorized_keys`, placeNoM, raLin}, // fail side: proj/authorized_keys
	{`cd /t/none && echo k >> authorized_keys`, placeNoM, raLin}, // never runs
	{`(cd {D}; echo k >> authorized_keys)`, placeClaimM, raLin},
	{`(cd {D}); echo k >> authorized_keys`, placeNoM, raLin},
	{`cd {D} | cat; echo k >> authorized_keys`, placeNoM, raLin},
	{`cd {D} && eval 'echo k >> authorized_keys'`, placeClaimM, raLin},
	{`cd {D} && sh -c 'echo k >> authorized_keys'`, placeClaimM, raLin},
	{`cd {D} && f() { echo k >> authorized_keys; }; f`, placeClaimM, raLin},
	{`cd {D} || eval 'echo k >> authorized_keys'`, placeNoM, raLin},
	{`cd /t/none && eval 'cd {D}' && echo k >> authorized_keys`, placeClaimM, raLinHome}, // reviewer N10 shape
	{`env -C {D} tee -a authorized_keys`, placeClaimM, raLin},
	{`env -C{D} tee -a authorized_keys`, placeClaimM, raLin},
	{`env --chdir={D} tee -a authorized_keys`, placeClaimM, raLin},
	{`sudo -D {D} tee -a authorized_keys`, placeClaimM, raLin},
	// ~ and HOME
	{`echo k >> ~/.ssh/authorized_keys`, placeClaimM, raLin},
	{`HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`HOME=/t/h; echo k >> ~/.ssh/authorized_keys`, placeNoM, raLin},
	{`HOME=/t/h sh -c 'echo k >> ~/.ssh/authorized_keys'`, placeNoM, raLin},
	{`HOME=/home/u/.ssh sh -c 'echo k >> ~/authorized_keys'`, placeClaimM, raLin},
	{`env HOME=/t/h sh -c 'echo k >> ~/.ssh/authorized_keys'`, placeNoM, raLin},
	{`env -i sh -c 'echo k >> ~/.ssh/authorized_keys'`, placeNoM, raLin},
	{`export HOME=/home/u/.ssh; sh -c 'echo k >> ~/authorized_keys'`, placeClaimM, raLin},
	// the export attribute and the prefix-on-export shape
	{`HOME=/home/u/.ssh export HOME; sh -c 'echo k >> ~/authorized_keys'`, placeClaimM, raLin},
	{`HOME=/home/u/.ssh export HOME; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`HOME=/t/h export HOME; echo k >> ~/.ssh/authorized_keys`, placeNoM, raLin},
	{`export HOME=/t/h; HOME+=/x; echo k >> ~/.ssh/authorized_keys`, placeNoM, raLin},
	{`HOME=/home/u; HOME+=/.ssh; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`HOME=/home/u/.ss; HOME+=h; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`declare -x HOME=/t/h; sh -c 'echo k >> ~/.ssh/authorized_keys'`, placeNoM, raLin},
	{`declare -u HOME=/home/u; echo k >> ~/.ssh/authorized_keys`, placeNoM, raLin},
	{`declare -l HOME=/HOME/U; echo k >> ~/.ssh/authorized_keys`, placeClaimM, raLin},
	{`declare -n r=HOME; r=/t/h; echo k >> ~/.ssh/authorized_keys`, placeNoM, raLin},
	{`declare -n r=HOME; r=/home/u/.ssh; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`HOME=/t/h; declare +x HOME; sh -c 'echo k >> ~/.ssh/authorized_keys'`, placeNoM, raLin},
	{`local HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`readonly HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, placeClaimM, raLin},
	{`HOME=.ssh; cd /home/u; echo k >> ~/authorized_keys`, placeClaimM, raLin}, // a relative HOME is used literally
	// CDPATH, OLDPWD, PWD
	{`CDPATH=/home/u; cd .ssh && echo k >> authorized_keys`, placeClaimM, raLin},
	{`CDPATH=/t; cd .ssh && echo k >> authorized_keys`, placeNoM, raLin},
	{`command export CDPATH=/home/u; cd .ssh && echo k >> authorized_keys`, placeClaimM, raLin},
	{`CDPATH+=:/home/u; cd .ssh && echo k >> authorized_keys`, placeClaimM, raLin},
	{`cd {D}; cd /t/a; cd - >/dev/null; echo k >> authorized_keys`, placeClaimM, raLin},
	{`OLDPWD={D}; cd -; echo k >> authorized_keys`, placeClaimM, raLin},
	{`PWD=/t/a; echo k >> authorized_keys`, placeNoM, raLinHome}, // PWD assignment does not move the cwd
}

func TestPropertyPlacement(t *testing.T) {
	n := 0
	for _, tpl := range placeTemplates {
		cmd := strings.ReplaceAll(tpl.cmd, "{D}", propDir)
		n++
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, tpl.opts)
		if !r.FullyKnown() {
			continue
		}
		hit := hasMutationAt(r, propMarker)
		switch tpl.label {
		case placeClaimM:
			if !hit {
				t.Errorf("fully known without a KNOWN mutation at the marker: %q\n%s", cmd, fmtRes(r))
			}
		case placeNoM:
			if hit {
				t.Errorf("fully known and claims the protected marker the command never writes: %q\n%s", cmd, fmtRes(r))
			}
		}
	}
	if n < 40 {
		t.Errorf("only %d placement templates", n)
	}
}

// Every program in the table is under the property: the writers, text-carriers and
// shells by a labelled template, the pure readers and inert-operand builtins by the
// no-mutation check below.
func TestPropertyReadersAndInertNeverMutate(t *testing.T) {
	n := 0
	for ti, tbl := range []map[string]Program{posixTable, windowsTable} {
		isWin := ti == 1
		for name := range tbl {
			class := refClass[strings.ToLower(name)]
			if class != "reads" && class != "inert" {
				continue
			}
			var o Options
			marker := propMarker
			if isWin {
				o, marker = raCmd, strings.ToLower(propWinMarker)
			} else {
				o = raLinHome
			}
			arg := propMarker
			if isWin {
				arg = propWinMarker
			}
			for _, cmd := range []string{name + " " + arg, name + " -x " + arg, name + " " + arg + " " + arg} {
				n++
				r := Extract(Call{Surface: SurfaceShell, Command: cmd}, o)
				for _, e := range r.Effects {
					if isMutation(e.Kind) && e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && (e.Target.Key() == marker || e.Target.Path == marker) {
						t.Errorf("%q: a %s program is claimed to mutate the marker\n%s", cmd, class, fmtRes(r))
					}
				}
			}
		}
	}
	if n < 300 {
		t.Errorf("only %d reader / inert commands", n)
	}
}

// TestPropertyTemplateCoverage: every table program is a pure reader or inert
// builtin (covered above) or is the first word of at least one labelled template.
func TestPropertyTemplateCoverage(t *testing.T) {
	covered := map[string]bool{}
	first := func(cmd string) {
		f := strings.Fields(cmd)
		if len(f) > 0 {
			covered[strings.ToLower(strings.TrimSuffix(f[0], ".exe"))] = true
		}
	}
	for _, tpl := range propTemplates {
		first(tpl.cmd)
	}
	for _, tpl := range broadTemplates {
		first(tpl.cmd)
	}
	for _, tpl := range placeTemplates {
		first(tpl.cmd)
		// a placement template exercises the builtins it names
		for _, w := range strings.Fields(strings.NewReplacer(";", " ", "&&", " ", "||", " ", "(", " ", ")", " ", "{", " ", "}", " ").Replace(tpl.cmd)) {
			covered[w] = true
		}
	}
	var missing []string
	for _, tbl := range []map[string]Program{posixTable, windowsTable} {
		for name := range tbl {
			l := strings.ToLower(name)
			if c := refClass[l]; c == "reads" || c == "inert" {
				continue
			}
			if !covered[l] && !covered[name] {
				missing = append(missing, name)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("table programs with no labelled template (add one to property_test.go / property2_test.go): %v", missing)
	}
}

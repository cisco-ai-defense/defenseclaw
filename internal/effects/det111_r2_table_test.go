// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDET111R2WindowsHostCommandsFromPosixShell(t *testing.T) {
	for _, tc := range []struct {
		name             string
		wantCmdC, wantPS bool
	}{
		{"cmd.exe", true, false}, {"powershell.exe", false, true}, {"pwsh.exe", false, true},
	} {
		p, ok := lookupProgram(tc.name, FlavorWindows, DialectPOSIX, false)
		if !ok || p.CmdC != tc.wantCmdC || p.PSLaunch != tc.wantPS {
			t.Errorf("lookupProgram(%q, Windows, POSIX) = (%+v, %v), want CmdC=%v PSLaunch=%v", tc.name, p, ok, tc.wantCmdC, tc.wantPS)
		}
	}
	if _, ok := lookupProgram("cmd.exe", FlavorPOSIX, DialectPOSIX, false); ok {
		t.Fatal("native Windows cmd leaked into a POSIX host table")
	}
}

func TestDET111R2SevenZipFusedOutputTableRole(t *testing.T) {
	p, ok := lookupProgram("7z", FlavorPOSIX, DialectPOSIX, false)
	if !ok {
		t.Fatal("7z missing from the POSIX program table")
	}
	ops, _, unknown := (&walker{}).classifyOperands([]Word{
		{Value: "x", Static: true}, {Value: "a.7z", Static: true},
		{Value: "-o/home/alice/.defenseclaw", Static: true},
	}, p, DialectPOSIX)
	if unknown {
		t.Fatal("known 7z extraction options were marked unknown")
	}
	var archiveRead, outputTree bool
	for _, op := range ops {
		if op.role == RoleRead && op.value == "a.7z" {
			archiveRead = true
		}
		if op.role == RoleWrite && op.value == "/home/alice/.defenseclaw" && op.subtree {
			outputTree = true
		}
	}
	if !archiveRead || !outputTree {
		t.Fatalf("7z roles = %#v; want archive read and subtree output write", ops)
	}
}

func TestDET111R2SevenZipDynamicFusedOutputTableRole(t *testing.T) {
	p, ok := lookupProgram("7z", FlavorWindows, DialectPowerShell, false)
	if !ok {
		t.Fatal("7z missing from the Windows program table")
	}
	ops, _, unknown := (&walker{}).classifyOperands([]Word{
		{Value: "x", Static: true}, {Value: "a.7z", Static: true},
		{Value: "-o$env:USERPROFILE\\.defenseclaw", Static: false, Reason: ReasonDynamicExpansion},
	}, p, DialectPowerShell)
	if unknown {
		t.Fatal("known dynamic 7z -o value was marked as an unknown option")
	}
	var outputTree bool
	for _, op := range ops {
		if op.role == RoleWrite && !op.static && op.subtree && strings.Contains(strings.ToLower(op.value), "$env:userprofile") {
			outputTree = true
		}
	}
	if !outputTree {
		t.Fatalf("7z dynamic output roles = %#v; want an unresolved subtree write", ops)
	}
}

func TestDET111R2BSDSedInPlaceFromCorpus(t *testing.T) {
	f, err := os.Open("testdata/det111_r2.cases.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var c det111R2CorpusCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if c.ID != "det111/GAP-1500/bsd-I-p/var" {
			continue
		}
		cmd := strings.Replace(c.Payload.Command, "sed ", "/usr/bin/sed ", 1)
		o := det111R2Options(c.Payload)
		o.BSDUserland = true
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: cmd, Workdir: c.Payload.CWD}, o)
		for _, e := range r.Effects {
			if e.Kind == KindWrite && e.TargetState == TargetStateKnown && strings.Contains(e.Target.Path, "/.claude/settings.json") {
				return
			}
		}
		t.Fatalf("BSD sed -I did not write the protected corpus target\n%s", fmtRes(r))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("GAP-1500 BSD -I corpus row missing")
}

func TestDET111R2SevenZipPSFusedOutputEndToEnd(t *testing.T) {
	o := Options{
		Flavor: FlavorWindows, Dialect: DialectPowerShell,
		Home: `C:\Users\alice`, CWD: `C:\Users\alice\proj`,
		Env: map[string]string{"HOME": `C:\Users\alice`, "USERPROFILE": `C:\Users\alice`},
	}
	command := `7z x a.7z -o$env:USERPROFILE\.defenseclaw`
	r := Extract(Call{Surface: SurfaceShell, Tool: "PowerShell", Workdir: o.CWD, Command: command}, o)
	for _, e := range r.Effects {
		if e.Kind != KindWrite || !e.Target.Subtree {
			continue
		}
		for _, spelling := range []string{e.Target.Path, e.Target.Spelling, e.Target.Glob} {
			if strings.Contains(strings.ToLower(spelling), ".defenseclaw") {
				return
			}
		}
	}
	t.Fatalf("fused PowerShell -o target did not reach the 7z subtree-write row\n%s", fmtRes(r))
}

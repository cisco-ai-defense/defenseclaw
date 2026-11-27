// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestDET111R2BuiltinOracle(t *testing.T) {
	shells := []struct {
		name string
		args []string
	}{
		{"bash", []string{"-c", "compgen -b"}},
		{"zsh", []string{"-c", `print -l ${(k)builtins}`}},
	}
	seen := map[string]bool{}
	for _, shell := range shells {
		if _, err := exec.LookPath(shell.name); err != nil {
			if shell.name == "bash" && runtime.GOOS == "windows" {
				t.Skipf("no bash on PATH on this Windows host (%v): the oracle lists the builtins of a POSIX shell installed on the host", err)
			}
			if shell.name == "bash" {
				t.Fatalf("bash builtin oracle unavailable: %v", err)
			}
			continue
		}
		out, err := exec.Command(shell.name, shell.args...).Output()
		if err != nil {
			t.Fatalf("%s builtin oracle: %v", shell.name, err)
		}
		for _, name := range strings.Fields(string(out)) {
			if seen[name] {
				continue
			}
			seen[name] = true
			p, ok := lookupProgram(name, FlavorPOSIX, DialectPOSIX, false)
			if !ok {
				t.Errorf("%s builtin %q falls through the POSIX program table", shell.name, name)
				continue
			}
			if p.BuiltinUnknown && (p.InertOperands || p.Pos != PosAllRead || !p.Strict) {
				t.Errorf("unmodeled builtin %q is not an unknown read row: %+v", name, p)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no shell builtins were checked")
	}

	p, ok := lookupProgram("echo", FlavorPOSIX, DialectPOSIX, false)
	if !ok || p.BuiltinUnknown || !p.InertOperands {
		t.Fatalf("echo must have an explicit data-only table row: %+v, %v", p, ok)
	}
}

func TestDET111R2UnknownBuiltinOperandsAreReads(t *testing.T) {
	opt := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj", Env: map[string]string{"HOME": "/home/u"}}
	r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: `help /home/u/.ssh/authorized_keys`, Workdir: opt.CWD}, opt)
	if r.FullyKnown() {
		t.Fatalf("unmodeled builtin must remain unknown\n%s", fmtRes(r))
	}
	for _, e := range r.Effects {
		if e.Kind == KindRead && (strings.Contains(e.Target.Path, "/home/u/.ssh/authorized_keys") || strings.Contains(e.Target.Spelling, "/home/u/.ssh/authorized_keys")) {
			return
		}
	}
	t.Fatalf("unmodeled builtin operand was not retained as a read\n%s", fmtRes(r))
}

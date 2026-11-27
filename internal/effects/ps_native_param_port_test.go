// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// TestPSNativeParamArgvMatchesPowerShell: a native program gets a parameter
// token as PowerShell's native binder passes it. Oracle (pwsh 7.6.6 and
// Windows PowerShell 5.1, a native argv printer): -o$env:UP\w -> the one
// literal word -o$env:UP\w (the token is the parameter o$env with the argument
// UP\w; nothing expands); -o:$v\w -> -o:<value>\w; -a:b -> -a:b; -a: b ->
// -a: and b; -abc -> -abc. A cmdlet binds the parameter instead.
func TestPSNativeParamArgvMatchesPowerShell(t *testing.T) {
	type wd struct {
		v      string
		static bool
	}
	cases := []struct {
		src  string
		want []wd
	}{
		{`tool x -o$env:TEMP\out`, []wd{{"tool", true}, {"x", true}, {`-o$env:TEMP\out`, true}}},
		{`tool -a:b`, []wd{{"tool", true}, {"-a:b", true}}},
		{`tool -a:'s t'`, []wd{{"tool", true}, {"-a:s t", true}}},
		{`tool -a: b`, []wd{{"tool", true}, {"-a:", true}, {"b", true}}},
		{`tool -abc`, []wd{{"tool", true}, {"-abc", true}}},
		{`tool -o:$env:TEMP\w`, []wd{{"tool", true}, {"", false}}},
		{`Write-Output -o:b`, []wd{{"Write-Output", true}, {"-o", true}, {"b", true}}},
	}
	for _, c := range cases {
		s := parsePowerShell(c.src, Options{Flavor: FlavorWindows, Dialect: DialectPowerShell})
		if len(s.Stmts) != 1 || len(s.Stmts[0].Cmds) != 1 {
			t.Fatalf("%q: want one command, got %+v", c.src, s.Stmts)
		}
		ws := s.Stmts[0].Cmds[0].Words
		if len(ws) != len(c.want) {
			t.Errorf("%q: want %d words, got %d: %+v", c.src, len(c.want), len(ws), ws)
			continue
		}
		for i, w := range c.want {
			if ws[i].Static != w.static || (w.static && ws[i].Value != w.v) {
				t.Errorf("%q word %d: want %q static=%v, got %+v", c.src, i, w.v, w.static, ws[i])
			}
		}
	}
	// -o:$env:TEMP\w is one word -o:<TEMP>\w: it expands where the hook knows TEMP.
	s := parsePowerShell(`tool -o:$env:TEMP\w`, Options{Flavor: FlavorWindows, Dialect: DialectPowerShell})
	w := newWalker(&Result{}, Options{Flavor: FlavorWindows, Env: map[string]string{"TEMP": `C:\t`}})
	if rv := w.resolveWord(s.Stmts[0].Cmds[0].Words[1]); !rv.Static || rv.Value != `-o:C:\t\w` {
		t.Errorf("colon form with a known TEMP: want -o:C:\\t\\w, got %+v", rv)
	}
}

// TestPSFusedNativeArgParseReader: a psparse.Parse Script (the
// psparse legacyFrontend seam reader and the deep-nesting fallback) splits
// -o$env:X\y into a switch and a glued argument; the lowering joins them into
// one argv word (DET111 R1, GAP-1663).
func TestPSFusedNativeArgParseReader(t *testing.T) {
	src := `tool x a.bin -o$env:TEMP\out`
	sc, err := psparse.Parse(src, psparse.Options{Dialect: psparse.DialectUnknown})
	if err != nil {
		t.Fatal(err)
	}
	s := lowerPSParsed(&Script{Dialect: DialectPowerShell}, sc, false, Options{Flavor: FlavorWindows, Dialect: DialectPowerShell}, true)
	ws := s.Stmts[0].Cmds[0].Words
	if len(ws) != 4 {
		t.Fatalf("want 4 words, got %d: %+v", len(ws), ws)
	}
	w := newWalker(&Result{}, Options{Flavor: FlavorWindows, Env: map[string]string{"TEMP": `C:\t`}})
	if rv := w.resolveWord(ws[3]); !rv.Static || rv.Value != `-oC:\t\out` {
		t.Errorf("psparse reader: want -oC:\\t\\out, got %+v", rv)
	}
}

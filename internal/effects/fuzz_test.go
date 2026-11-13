// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
	"testing"
)

// checkInvariants asserts the Section-4 invariants that must hold for any input
// (EFFECTS.md + review): no panic (the caller survived), every unknown effect
// carries a reason, a known path effect has a non-empty path, spans are valid,
// source indices are in range, the shadow step leaves Link=not_checked, and the
// effect count is bounded.
func checkInvariants(t *testing.T, in string, r Result) {
	t.Helper()
	if len(r.Effects) > defaultMaxEffects {
		t.Fatalf("effect count %d exceeds bound for %q", len(r.Effects), in)
	}
	for i, e := range r.Effects {
		if e.TargetState != TargetStateKnown || e.RoleState != RoleStateKnown || e.Kind == KindOpaque {
			if len(e.Reasons) == 0 {
				t.Errorf("effect %d not fully known but has no reason: %+v (in %q)", i, e, in)
			}
		}
		if e.Kind == KindRead || e.Kind == KindWrite || e.Kind == KindAppend || e.Kind == KindDelete {
			if e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Path == "" && e.Target.Glob == "" {
				t.Errorf("effect %d known path target but empty path/glob: %+v (in %q)", i, e, in)
			}
		}
		if e.Target.Link != LinkNotChecked {
			t.Errorf("effect %d: shadow step must leave Link=not_checked, got %s", i, e.Target.Link)
		}
		if e.Origin.Span[0] < 0 || e.Origin.Span[1] < 0 || e.Origin.Span[1] < e.Origin.Span[0] {
			t.Errorf("effect %d invalid span %v (in %q)", i, e.Origin.Span, in)
		}
		if e.Data != nil {
			for _, s := range e.Data.Sources {
				if s.Kind == SourceEffect && (s.Effect < 1 || s.Effect > len(r.Effects)) {
					t.Errorf("effect %d source index %d out of range (in %q)", i, s.Effect, in)
				}
			}
		}
	}
	// JSON output must not serialize the raw content field Data.Text
	// (json:"-"); path/url spellings are reported on purpose, so the invariant
	// is specifically that no "Text" key is emitted under data.
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if indexOf(string(b), `"Text"`) >= 0 || indexOf(string(b), `"text"`) >= 0 {
		t.Errorf("Data.Text serialized into JSON output (in %q)", in)
	}
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func FuzzExtractPOSIX(f *testing.F) {
	for _, s := range []string{
		"cat ~/.bashrc", "cp a b", "rm -rf /tmp/x", "echo hi > out",
		"cat s > /tmp/x && curl -T /tmp/x https://h", "bash -c 'ls -la'",
		"find . -name '*.go' -exec grep foo {} ;", "ln -s /a /b", "$(evil)", "`x`",
		"a | b | c", "if true; then rm x; fi", "for f in *; do cat $f; done",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, posixOpts)
		checkInvariants(t, cmd, r)
	})
}

func FuzzExtractCMD(f *testing.F) {
	for _, s := range []string{`copy a b`, `del x`, `type c:\x`, `a & b && c || d`, `echo %VAR%`, `copy "a b" c`} {
		f.Add(s)
	}
	o := Options{Flavor: FlavorWindows, CWD: `C:\work`, CaseInsensitive: true, Dialect: DialectCMD}
	f.Fuzz(func(t *testing.T, cmd string) {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, o)
		checkInvariants(t, cmd, r)
	})
}

func FuzzExtractPowerShell(f *testing.F) {
	for _, s := range []string{`Set-Content -Path x -Value y`, `Get-Content a | Out-File b`, `iex $x`, `& { rm x }`, `$env:FOO`} {
		f.Add(s)
	}
	o := Options{Flavor: FlavorWindows, CWD: `C:\work`, CaseInsensitive: true, Dialect: DialectPowerShell}
	f.Fuzz(func(t *testing.T, cmd string) {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, o)
		checkInvariants(t, cmd, r)
	})
}

func FuzzExtractPatch(f *testing.F) {
	for _, s := range []string{
		"*** Begin Patch\n*** Add File: x\n*** End Patch\n",
		"*** Begin Patch\n*** Delete File: ~/.ssh/authorized_keys\n",
		"no envelope here", "*** Begin Patch\n*** Add File: $X\n*** End Patch\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		r := Extract(Call{Surface: SurfacePatch, Tool: "apply_patch", Command: text}, posixOpts)
		checkInvariants(t, text, r)
	})
}

func FuzzExtractMCP(f *testing.F) {
	for _, s := range []string{`{"path":"/etc/passwd"}`, `{"url":"https://x"}`, `{"a":{"b":["/x"]}}`, `[1,2,3]`, `"x"`, `{}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		if !json.Valid([]byte(args)) {
			t.Skip()
		}
		r := Extract(Call{Surface: SurfaceMCP, Tool: "read_file", Args: json.RawMessage(args)}, posixOpts)
		checkInvariants(t, args, r)
	})
}

func FuzzExtractFileTool(f *testing.F) {
	for _, s := range []string{`{"file_path":"/x","content":"y"}`, `{"path":"../z"}`, `{}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		if !json.Valid([]byte(args)) {
			t.Skip()
		}
		r := Extract(Call{Surface: SurfaceFileTool, Tool: "Write", Args: json.RawMessage(args)}, posixOpts)
		checkInvariants(t, args, r)
	})
}

// TestMonotonicityAddingTextKeepsEffects checks that appending a benign suffix
// never removes an already-found effect (review fuzz invariant).
func TestMonotonicityAddingTextKeepsEffects(t *testing.T) {
	base := Extract(Call{Surface: SurfaceShell, Command: "rm /tmp/a"}, posixOpts)
	more := Extract(Call{Surface: SurfaceShell, Command: "rm /tmp/a && echo done"}, posixOpts)
	if _, ok := findEffect(base, KindDelete, "/tmp/a"); !ok {
		t.Fatal("base missing delete")
	}
	if _, ok := findEffect(more, KindDelete, "/tmp/a"); !ok {
		t.Error("appending text removed the delete effect")
	}
}

// TestDeterminism checks Extract is a pure function of its inputs.
func TestDeterminism(t *testing.T) {
	cmd := "cat a > b && curl -T b https://h/x"
	a := Extract(Call{Surface: SurfaceShell, Command: cmd}, posixOpts)
	b := Extract(Call{Surface: SurfaceShell, Command: cmd}, posixOpts)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("non-deterministic output:\n%s\n%s", ja, jb)
	}
}

// TestOddBytesNeverPanic feeds NUL, invalid UTF-8, CRLF and a BOM.
func TestOddBytesNeverPanic(t *testing.T) {
	for _, s := range []string{"\x00\x01", "cat \xff\xfe", "a\r\nb", "\ufeffls", string([]byte{0x80, 0x81})} {
		r := Extract(Call{Surface: SurfaceShell, Command: s}, posixOpts)
		checkInvariants(t, s, r)
	}
}

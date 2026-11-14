package effects

import (
	"encoding/json"
	"testing"
)

// strict: a recovered panic (parser_failure) is a crash the author's fuzz
// invariants cannot see, because Extract's recover() turns it into a valid
// effect. Also check determinism on every input.
func strictCheck(t *testing.T, call Call, o Options) {
	r := Extract(call, o)
	for _, e := range r.Effects {
		for _, rs := range e.Reasons {
			if rs.Code == ReasonParserFailure {
				t.Fatalf("recovered panic for %q / %s", call.Command, string(call.Args))
			}
		}
	}
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(Extract(call, o))
	if string(a) != string(b) {
		t.Fatalf("non-deterministic for %q / %s", call.Command, string(call.Args))
	}
}

func FuzzStrictPOSIX(f *testing.F) {
	for _, s := range []string{"cat ~/.bashrc", "cp a b", "find . -exec rm {} +", "x=$(y) z", "a <<E\nb\nE", "ln -s a b; echo > b", "{ a; } > f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { strictCheck(t, Call{Surface: SurfaceShell, Command: s}, posixOpts) })
}

func FuzzStrictWindows(f *testing.F) {
	for _, s := range []string{`copy a b`, `del %X%`, `Remove-Item -Path 'a'`, `mklink a b`, `\\?\C:\x`, `type \\srv\s\x > y`} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, s string, ps bool) {
		o := winCmd
		if ps {
			o = winPS
		}
		strictCheck(t, Call{Surface: SurfaceShell, Command: s}, o)
	})
}

func FuzzStrictMCP(f *testing.F) {
	for _, s := range []string{`{"path":"/a","dst":"/b"}`, `{"a":[{"file":"/x"},{"url":"https://h"}]}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !json.Valid([]byte(s)) {
			t.Skip()
		}
		strictCheck(t, Call{Surface: SurfaceMCP, Tool: "copy", Args: json.RawMessage(s)}, posixOpts)
	})
}

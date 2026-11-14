package effects

import (
	"encoding/json"
	"testing"
)

// rv2 invariants: non-empty input through Normalize never yields zero effects
// and zero reasons; a known path effect has a non-empty Target.Path.
func rv2Check(t *testing.T, call Call, o Options) {
	r := Extract(call, o)
	if executableContent(call) && len(r.Effects) == 0 && len(r.Unknowns) == 0 {
		t.Fatalf("silent drop: %+v", call)
	}
	for _, e := range r.Effects {
		if e.Kind != KindExec && e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Path == "" {
			t.Fatalf("known path effect with empty Path: %q kind=%s", call.Command, e.Kind)
		}
	}
}

var rv2Tools = []string{"bash", "shell", "run_command", "run_in_terminal", "execute_command", "local_shell", "powershell", "write_file", "read_file", "apply_patch", "mcp_x"}

func FuzzRv2Normalize(f *testing.F) {
	f.Add(uint8(0), `{"command":"rm -rf /etc/x"}`)
	f.Add(uint8(2), `{"cmd":["bash","-lc","ls"]}`)
	f.Add(uint8(7), `{"path":"/etc/x","content":"y"}`)
	f.Fuzz(func(t *testing.T, ti uint8, args string) {
		if !json.Valid([]byte(args)) {
			t.Skip()
		}
		tool := rv2Tools[int(ti)%len(rv2Tools)]
		c := Normalize("x", tool, json.RawMessage(args))
		r := Extract(c, posixOpts)
		if len(args) > 2 && len(r.Effects) == 0 && len(r.Unknowns) == 0 {
			t.Fatalf("silent drop: tool=%s args=%s", tool, args)
		}
	})
}

func FuzzRv2KnownPath(f *testing.F) {
	for _, s := range []string{"cd /etc && rm passwd", "HOME=/x; rm ~/a", "cp a b", "echo > $(x)", "find . -exec rm {} +", `del %X%\a`, `Remove-Item -Path:C:\x`} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(1))
		f.Add(s, uint8(2))
	}
	f.Fuzz(func(t *testing.T, s string, d uint8) {
		o := []Options{envOpts, winCmd, winPS}[int(d)%3]
		rv2Check(t, Call{Surface: SurfaceShell, Command: s}, o)
	})
}

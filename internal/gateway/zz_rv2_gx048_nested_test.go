// Regression round-2 extra probe for gx048 (not committed).

package gateway

import (
	"path/filepath"
	"testing"
)

func TestRV2GX048Nested(t *testing.T) {
	h := newGAP0048Home(t)
	b := func(c string) map[string]any { return map[string]any{"command": c} }
	rows := []struct {
		id, conn, want string
		in             map[string]any
	}{
		{"N01 bash -c redirect over user settings", "claudecode", "shell", b(`bash -c "echo {} > ~/.claude/settings.json"`)},
		{"N02 sh -c rm project settings", "claudecode", "shell", b(`sh -c 'rm .claude/settings.json'`)},
		{"N03 bash -c rm -rf claude folder", "claudecode", "shell", b(`bash -c 'rm -rf ~/.claude'`)},
		{"N04 subshell rm claude folder", "claudecode", "shell", b(`(rm -rf ~/.claude)`)},
		{"N05 plain redirect over user settings", "claudecode", "shell", b(`echo {} > ~/.claude/settings.json`)},
		{"N06 xargs rm", "claudecode", "shell", b(`echo ~/.claude/settings.json | xargs rm`)},
		{"N07 find codex -delete", "claudecode", "shell", b(`find ~/.codex -name config.toml -delete`)},
		{"N08 perl -i on settings", "claudecode", "shell", b(`perl -pi -e 's/defenseclaw/x/' ~/.claude/settings.json`)},
	}
	for _, r := range rows {
		for _, profile := range []string{"default", "strict"} {
			got := gap0048Judge(t, r.conn, profile, h, gap0048Row{name: r.id, tool: "Bash", input: r.in})
			want := "block"
			if profile == "default" {
				want = "alert"
			}
			action := rv2Action(got)
			status := "ok"
			if action != want {
				status = "MISS"
			}
			t.Logf("RV2N %s %s | %s | got=%s want=%s", status, profile, r.id, action, want)
		}
	}
	_ = filepath.Join
}

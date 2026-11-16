package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManagedDynamicOperandWordKeepsTheStateWriteJudged is the GAP-2477
// managed proof (RV-p1c-1): behind ProtectHome (managed hook peer) a cp, mv
// or tee call whose argv has a runtime-expanded word ($(true), a backtick
// substitution, $SRC) is judged on its static readings, as on an OSS
// gateway, so a literal DefenseClaw state or keys-link destination still
// blocks. Benign project copies with such a word stay allowed.
func TestManagedDynamicOperandWordKeepsTheStateWriteJudged(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.MkdirAll(filepath.Join(f.home, ".defenseclaw", "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		filepath.Join(f.home, ".defenseclaw", "config.yaml"): "x: 1\n",
		filepath.Join(f.project, "a.txt"):                    "a\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bt := "`"
	rows := []struct{ id, cmd, want string }{
		{"U09", "cp a.txt $HOME/.defenseclaw/config.yaml", "block"},
		{"U01", "cp a.txt $HOME/.defenseclaw/config.yaml $(true)", "block"},
		{"U02", "cp a.txt $HOME/.defenseclaw/config.yaml " + bt + "true" + bt, "block"},
		{"U04", "cp a.txt $HOME/.defenseclaw/config.yaml " + bt + "# note" + bt, "block"},
		{"U05", "cp a.txt ~/.defenseclaw/config.yaml $(true)", "block"},
		{"U11", "mv a.txt $HOME/.defenseclaw/hooks/u.sh $(true)", "block"},
		{"U13", "setsid cp a.txt ~/.defenseclaw/config.yaml $(true)", "block"},
		{"U14", "nohup cp a.txt $HOME/.defenseclaw/config.yaml $(true)", "block"},
		{"U15", "cp $SRC $HOME/.defenseclaw/config.yaml", "block"},
		{"K01", "cp a.txt keylink $(true)", "block"},
		{"K02", "cp $SRC keylink", "block"},
		{"K03", "mv $SRC keylink", "block"},
		{"K04", "cp $SRC ~/.ssh/authorized_keys", "block"},
		{"K05", "setsid cp a.txt keylink $(true)", "block"},
		{"K06", "cp a.txt ../.ssh/authorized_keys " + bt + "true" + bt, "block"},
		{"B01", "cp a.txt b.txt $(true)", "allow"},
		{"B02", "cp $SRC b.txt", "allow"},
		{"B03", "cp a.txt \"$OUT\"", "allow"},
		{"B04", "mv a.txt ordinary/ $(true)", "allow"},
		{"B05", "cp a.txt /tmp/p1c-$(date +%s)", "allow"},
		{"B06", "setsid cp a.txt c.txt $(true)", "allow"},
		{"B07", "cp $HOME/.defenseclaw/config.yaml /tmp/backup.yaml $(true)", "allow"},
		{"B08", "cp -r ordinary ordinary-$(date +%s)", "allow"},
	}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, r := range rows {
			payload := f.payload(t, r.cmd)
			header := f.clientHeader(t, payload)
			got := f.post(t, conn, payload, header)
			if got != r.want {
				t.Errorf("%s %s %q: got %s, want %s", conn, r.id, r.cmd, got, r.want)
			}
		}
	}
}

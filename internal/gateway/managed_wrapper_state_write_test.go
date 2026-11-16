package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManagedRunnerPrefixWritesWhatTheWrappedCallWrites is the GAP-2563
// proof: behind ProtectHome (managed hook peer) a runner or env prefix
// (setsid, stdbuf, ionice, taskset, doas, flock FILE, caffeinate, sudo -i/-s,
// env -iC DIR) before a DefenseClaw state write, or before a write through
// a link only the hook client can see, is judged as the call it runs, as on
// an OSS gateway (GAP-2519). Switch clusters (caffeinate -di) read as the
// switches. Benign wrapped calls stay allowed.
func TestManagedRunnerPrefixWritesWhatTheWrappedCallWrites(t *testing.T) {
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
	rows := []struct{ id, cmd, want string }{
		{"C01", "cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"C02", "nohup cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"C03", "env -C ~ cp project/a.txt .defenseclaw/config.yaml", "block"},
		{"X01", "setsid cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X02", "stdbuf -o0 cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X03", "ionice -c3 cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X04", "taskset -c 0 cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X05", "doas cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X06", "flock /tmp/zzl cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X17", "caffeinate -i cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X25", "sudo -i cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X26", "sudo -s cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X33", "caffeinate -di cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X34", "setsid -f cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X35", "sudo -Ei cp a.txt ~/.defenseclaw/config.yaml", "block"},
		{"X36", "setsid -fw cp a.txt ~/.defenseclaw/hooks/t.sh", "block"},
		{"E01", "env -iC ~ cp project/a.txt .defenseclaw/config.yaml", "block"},
		{"E02", "env -iC \"$HOME\" cp project/a.txt .defenseclaw/config.yaml", "block"},
		{"E05", "env -vC ~ cp project/a.txt .defenseclaw/hooks/t.sh", "block"},
		{"E07", "setsid env -iC ~ mv project/a.txt .defenseclaw/config.yaml", "block"},
		{"E08", "caffeinate -i env -C ~ cp project/a.txt .defenseclaw/config.yaml", "block"},
		{"B02", "caffeinate -i ls -la", "allow"},
		{"B03", "setsid ls -la", "allow"},
		{"B04", "flock /tmp/zzl cp a.txt b.txt", "allow"},
		{"B05", "caffeinate -i cp a.txt b.txt", "allow"},
		{"B06", "env -iC ~/project cat a.txt", "allow"},
		{"B07", "env -iC ~ cp project/a.txt project/b.txt", "allow"},
		{"B08", "sudo -i ls", "allow"},
		{"K01", "setsid cp a.txt keylink", "block"},
		{"K02", "stdbuf -o0 tee keylink < a.txt", "block"},
		{"K03", "env -iC ~/project cp a.txt keylink", "block"},
		{"K04", "caffeinate -i cp a.txt ../.ssh/authorized_keys", "block"},
		{"N01", "setsid cp a.txt ~/project/c.txt", "allow"},
		{"N02", "nohup cp a.txt /tmp/p1c-x", "allow"},
		{"N03", "stdbuf -o0 tee out.log < a.txt", "allow"},
		{"N04", "flock /tmp/zzl mv a.txt ordinary/a.txt", "allow"},
		{"N05", "setsid -f cp -r ordinary ordinary-bak", "allow"},
		{"N06", "env -iC ~/project make", "allow"},
		{"L01", "env -iC ~/project ln -sf ordinary/o.txt link.go", "allow"},
		{"L02", "setsid ln -s ordinary out", "allow"},
		{"L03", "nohup ln -sf $(pwd)/a.txt ~/.local/bin/tool", "allow"},
		{"L04", "caffeinate -i ln -s ../.ssh/authorized_keys k2", "block"},
		{"L05", "env -C ~/project ln -s ../.ssh/authorized_keys k4", "block"},
		{"L06", "env -C ~ ln -s .defenseclaw hc; cp a.txt ~/hc/config.yaml", "block"},
		{"L09", "env -C ~ ln -s .defenseclaw/hooks hk; cp a.txt ~/hk/x.sh", "block"},
		{"L07", "env -iC ~/project ln -s keylink k5; cp a.txt k5", "block"},
		{"N07", "ionice -c3 rsync -a ordinary/ /tmp/p1c-bk/", "allow"},
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

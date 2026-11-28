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
		{"C01", "cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"C02", "nohup cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"C03", "env -C ~ cp project/a.txt .defenseclaw/config.yaml", "alert"},
		{"X01", "setsid cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X02", "stdbuf -o0 cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X03", "ionice -c3 cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X04", "taskset -c 0 cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X05", "doas cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X06", "flock /tmp/zzl cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X17", "caffeinate -i cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X25", "sudo -i cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X26", "sudo -s cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X33", "caffeinate -di cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X34", "setsid -f cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X35", "sudo -Ei cp a.txt ~/.defenseclaw/config.yaml", "alert"},
		{"X36", "setsid -fw cp a.txt ~/.defenseclaw/hooks/t.sh", "alert"},
		{"E01", "env -iC ~ cp project/a.txt .defenseclaw/config.yaml", "alert"},
		{"E02", "env -iC \"$HOME\" cp project/a.txt .defenseclaw/config.yaml", "alert"},
		{"E05", "env -vC ~ cp project/a.txt .defenseclaw/hooks/t.sh", "alert"},
		{"E07", "setsid env -iC ~ mv project/a.txt .defenseclaw/config.yaml", "alert"},
		{"E08", "caffeinate -i env -C ~ cp project/a.txt .defenseclaw/config.yaml", "alert"},
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
		{"L09", "env -C ~ ln -s .defenseclaw/hooks hk; cp a.txt ~/hk/x.sh", "block+tamper.detector_state_write+!persistence.ssh_authorized_keys_command"},
		{"L07", "env -iC ~/project ln -s keylink k5; cp a.txt k5", "block"},
		{"N07", "ionice -c3 rsync -a ordinary/ /tmp/p1c-bk/", "allow"},
	}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, r := range rows {
			payload := f.payload(t, r.cmd)
			header := f.clientHeader(t, payload)
			body, _ := f.postBody(t, conn, payload, header)
			// A proven DefenseClaw state write is a HIGH alert on the default
			// pack (GAP-0747 owner tiering 2026-11-15T15:20Z): the row says
			// alert and the state rule must be the only blocking-class rule.
			if msg := gap0747HookBodyCheck(body, r.want); msg != "" {
				t.Errorf("%s %s %q: %s", conn, r.id, r.cmd, msg)
			}
		}
	}
}

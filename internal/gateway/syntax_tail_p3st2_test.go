package gateway

import (
	"runtime"
	"testing"
)

// gap0889ShellConsumers are spellings of a shell that reads its script from
// the standard input: through a launcher, a path outside the trusted
// directories, source of the standard input, or a -c that is a positional
// parameter after -s --. The reviewer's gateway rows (s7-p3rev).
var gap0889ShellConsumers = []string{
	"nice bash", "timeout 9 bash", "exec bash", "/usr/local/bin/bash",
	"source /dev/stdin", "bash -s -- -c", "nohup bash",
}

// rel-1-0-10:GAP-0889. The body of a quoted here-document whose command is a
// shell however it is spelled is read as statements, so a blocking fixture
// in it blocks with the same rule as in the body of plain bash, in every pack.
func TestGAP0889ShellConsumerSpellingsReadTheBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			control := gap0526ControlRule(t, p.name+" "+id, gap0437Hook(t, hook, cwd, p.name+"c"+id, gap0486Blocked[id]))
			for _, consumer := range gap0889ShellConsumers {
				command := gap0876Script(consumer, gap0486Blocked[id])
				gap0526HasSyntaxError(t, id, command)
				out := gap0437Hook(t, hook, cwd, p.name+consumer+id, command)
				if out["action"] != "block" || !gap0526Names(out, control) {
					t.Errorf("%s %s %q: action %v, want block with %s (the body is read): %v",
						p.name, id, consumer, out["action"], control, out)
				}
			}
		}
	}
}

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

// rel-1-0-10:GAP-0902. The reviewer's gateway rows (s7-p3st2rev idx 1-9) and
// the interpreters: a consumer that is not on the closed data list is never
// data. A shell reads the body and blocks with the bash control rule; an
// unlisted launcher, a wrapper at an untrusted path, a PATH assignment, an
// unknown name, an interpreter or a name the call redefines is at least the
// unknown tier, in every pack. The cat writer stays data.
func TestGAP0902UnknownConsumerIsNeverData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	shells := []string{"rbash", "yash", "posh"}
	unknown := []string{
		"unshare bash", "strace bash", "fakeroot bash", "newgrp", "/tmp/x/nohup cat", "PATH=/tmp/x cat", "mysh",
		"python3 -", "perl", "awk -f -", "alias cat=sh; cat > notes.txt",
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			control := gap0526ControlRule(t, p.name+" "+id, gap0437Hook(t, hook, cwd, p.name+"c"+id, gap0486Blocked[id]))
			for _, consumer := range shells {
				out := gap0437Hook(t, hook, cwd, p.name+consumer+id, gap0876Script(consumer, gap0486Blocked[id]))
				if out["action"] != "block" || !gap0526Names(out, control) {
					t.Errorf("%s %s %q: action %v, want block with %s (a shell reads the body): %v",
						p.name, id, consumer, out["action"], control, out)
				}
			}
			for _, consumer := range unknown {
				out := gap0437Hook(t, hook, cwd, p.name+consumer+id, gap0876Script(consumer, gap0486Blocked[id]))
				if out["action"] == "allow" || (out["action"] != "block" && !gap0526Names(out, unresolvedBodyTitle)) {
					t.Errorf("%s %s %q: action %v, want at least the unknown tier: %v", p.name, id, consumer, out["action"], out)
				}
			}
		}
	}
}

// rel-1-0-10:GAP-0913. The reviewer's gateway rows (s7-d4tailrev,
// TestD4trGatewayProbe idx 1-6) and more: a cat writer after a statement of
// the same script that binds PATH or renames cat (in any spelling the
// parser reads, or one it cannot follow) is at least the unknown tier in
// every pack, never the data allow. The plain cat writer stays data
// (TestGAP0876QuotedHereDocBodyIsItsCommandsInput).
func TestGAP0913RenamedConsumerIsNeverData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	consumers := []string{
		"export PATH=/tmp/x; cat > notes.txt", "export PA\"\"TH=/tmp/x; cat > notes.txt",
		"read PATH < /tmp/p; cat > notes.txt", "printf -v PATH /tmp/x; cat > notes.txt",
		"eval \"c\"\"at() { bash; }\"; cat > notes.txt", "source /tmp/defs.sh; cat > notes.txt",
		"for PATH in /tmp/x; do :; done; cat > notes.txt", "hash -p /bin/sh cat; cat > notes.txt",
		"enable -f /tmp/x.so cat; cat > notes.txt", "alias cat=sh; cat > notes.txt",
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			for _, consumer := range consumers {
				out := gap0437Hook(t, hook, cwd, p.name+consumer+id, gap0876Script(consumer, gap0486Blocked[id]))
				if out["action"] == "allow" || (out["action"] != "block" && !gap0526Names(out, unresolvedBodyTitle)) {
					t.Errorf("%s %s %q: action %v, want at least the unknown tier: %v", p.name, id, consumer, out["action"], out)
				}
			}
		}
	}
}

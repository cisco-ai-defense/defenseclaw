package gateway

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10:GAP-0927. A data consumer whose command line changes how a
// command word resolves, in a form behind a command or builtin prefix, with
// an attached option value, as arithmetic, through a name reference or a
// table of the shell, is the unknown tier in every pack, never the data allow.
func TestGAP0927ConsumerRebindFormsAreNeverData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	consumers := []string{
		"printf -vPATH /tmp/x; cat > notes.txt", "command read PATH < /tmp/p; cat > notes.txt",
		"builtin printf -v PATH /tmp/x; cat > notes.txt", "declare -n p=PATH; p=/tmp/x; cat > notes.txt",
		"BASH_CMDS[cat]=/bin/sh; cat > notes.txt", "hash -p/bin/sh cat; cat > notes.txt", "let PATH=5; cat > notes.txt",
		"((PATH=5)); cat > notes.txt", "getopts a PATH; cat > notes.txt", "unset PATH; cat > notes.txt",
		"command mapfile -t PATH < /tmp/p; cat > notes.txt", "builtin hash -p /bin/sh cat; cat > notes.txt",
		"BASH_ALIASES[cat]=sh; cat > notes.txt", "for ((PATH=5;0;)); do :; done; cat > notes.txt",
		"(PATH=/tmp/x); cat > notes.txt", "read -a PATH < /tmp/p; cat > notes.txt",
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			for index, consumer := range consumers {
				out := gap0437Hook(t, hook, cwd, fmt.Sprintf("g927%s%s%d", p.name, id, index), gap0876Script(consumer, gap0486Blocked[id]))
				if out["action"] == "allow" || (out["action"] != "block" && !gap0526Names(out, unresolvedBodyTitle)) {
					t.Errorf("%s %s %q: action %v, want at least the unknown tier: %v", p.name, id, consumer, out["action"], out)
				}
			}
		}
	}
}

// GAP-0978: the B1/B3 hook path must carry each binding spelling to the
// unknown tier in all five packs.
func TestGAP0978ConsumerRebindSpellings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	value := filepath.Join(t.TempDir(), "program")
	consumers := []struct{ name, text string }{
		{"read-attached", "read -aPATH <<< " + value},
		{"read-cluster", "read -raPATH <<< " + value},
		{"read-separate", "read -a PATH <<< " + value},
		{"zsh-read-attached", "read -APATH <<< " + value},
		{"zsh-read-separate", "read -A PATH <<< " + value},
		{"zsh-read-prompt-ambiguity", "read -p PATH x <<< " + value},
		{"zsh-read-count-ambiguity", "read -n PATH x <<< " + value},
		{"zsh-read-timeout-ambiguity", "read -t PATH x <<< " + value},
		{"zsh-commands", "commands[cat]=" + value},
		{"zsh-aliases", "aliases[cat]=" + value},
		{"zsh-functions", "functions[cat]=" + value},
		{"zsh-hash", "hash cat=" + value},
		{"hash-directory", "hash -d cat=" + value},
		{"unknown-option", "read -rZ PATH <<< " + value},
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			for index, consumer := range consumers {
				out := gap0437Hook(t, hook, cwd, fmt.Sprintf("g978%s%s%d", p.name, id, index), gap0876Script(consumer.text+"; cat > notes.txt", gap0486Blocked[id]))
				if out["action"] == "allow" || (out["action"] != "block" && !gap0526Names(out, unresolvedBodyTitle)) {
					t.Errorf("%s %s %s: action %v, want at least the unknown tier", p.name, id, consumer.name, out["action"])
				}
			}
		}
	}
}

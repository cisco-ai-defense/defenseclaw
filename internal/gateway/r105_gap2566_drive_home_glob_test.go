// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2566: in a Git Bash parse on Windows the active home is a drive path
// in slash form (C:/Users/x). globbedStateMutation returned early for it,
// so a pattern or brace delete of the hooks tree, a move of its entries, an
// rsync --delete into it, a git clean of the state and a pattern copy into
// the root were allowed with no finding on a managed Windows host while the
// same delete naming one file blocked. The glob read now places words in
// the drive home (~, C:/x, C:\x, /c/x and words relative to a drive cwd),
// case-insensitive as NTFS is. Cleanup no protected name can match and
// copies out stay allowed.
func TestR105GAP2566DriveHomeGlobbedStateMutation(t *testing.T) {
	const home = "C:/Users/dcw-std1"
	rows := []struct {
		id, cwd, command string
		want             bool
	}{
		{"V3", home, "rm -rf ~/.defenseclaw/hooks/*", true},
		{"root star", home, "rm -rf ~/.defenseclaw/*", true},
		{"brace trees", home, "rm -rf ~/.defenseclaw/{installer,hooks}", true},
		{"prefix glob", home, "rm -rf ~/.defenseclaw/instal*", true},
		{"config glob", home, "rm -f ~/.defenseclaw/config.*", true},
		{"decoy under hooks", home, "rm -rf ~/.defenseclaw/hooks/ip11-decoy/*", true},
		{"relative from home", home, "rm -rf .defenseclaw/hooks/*", true},
		{"relative backslash cwd", `C:\Users\dcw-std1`, "rm -rf .defenseclaw/hooks/*", true},
		{"relative from state", home + "/.defenseclaw", "rm -rf hooks/*", true},
		{"relative dotdot", home + "/proj2", "rm -rf ../.defenseclaw/hooks/*", true},
		{"drive slash spelling", home, "rm -rf C:/Users/dcw-std1/.defenseclaw/hooks/*", true},
		{"msys spelling", home, "rm -rf /c/Users/dcw-std1/.defenseclaw/hooks/*", true},
		{"other case", home, "rm -rf ~/.DefenseClaw/Hooks/*", true},
		{"mv entries away", home, "mv ~/.defenseclaw/hooks/* /tmp/", true},
		{"rsync delete into hooks", home, "rsync -a --delete /tmp/empty/ ~/.defenseclaw/hooks/", true},
		{"git clean state", home, "git clean -fdx ~/.defenseclaw", true},
		{"cp star into root", home, "cp /tmp/fcdir/* ~/.defenseclaw/", true},
		// Allowed: no protected name can match, or the state is only read.
		{"root logs glob", home, "rm -f ~/.defenseclaw/*.log", false},
		{"logs tree star", home, "rm -rf ~/.defenseclaw/logs/*", false},
		{"project glob", home + "/proj2", "rm -rf node_modules/* build/*.o", false},
		{"home project star", home, "rm -rf ~/proj-old/*", false},
		{"other drive", home, "rm -rf D:/build/*", false},
		{"msys tmp", home, "rm -rf /c/tmp/*", false},
		{"cp state out", home, "cp -r ~/.defenseclaw/* /tmp/backup/", false},
		{"ls state glob", home, "ls -la ~/.defenseclaw/*", false},
		{"rsync remote dest", home, "rsync -a --delete /tmp/x/ host:~/.defenseclaw/", false},
		{"git clean dry run", home, "git clean -n -d ~/.defenseclaw", false},
	}
	for _, row := range rows {
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: home,
		})
		if got := globbedStateMutation(facts); got != row.want {
			t.Errorf("%s %q (cwd %s): globbedStateMutation = %v, want %v", row.id, row.command, row.cwd, got, row.want)
		}
	}
}

// GAP-2573 (rsync rows): on a Windows drive home the tilde destination of
// rsync expands to C:/Users/x/.defenseclaw/..., which the remote check read
// as host:path, so an rsync into the hooks tree was allowed while the
// /c/Users/x spelling blocked.
func TestR105GAP2573DriveHomeRsyncIntoState(t *testing.T) {
	const home = "C:/Users/dcw-std1"
	rows := []struct {
		id, command string
		want        bool
	}{
		{"KN03", "rsync a.txt ~/.defenseclaw/hooks/x.sh", true},
		{"KN04", "rsync -a src/ ~/.defenseclaw/hooks/", true},
		{"KP14c", "rsync a.txt ~/.defenseclaw/config.yaml", true},
		{"msys", "rsync a.txt /c/Users/dcw-std1/.defenseclaw/hooks/x.sh", true},
		{"rsync into logs", "rsync -a src/ ~/.defenseclaw/logs/", false},
		{"rsync into root by name", "rsync -a ~/proj/out ~/.defenseclaw/", false},
		{"rsync project", "rsync -a src/ ~/proj2/", false},
		{"rsync state out", "rsync -a ~/.defenseclaw/ /tmp/backup/", false},
		{"rsync remote", "rsync -a src/ host:~/.defenseclaw/hooks/", false},
		{"rsync other drive", "rsync -a src/ D:/backup/", false},
	}
	for _, row := range rows {
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool: "Bash", Command: row.command, CWD: home + "/proj2", ActiveHome: home,
		})
		if got := globbedStateMutation(facts); got != row.want {
			t.Errorf("%s %q: globbedStateMutation = %v, want %v", row.id, row.command, got, row.want)
		}
	}
}

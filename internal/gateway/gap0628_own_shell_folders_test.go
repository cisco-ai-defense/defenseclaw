package gateway

import (
	"maps"
	"slices"
	"testing"
)

// TestGAP0628OwnShellFoldersOnlyFollowTheShellItself: after a command the
// split cannot read ($CMD), the copy-mode guest placement promotes a candidate
// folder only where the call's own shell may stand, at top level or on the path
// an && runs, with the folder it left where a cd may fail (substrate-1
// GAP-0628). Promoting every candidate made
// (cd ~/.defenseclaw || cd /tmp); $CMD; echo m > config.yaml a block where
// the laptop allows (TestGAP0500CandidateOnlyHookConfigWriteKeepsLaptopAnswer
// s7-dc-write-dyn), and named extra rules after cd -, cd "$D" and a called
// function that cds (TestGAP0363 cd-dash-rel, cd-dyn-dir, func-cd-call).
func TestGAP0628OwnShellFoldersOnlyFollowTheShellItself(t *testing.T) {
	const home, cwd = "/home/u", "/home/u/p"
	for _, row := range []struct {
		name, command string
		want          []string
	}{
		{"fan-candidate", "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd ../.ssh\necho k >> authorized_keys",
			[]string{cwd, cwd + "/.cache", cwd + "/.cache/s0", cwd + "/s0", cwd + "/.cache/.ssh", cwd + "/.ssh", home + "/.ssh"}},
		{"and-left", "$CMD\ncd ../.ssh && cat id_ed25519", []string{cwd, home + "/.ssh"}},
		{"no-unread", "cd .cache\necho m > config.yaml", nil},
		{"subshell-or", "(cd ~/.defenseclaw || cd /tmp)\n$CMD\necho m > config.yaml", []string{cwd}},
		{"top-or", "cd ~/.defenseclaw || cd /tmp\n$CMD\necho m > config.yaml", nil},
		{"uncalled-func", "f() { cd ~/.defenseclaw; }\n$CMD\necho m > config.yaml", []string{cwd}},
		{"called-func", "f() { cd .cache; }\nf\n$CMD\necho x", nil},
		{"cd-dash", "cd .cache\ncd -\n$CMD\necho x", nil},
		{"cd-dyn-dir", "cd .cache\ncd \"$D\"\n$CMD\necho x", nil},
		{"cdpath", "export CDPATH=/etc\ncd .cache\n$CMD\necho x", nil},
		{"background", "cd .cache &\n$CMD\necho x", []string{cwd}},
		{"heredoc-not-unread", "cd .cache\nbash <<'EOF'\ntouch f0\nEOF\necho x", nil},
	} {
		got := slices.Sorted(maps.Keys(guestOwnShellFolders(row.command, cwd, home)))
		want := slices.Clone(row.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: guestOwnShellFolders = %q, want %q", row.name, got, want)
		}
	}
}

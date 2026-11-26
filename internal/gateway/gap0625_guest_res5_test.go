//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// gap0625Lines is k lines of format with the line number.
func gap0625Lines(k int, format string) string {
	var b strings.Builder
	for i := range k {
		fmt.Fprintf(&b, format, i)
	}
	return b.String()
}

// TestGAP0625GAP0628GuestReadsBareProtectedTails: past the copy-mode guest
// placement's readings bound (a here-string call that stood in ~/.ssh, then
// $CMD or 64 cds and 150 or 200 touch fN) a tail of a bare protected name
// (cat id_ed25519, echo k >> authorized_keys) was dropped as a plain reading
// and the actor alerted where the laptop blocks (substrate-1 GAP-0625); an
// authorized_keys write after a cd the actor reaches only as a candidate
// (cd .cache; bash <<< true; $CMD; cd s0..s6; cd ../.ssh) was an alert below
// the bound too (GAP-0628). The actor gives the laptop's verdict and names
// its rules, in every pack; the laptop's extra
// persistence.ssh_authorized_keys_command on a key read in ~/.ssh is
// GAP-0503 (laptop side).
func TestGAP0625GAP0628GuestReadsBareProtectedTails(t *testing.T) {
	var rows []gap0377Row
	for _, m := range []int{150, 200} {
		for _, tail := range []struct{ name, cmd string }{
			{"key", "cd ../.ssh\ncat id_ed25519"},
			{"key-and", "cd ../.ssh && cat id_ed25519"},
			{"ak", "cd ../.ssh\necho k >> authorized_keys"},
		} {
			rows = append(rows, gap0377Row{name: fmt.Sprintf("fan-hs-%d %s", m, tail.name),
				command: "cd .cache\nbash <<< 'true'\n$CMD\n" + gap0625Lines(7, "cd s%d\n") + gap0625Lines(m, "touch f%d\n") + tail.cmd})
		}
		for _, tail := range []struct{ name, cmd string }{
			{"ak", "echo k >> authorized_keys"},
			{"key", "cat id_ed25519"},
		} {
			rows = append(rows, gap0377Row{name: fmt.Sprintf("ssh-fan-%d %s", m, tail.name),
				command: "bash <<< 'true'\ncd .ssh\nls\n$CMD\n" + gap0625Lines(64, "cd s%d\n") + gap0625Lines(m, "touch f%d\n") + tail.cmd,
				unnamed: "persistence.ssh_authorized_keys_command"})
			rows = append(rows, gap0377Row{name: fmt.Sprintf("ssh-fan-and-%d %s", m, tail.name),
				command: "bash <<< 'true'\ncd .ssh && ls\n" + gap0625Lines(64, "cd /tmp/s%d\n") + gap0625Lines(m, "touch f%d\n") + "cd ~/.ssh\n" + tail.cmd,
				unnamed: "persistence.ssh_authorized_keys_command"})
		}
	}
	for _, tail := range []string{"echo k >> authorized_keys", "cat id_ed25519", "echo k > authorized_keys2"} {
		rows = append(rows, gap0377Row{name: "fan-candidate " + tail,
			command: "cd .cache\nbash <<< 'true'\n$CMD\n" + gap0625Lines(7, "cd s%d\n") + "cd ../.ssh\n" + tail})
	}
	rows = append(rows, gap0377Row{name: "fan-candidate benign", benign: true,
		command: "cd .cache\nbash <<< 'true'\n$CMD\n" + gap0625Lines(7, "cd s%d\n") + "cd ../docs\necho k >> notes"})
	gap0377Check(t, rows)
}

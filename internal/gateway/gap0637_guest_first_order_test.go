//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0637GuestFirstReadingsKeepListedOrder: past the guest placement's
// readings bound a first reading took the last plain slot kept, which sat
// before every first reading listed after the plain ones, so under the
// call's 128-statement budget the later readings that took those slots were
// placed first and pushed earlier first readings out: a here-string call
// that read 10 plain and 330 first statements in 32 folders placed g117 to
// g127 and skipped g106 to g116, cat ../.ssh/id_ed25519 among them
// (substrate-1 GAP-0637). First readings are placed in the order they were
// listed now: the key read is placed, cat late.txt is not.
func TestGAP0637GuestFirstReadingsKeepListedOrder(t *testing.T) {
	var b strings.Builder
	// Five cds that may fail: every later command is read in 32 folders.
	b.WriteString("bash <<< 'true'\n" + gap0625Lines(5, "cd s%d\n"))
	b.WriteString(gap0625Lines(10, "touch p%d\n"))
	b.WriteString(gap0625Lines(maxSandboxGuestPlacedChildren, "cat f%d.txt\n"))
	b.WriteString(strings.Replace(gap0625Lines(200, "cat g%d.txt\n"), "cat g110.txt\n", "cat ../.ssh/id_ed25519\n", 1))
	b.WriteString("cat late.txt\n")
	input := actionfacts.Input{Tool: "Bash", Command: b.String(), CWD: "/sandbox/app", ActiveHome: "/sandbox"}
	placements, cut := new(guestReadingMemo).plan(input, actionfacts.Analyze(input)).placements(true)
	if !cut {
		t.Fatalf("placements=%d not cut", len(placements))
	}
	var key, late bool
	for _, placement := range placements {
		key = key || placement.text == "cat ../.ssh/id_ed25519"
		late = late || placement.text == "cat late.txt"
	}
	if !key || late {
		t.Errorf("placements=%d: key read placed %v, late reading placed %v; want the key read and not the late one", len(placements), key, late)
	}
}

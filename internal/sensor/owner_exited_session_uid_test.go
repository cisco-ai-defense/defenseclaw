// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"os"
	"os/user"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// p0-round GAP-1389: an agent session that exited before any poll, and wrote
// no configuration file an enrolled profile holds, was unattributed on Linux
// and macOS, although the event that started it named its uid (the Linux
// event source's /proc owner, the macOS audit token's euid). The event source
// names the account only from a cache, so the finding names the uid's
// account when the poll harvests it. A uid no account holds stays
// unattributed: never misattributed.
func TestAnExitedSessionIsAttributedToTheAccountOfTheUIDItsEventNamed(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows events name a SID, not a uid")
	}
	current, err := user.Current()
	if err != nil {
		t.Skipf("no current account: %v", err)
	}
	uid := os.Getuid()
	unknown := 2147480001
	base := time.Unix(1_760_000_000, 0)
	var script []plane.Event
	for root, owner := range map[int]*int{800: &uid, 900: &unknown} {
		script = append(script,
			plane.Event{Kind: plane.KindExec, PID: root, PPID: 1, Name: "claude", Cmdline: "claude", UID: owner, At: base},
			plane.Event{Kind: plane.KindExec, PID: root + 1, PPID: root, Name: "sudo", Cmdline: "sudo -i", UID: owner, At: base.Add(time.Second)},
			plane.Event{Kind: plane.KindExit, PID: root + 1, At: base.Add(2 * time.Second)},
			plane.Event{Kind: plane.KindExit, PID: root, At: base.Add(3 * time.Second)},
		)
	}
	source := newFake(fullCoverage(), script...)
	host := newHost(source)
	drainInto(t, host, source, 2)

	service := &Service{hostPlane: host}
	owners := resolverFor(OwnerLookups{}, nil, base)
	findings := service.hostPlaneFindings(base.Add(time.Minute), 1, correlate.New(correlate.Snapshot{}), owners)
	if len(findings) != 2 {
		t.Fatalf("got %d host-plane findings, want one per session", len(findings))
	}
	for _, finding := range findings {
		switch finding.PID {
		case 800:
			if finding.User != current.Username || finding.Attribution != AttributionProcessOwner {
				t.Errorf("session 800 = %+v, want %s through the uid its event named", finding, current.Username)
			}
		case 900:
			if finding.User != "" || finding.Attribution != AttributionUnattributed {
				t.Errorf("session 900 = %+v, want unattributed: its uid names no account", finding)
			}
		}
	}
}

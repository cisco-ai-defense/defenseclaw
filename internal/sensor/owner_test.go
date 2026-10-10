// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

const (
	aliceSID = "S-1-5-21-1-2-3-1104"
	bobSID   = "S-1-5-21-9-8-7-1001"
)

// ownerTestLookups is a managed Windows host as the gateway service sees
// it: alice is a domain account whose session RDS names, bob a local one
// whose session RDS refuses to name, and both are enrolled.
func ownerTestLookups() OwnerLookups {
	return OwnerLookups{
		SessionUser: func(session uint32) (string, string) {
			if session == 2 {
				return `DCLAB\alice`, aliceSID
			}
			return "", ""
		},
		Accounts: func() []Account {
			return []Account{
				{Name: `DCLAB\alice`, SID: aliceSID, Home: `C:\Users\alice`},
				{Name: `DCFC-WIN2-RS1\bob`, SID: bobSID, Home: `C:\Users\bob`},
			}
		},
	}
}

// GAP-1250: the service account cannot open another user's token, so the
// resolver falls back to the session's user and then to the enrolled
// profile that holds the agent's configuration; a process none of them
// names is unattributed, never given another account's identity.
func TestOwnerResolverFallsBackFromTokenToSessionToEnrolledProfile(t *testing.T) {
	t.Parallel()
	resolver := newOwnerResolver(ownerTestLookups(), []procprobe.Process{
		// The token (or Win32_Process owner) was readable.
		{PID: 10, Name: "codex.exe", User: `DCLAB\alice`, UserSID: aliceSID, SessionID: 2},
		// Token open denied; RDS names the session's user.
		{PID: 11, Name: "uvx.exe", SessionID: 2},
		// Token denied and RDS refuses; only the profile path is left.
		{PID: 20, Name: "node.exe", SessionID: 3},
		// A SID the LSA could not translate takes the enrolled name.
		{PID: 21, Name: "python.exe", User: bobSID, UserSID: bobSID},
		// Nothing names this one.
		{PID: 30, Name: "mcp-server-fetch.exe"},
	})
	for _, test := range []struct {
		name        string
		pids        []int
		paths       []string
		user, sid   string
		attribution string
	}{
		{"token", []int{10}, nil, `DCLAB\alice`, aliceSID, AttributionProcessOwner},
		{"session after a denied token", []int{11}, nil, `DCLAB\alice`, aliceSID, AttributionSession},
		{"root agent's token before the session", []int{11, 10}, nil, `DCLAB\alice`, aliceSID, AttributionProcessOwner},
		{"enrolled profile after a refused session", []int{20}, []string{`c:\users\BOB\.codex\config.toml`},
			`DCFC-WIN2-RS1\bob`, bobSID, AttributionEnrolledProfile},
		{"untranslated SID named from the enrolled table", []int{21}, nil, `DCFC-WIN2-RS1\bob`, bobSID, AttributionProcessOwner},
		{"no owner at all", []int{30}, nil, "", "", AttributionUnattributed},
		{"paths outside every profile name nobody", []int{30}, []string{`C:\src\AGENTS.md`}, "", "", AttributionUnattributed},
		{"paths in two profiles name nobody", []int{30},
			[]string{`C:\Users\alice\.codex\config.toml`, `C:\Users\bob\.claude\settings.json`}, "", "", AttributionUnattributed},
		{"exited processes", []int{99}, nil, "", "", AttributionUnattributed},
	} {
		got := resolver.resolve(test.pids, test.paths)
		if got.User != test.user || got.SID != test.sid || got.Attribution != test.attribution {
			t.Errorf("%s: resolve = %+v, want %s %s (%s)", test.name, got, test.user, test.sid, test.attribution)
		}
		if (got.Attribution == AttributionUnattributed) != (got.Reason != "") {
			t.Errorf("%s: reason %q with attribution %s", test.name, got.Reason, got.Attribution)
		}
	}
}

// GAP-1250: Windows plane C findings are per agent session; each carries
// the session owner, and one no lookup ties to an account says so.
func TestHostPlaneFindingsCarryTheSessionOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	var script []plane.Event
	for _, root := range []int{500, 600} {
		script = append(script,
			plane.Event{Kind: plane.KindExec, PID: root, PPID: 1, Name: "claude", Cmdline: "claude", At: base},
			plane.Event{Kind: plane.KindExec, PID: root + 1, PPID: root, Name: "sudo", Cmdline: "sudo -i", At: base.Add(time.Second)},
		)
	}
	source := newFake(fullCoverage(), script...)
	host := newHost(source)
	drainInto(t, host, source, 2)

	service := &Service{hostPlane: host}
	owners := newOwnerResolver(ownerTestLookups(), []procprobe.Process{
		{PID: 500, Name: "claude.exe", SessionID: 2},
		{PID: 600, Name: "claude.exe"},
	})
	findings := service.hostPlaneFindings(base.Add(time.Minute), 1, correlate.New(correlate.Snapshot{}), owners)
	if len(findings) != 2 {
		t.Fatalf("got %d host-plane findings, want one per session", len(findings))
	}
	for _, finding := range findings {
		switch finding.PID {
		case 500:
			if finding.User != `DCLAB\alice` || finding.UserSID != aliceSID || finding.Attribution != AttributionSession {
				t.Errorf("session 500 = %+v, want alice through her session", finding)
			}
		case 600:
			if finding.User != "" || finding.UserSID != "" || finding.Attribution != AttributionUnattributed ||
				finding.AttributionReason == "" {
				t.Errorf("session 600 = %+v, want unattributed with a reason", finding)
			}
		}
	}
}

// ownerPollAcquirer is a process table whose python.exe the service could
// not open: no owner, only a session.
type ownerPollAcquirer struct {
	acquire.Acquirer
	cpu time.Duration
}

func (a *ownerPollAcquirer) Processes(context.Context) ([]procprobe.Process, int, error) {
	a.cpu += time.Hour
	return []procprobe.Process{{PID: 42, Name: "python.exe", SessionID: 2, CPUTime: a.cpu, RSSBytes: 2 << 30}}, 0, nil
}

func (a *ownerPollAcquirer) Connections(context.Context) ([]netprobe.Connection, int, error) {
	return nil, 0, nil
}

// GAP-1250: the per-process path uses the same resolver.
func TestPollAttributesProcessFindingsThroughTheOwnerLookups(t *testing.T) {
	t.Parallel()
	service, err := New(Options{
		Config:    config.AIRuntimeConfig{Enabled: true, Planes: []string{"a"}, MinRiskToReport: 1},
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  StaticResolver{Names: map[string]string{}},
		Owners:    ownerTestLookups(),
	})
	if err != nil {
		t.Fatal(err)
	}
	service.options.Acquirer = &ownerPollAcquirer{Acquirer: service.options.Acquirer}
	service.Poll(context.Background())
	snapshot := service.Poll(context.Background())
	if len(snapshot.Findings) != 1 {
		t.Fatalf("findings = %+v, want python.exe", snapshot.Findings)
	}
	finding := snapshot.Findings[0]
	if finding.User != `DCLAB\alice` || finding.UserSID != aliceSID || finding.Attribution != AttributionSession {
		t.Fatalf("finding = %+v, want alice through her session", finding)
	}
}

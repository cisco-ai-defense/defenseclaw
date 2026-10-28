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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

func TestSessionOwnerEvidenceKeepsDistinctClaudeProfiles(t *testing.T) {
	t.Parallel()
	paths := []string{`C:\Users\alice\.claude\settings.json`, `C:\Users\bob\.claude\settings.json`}
	at := time.Unix(1_760_000_000, 0)
	session := agentchain.NewSession(99, "claude", at)
	for _, path := range paths {
		session.Record(agentchain.Observation{
			SignalID: "agent_config_persistence", Detail: "Claude settings updated",
			Path: path, At: at,
		})
	}
	refs, evidence := sessionOwnerEvidence(procRef{PID: 99, Name: "claude", At: at}, session.Observations())
	if len(evidence) != 2 ||
		(evidence[0] != paths[0] && evidence[1] != paths[0]) ||
		(evidence[0] != paths[1] && evidence[1] != paths[1]) {
		t.Fatalf("config path evidence = %v, want both profiles", evidence)
	}
	got := resolverFor(ownerTestLookups(), nil, at).resolve(refs, evidence)
	if got.Attribution != AttributionUnattributed || got.User != "" || got.SID != "" {
		t.Fatalf("owner = %+v, want ambiguous and unattributed", got)
	}
}

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
	at := time.Unix(1_760_000_000, 0)
	processes := []procprobe.Process{
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
	}
	resolver := resolverFor(ownerTestLookups(), processes, at)
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
		got := resolver.resolve(refsFor(processes, test.pids, at), test.paths)
		if got.User != test.user || got.SID != test.sid || got.Attribution != test.attribution {
			t.Errorf("%s: resolve = %+v, want %s %s (%s)", test.name, got, test.user, test.sid, test.attribution)
		}
		if (got.Attribution == AttributionUnattributed) != (got.Reason != "") {
			t.Errorf("%s: reason %q with attribution %s", test.name, got.Reason, got.Attribution)
		}
	}
}

// resolverFor is the owner resolver after one poll saw processes at at.
func resolverFor(lookups OwnerLookups, processes []procprobe.Process, at time.Time) *ownerResolver {
	book := newOwnerBook(lookups, time.Hour)
	book.observe(processes, at)
	return book.resolver()
}

// refsFor names pids as the processes rows describe them, seen at at.
func refsFor(processes []procprobe.Process, pids []int, at time.Time) []procRef {
	refs := make([]procRef, 0, len(pids))
	for _, pid := range pids {
		ref := procRef{PID: pid, At: at}
		for _, process := range processes {
			if process.PID == pid {
				ref.Start, ref.Name = process.StartedAt, process.Name
			}
		}
		refs = append(refs, ref)
	}
	return refs
}

// GAP-1372: Windows hands an exited process's pid to the next process. A
// finding keeps the owner of the process instance it saw, the process that
// reused the pid never lends it its own owner, and a finding whose process
// no poll saw alive is unattributed rather than given the new owner.
func TestOwnerOfARecycledPIDStaysWithTheProcessTheFindingSaw(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	book := newOwnerBook(ownerTestLookups(), time.Hour)
	uvx := procprobe.Process{PID: 7708, Name: "uvx.exe", User: `DCLAB\alice`, UserSID: aliceSID, StartedAt: base}
	dwm := procprobe.Process{PID: 7708, Name: "dwm.exe", User: `Window Manager\DWM-17`, UserSID: "S-1-5-90-0-17",
		SessionID: 17, StartedAt: base.Add(4 * time.Minute)}
	book.observe([]procprobe.Process{uvx}, base.Add(time.Minute))
	book.observe(nil, base.Add(2*time.Minute)) // uvx.exe exited
	book.observe([]procprobe.Process{dwm}, base.Add(5*time.Minute))
	resolver := book.resolver()

	for _, test := range []struct {
		name        string
		ref         procRef
		sid         string
		attribution string
	}{
		{"the instance the finding saw", procRef{PID: 7708, Start: base, Name: "uvx.exe", At: base.Add(time.Minute)},
			aliceSID, AttributionProcessOwner},
		{"no start: read from the poll that recorded it",
			procRef{PID: 7708, Name: "uvx.exe", At: base.Add(time.Minute)}, aliceSID, AttributionProcessOwner},
		{"the process that reused the pid", procRef{PID: 7708, Start: dwm.StartedAt, Name: "dwm.exe",
			At: base.Add(5 * time.Minute)}, dwm.UserSID, AttributionProcessOwner},
		{"a process no poll saw alive", procRef{PID: 7708, Start: base.Add(3 * time.Minute), Name: "python.exe",
			At: base.Add(3 * time.Minute)}, "", AttributionUnattributed},
		{"no start and another image", procRef{PID: 7708, Name: "python.exe", At: base.Add(3 * time.Minute)},
			"", AttributionUnattributed},
	} {
		got := resolver.resolve([]procRef{test.ref}, nil)
		if got.SID != test.sid || got.Attribution != test.attribution {
			t.Errorf("%s: resolve = %+v, want %q (%s)", test.name, got, test.sid, test.attribution)
		}
		if test.attribution == AttributionUnattributed && !strings.Contains(got.Reason, "other processes") {
			t.Errorf("%s: reason %q does not say the pid was reused", test.name, got.Reason)
		}
	}
}

// GAP-1401: a session's owner comes from its root process. When no poll read
// the root's owner, a child that runs as another account does not lend the
// session its owner: the finding is unattributed.
func TestASessionChildNeverNamesTheSessionOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	book := newOwnerBook(OwnerLookups{}, time.Hour)
	child := procprobe.Process{PID: 4200, Name: "sudo", User: "root", StartedAt: base.Add(time.Second)}
	book.observe([]procprobe.Process{child}, base.Add(2*time.Second))
	root := procRef{PID: 4100, Start: base, Name: "claude", At: base.Add(2 * time.Second)}
	processes, _ := sessionOwnerEvidence(root, []agentchain.Observation{{
		PID: child.PID, Start: child.StartedAt, Name: child.Name, At: base.Add(2 * time.Second),
	}})
	got := book.resolver().resolve(processes, nil)
	if got.Attribution != AttributionUnattributed || got.User != "" {
		t.Fatalf("resolve = %+v, want unattributed rather than the child's account", got)
	}
	// The same process as the finding's own process still names its owner.
	if got := book.resolver().resolve([]procRef{{PID: child.PID, Start: child.StartedAt, Name: child.Name,
		At: base.Add(2 * time.Second)}}, nil); got.User != "root" || got.Attribution != AttributionProcessOwner {
		t.Fatalf("own process resolve = %+v, want root (%s)", got, AttributionProcessOwner)
	}
}

// GAP-1401: on Windows the session root's own reference carries no SID while
// a runas child's creation event names another account. The child's SID
// does not become the session owner; the root's own SID still does.
func TestASessionChildSIDNeverNamesTheSessionOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	root := procRef{PID: 4100, Start: base, Name: "claude.exe", At: base.Add(2 * time.Second)}
	child := agentchain.Observation{
		PID: 4200, Start: base.Add(time.Second), Name: "cmd.exe", At: base.Add(2 * time.Second),
		User: `DCFC-WIN2-RS1\bob`, SID: bobSID,
	}
	processes, _ := sessionOwnerEvidence(root, []agentchain.Observation{child})
	got := resolverFor(ownerTestLookups(), nil, base).resolve(processes, nil)
	if got.SID == bobSID || got.Attribution == AttributionProcessOwner {
		t.Fatalf("resolve = %+v, want the child's account kept off the session", got)
	}
	rootEvent := agentchain.Observation{PID: root.PID, Start: root.Start, Name: root.Name, At: root.At,
		User: `DCLAB\alice`, SID: aliceSID}
	processes, _ = sessionOwnerEvidence(root, []agentchain.Observation{child, rootEvent})
	if got := resolverFor(ownerTestLookups(), nil, base).resolve(processes, nil); got.SID != aliceSID ||
		got.Attribution != AttributionProcessOwner {
		t.Fatalf("resolve = %+v, want the root's own account %s", got, aliceSID)
	}
}

// GAP-1465: a POSIX shell the polls saw as alice's execs an agent in place
// and exits before the next poll. The exec names alice, so the book keeps
// her as the owner; an exec that names another account still hands the pid on.
func TestAPOSIXExecUnderTheSameAccountKeepsTheOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	for _, test := range []struct {
		execUser, wantUser, attribution string
	}{
		{"alice", "alice", AttributionProcessOwner},
		{"bob", "", AttributionUnattributed},
		{"", "", AttributionUnattributed},
	} {
		book := newOwnerBook(OwnerLookups{}, time.Hour)
		book.observe([]procprobe.Process{{PID: 5100, Name: "bash", User: "alice", StartedAt: base}}, base.Add(time.Second))
		book.heard(pidEvents{ByPID: map[int][]pidEvent{5100: {{At: base.Add(2 * time.Second), User: test.execUser}}}})
		got := book.resolver().resolve([]procRef{{PID: 5100, Start: base, Name: "claude", At: base.Add(3 * time.Second)}}, nil)
		if got.User != test.wantUser || got.Attribution != test.attribution {
			t.Errorf("exec as %q: resolve = %+v, want %q (%s)", test.execUser, got, test.wantUser, test.attribution)
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
	owners := resolverFor(ownerTestLookups(), []procprobe.Process{
		{PID: 500, Name: "claude.exe", SessionID: 2, StartedAt: base},
		{PID: 600, Name: "claude.exe", StartedAt: base},
	}, base)
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

// GAP-1403: a LocalSystem cmd.exe a poll saw held pid 944; it exited with
// no exit record and alice's claude.exe got 944 and wrote her settings.json
// before the next poll. The lineage tracker still holds cmd.exe's start
// for the pid, so the finding must not take cmd.exe's owner: only her
// profile names claude.exe.
func TestRecycledPIDNeverLendsTheEarlierHoldersOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	host := newHostPlane(newFake(fullCoverage()), agentchain.NewTracker(),
		tactics.IndicatorsFor("windows"), time.Hour, scoring.KillChainMinStages)
	host.handle(plane.Event{Kind: plane.KindExec, PID: 944, PPID: 4, Name: "cmd.exe",
		Cmdline: `cmd /d /c Setup.exe /ensure`, User: "DCFC-WIN2-RS8$", At: base})
	cmd := procprobe.Process{PID: 944, PPID: 4, Name: "cmd.exe", User: `NT AUTHORITY\SYSTEM`, UserSID: "S-1-5-18",
		StartedAt: base}
	host.tracker.ObserveProcessTable([]agentchain.ProcessRow{{PID: 944, PPID: 4, Name: "cmd.exe", Start: base}})
	book := newOwnerBook(ownerTestLookups(), time.Hour)
	book.observe([]procprobe.Process{cmd}, base.Add(time.Minute))

	host.handle(plane.Event{Kind: plane.KindExec, PID: 944, PPID: 5000, Name: "claude.exe", Cmdline: "claude",
		User: "alice", At: base.Add(18 * time.Minute)})
	host.handle(plane.Event{Kind: plane.KindFileWrite, PID: 944, Name: "claude.exe",
		Path: `C:\Users\alice\.claude\settings.json`, User: "alice", At: base.Add(19 * time.Minute)})

	findings := (&Service{hostPlane: host}).hostPlaneFindings(base.Add(20*time.Minute), 1,
		correlate.New(correlate.Snapshot{}), book.resolver())
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want the claude.exe session", findings)
	}
	got := findings[0]
	if got.User != `DCLAB\alice` || got.UserSID != aliceSID || got.Attribution != AttributionEnrolledProfile {
		t.Fatalf("finding = %s %s (%s), want alice through her profile, never cmd.exe's owner",
			got.User, got.UserSID, got.Attribution)
	}
}

// GAP-1464: alice's claude.exe exits and bob's claude.exe gets its pid one
// second after alice's started, inside instanceStartTolerance. Whether or
// not the host plane reported the exit, bob's process is a new instance:
// bob's findings name bob and alice's keep naming alice.
func TestPIDReusedWithinTheStartToleranceTakesTheNewOwner(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	alice := procprobe.Process{PID: 4120, Name: "claude.exe", User: `DCLAB\alice`, UserSID: aliceSID, StartedAt: base}
	bob := procprobe.Process{PID: 4120, Name: "claude.exe", User: `DCFC-WIN2-RS1\bob`, UserSID: bobSID,
		StartedAt: base.Add(time.Second)}
	for _, exitHeard := range []bool{true, false} {
		book := newOwnerBook(ownerTestLookups(), time.Hour)
		book.observe([]procprobe.Process{alice}, base.Add(500*time.Millisecond))
		if exitHeard {
			book.heard(pidEvents{ByPID: map[int][]pidEvent{4120: {{At: base.Add(700 * time.Millisecond), Exit: true}}}})
		}
		book.observe([]procprobe.Process{bob}, base.Add(1500*time.Millisecond))
		resolver := book.resolver()
		for _, want := range []struct {
			process procprobe.Process
			at      time.Time
			sid     string
		}{{alice, base.Add(500 * time.Millisecond), aliceSID}, {bob, base.Add(1500 * time.Millisecond), bobSID}} {
			ref := procRef{PID: 4120, Start: want.process.StartedAt, Name: "claude.exe", At: want.at}
			if got := resolver.resolve([]procRef{ref}, nil); got.SID != want.sid {
				t.Errorf("exit heard %v: finding of %s resolved to %+v, want %s", exitHeard, want.process.User, got, want.sid)
			}
		}
	}
}

// GAP-1464: a Windows process-creation event carries no creation time, so a
// finding's process has no start until a poll sees it. alice's claude.exe
// writes her settings and exits, bob's claude.exe gets its pid 150 ms after
// hers started, and the next poll records bob's. Her finding is not tied to
// bob's instance by pid, image and a nearby start: the exit between her
// process's creation and that poll proves the polled process is another,
// whether the book hears of the exit before the poll or after it.
func TestRecycledPIDWithoutAStartIsNotTheNextHoldersProcess(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	const pid = 1204
	for _, lateLifecycle := range []bool{false, true} {
		host := newHostPlane(newFake(fullCoverage()), agentchain.NewTracker(),
			tactics.IndicatorsFor("windows"), time.Hour, scoring.KillChainMinStages)
		book := newOwnerBook(ownerTestLookups(), time.Hour)
		write := func(user string, at time.Time) {
			host.handle(plane.Event{Kind: plane.KindFileWrite, PID: pid, Name: "claude.exe",
				Path: `C:\Users\` + user + `\.claude\settings.json`, User: user, At: at})
		}
		poll := func() {
			book.heard(host.takeLifecycle())
			book.observe([]procprobe.Process{{PID: pid, Name: "claude.exe", User: `DCFC-WIN2-RS1\bob`, UserSID: bobSID,
				StartedAt: base.Add(150 * time.Millisecond)}}, base.Add(time.Minute))
		}
		host.handle(plane.Event{Kind: plane.KindExec, PID: pid, PPID: 900, Name: "claude.exe", Cmdline: "claude", At: base})
		write("alice", base.Add(20*time.Millisecond))
		if lateLifecycle {
			poll()
		}
		host.handle(plane.Event{Kind: plane.KindExit, PID: pid, Name: "claude.exe", At: base.Add(100 * time.Millisecond)})
		host.handle(plane.Event{Kind: plane.KindExec, PID: pid, PPID: 900, Name: "claude.exe", Cmdline: "claude",
			At: base.Add(150 * time.Millisecond)})
		write("bob", base.Add(170*time.Millisecond))
		if !lateLifecycle {
			poll()
		}
		findings := (&Service{hostPlane: host}).hostPlaneFindings(base.Add(61*time.Second), 1,
			correlate.New(correlate.Snapshot{}), book.resolver())
		if len(findings) != 2 {
			t.Fatalf("late lifecycle %v: findings = %+v, want one per claude.exe", lateLifecycle, findings)
		}
		for _, finding := range findings {
			want, attribution := bobSID, AttributionProcessOwner
			if finding.FirstSeen.Before(base.Add(100 * time.Millisecond)) {
				want, attribution = aliceSID, AttributionEnrolledProfile
			}
			if finding.UserSID != want || finding.Attribution != attribution {
				t.Errorf("late lifecycle %v: finding first seen %s = %s %s (%s), want %s (%s)", lateLifecycle,
					finding.FirstSeen.Sub(base), finding.User, finding.UserSID, finding.Attribution, want, attribution)
			}
		}
	}
}

// GAP-1464: each Windows event names the account of the process that
// produced it. alice's, bob's and again alice's claude.exe take one pid in
// turn with neither exit logged, and write a project's Claude settings, a
// path no profile holds. Each creation that names another account starts
// its own instance, and each finding names the account its own events named,
// not one the book holds for the pid.
func TestRecycledPIDFindingsNameTheAccountTheirEventsNamed(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	const pid = 1204
	host := newHostPlane(newFake(fullCoverage()), agentchain.NewTracker(),
		tactics.IndicatorsFor("windows"), time.Hour, scoring.KillChainMinStages)
	holders := []struct{ user, sid string }{
		{`DCLAB\alice`, aliceSID}, {`DCFC-WIN2-RS1\bob`, bobSID}, {`DCLAB\alice`, aliceSID},
	}
	for index, holder := range holders {
		at := base.Add(time.Duration(index) * 150 * time.Millisecond)
		host.handle(plane.Event{Kind: plane.KindExec, PID: pid, PPID: 900, Name: "claude.exe", Cmdline: "claude",
			User: holder.user, UserSID: holder.sid, At: at})
		host.handle(plane.Event{Kind: plane.KindFileWrite, PID: pid, Name: "claude.exe",
			Path: `C:\src\app\.claude\settings.json`, User: holder.user, UserSID: holder.sid, At: at.Add(20 * time.Millisecond)})
	}
	book := newOwnerBook(ownerTestLookups(), time.Hour)
	book.heard(host.takeLifecycle())
	book.observe([]procprobe.Process{{PID: pid, Name: "claude.exe", User: `DCLAB\alice`, UserSID: aliceSID,
		StartedAt: base.Add(300 * time.Millisecond)}}, base.Add(time.Minute))
	findings := (&Service{hostPlane: host}).hostPlaneFindings(base.Add(61*time.Second), 1,
		correlate.New(correlate.Snapshot{}), book.resolver())
	if len(findings) != len(holders) {
		t.Fatalf("findings = %+v, want one per claude.exe", findings)
	}
	for _, finding := range findings {
		holder := holders[int(finding.FirstSeen.Sub(base)/(150*time.Millisecond))]
		if finding.UserSID != holder.sid || finding.Attribution != AttributionProcessOwner {
			t.Errorf("finding first seen %s = %s %s (%s), want %s", finding.FirstSeen.Sub(base),
				finding.User, finding.UserSID, finding.Attribution, holder.sid)
		}
	}
}

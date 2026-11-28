// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestPrivateKeyGlobOfACallWithNoFolderIsBoundedOnTheInspectRoute is
// rel-1-0-10:GAP-1066 (cells of the s7-td327r3rev3 probe TestRV3Probe, route
// inspect-oc, CAP|nocwd). An OpenClaw call with no folder reads a
// current-folder head as the empty folder, so the private-key reader expanded
// $PWD/*/* as /*/* on the gateway host: up to 4,096 directory entries, each
// directory read and sorted whole first, then a link walk and eight stats for
// each match. The route passed its 200 ms scan budget and answered 504 where
// rel allowed. The expansion now reads at most its cap of entries, with one
// stat a match, and a pattern it read only up to that cap with no key among
// the matches before it is TRUNCATED (cap=paths): the unknown tier of the
// pack, an alert in default, permissive and managed, a block in strict and
// managed-strict. A key the walk reaches before the cap, and a key pattern
// spelled through the same head, still block in every pack.
//
// The wide folder is built here (8 folders of 600 files, past the cap) and
// spelled from the empty current folder ($PWD/<path>/*/*), which is the
// reading of the gap's cells on a host whose / holds that many names; the
// gap's own cells read the host's / and answer either rel's allow or the
// unknown tier, never 504. Outside a race build each row of every pack
// answers three times and the median of the CPU time of those answers is held
// to half of the production scan budget for the default pack, and the fastest of
// those answers to 3/2 of the default pack's median of the same row (plus a 20
// ms slack) for each other pack (GAP-2004: a slow strict, permissive or managed row is seen, measured
// against its own baseline, not against a bar the host's folders can cross);
// under -race only the answers are checked. The bar counts work (the
// process's CPU time) and the deadline of the route is raised far above any
// load, because a wall-clock
// bar and the 200 ms deadline both fail on a loaded shared box with the
// expansion bounded (GAP-0708: 128 ms against 100 ms at load 11-22): a
// regression to the unbounded expansion reads thousands of entries, which
// is CPU time whatever else runs. The gap's own cells read the host's / and
// its folders, so their CPU time is mostly the host's (rel-1-0-10:GAP-1784:
// 15 ms on a bench box, 50-115 ms on a build box whose folders are wide, same
// commit): the default pack's median of those rows is held to the bar plus
// what reading the same folders up to the cap costs this host at the same
// moment (hostRootReadCPU), so the bar still counts the route's own work and
// a host with wide folders does not fail it.
func TestPrivateKeyGlobOfACallWithNoFolderIsBoundedOnTheInspectRoute(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	wideFolder := func(name string) string {
		dir := filepath.Join(root, name)
		for folder := range 8 {
			sub := filepath.Join(dir, fmt.Sprintf("d%d", folder))
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			for file := range 600 {
				if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%03d", file)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return dir
	}
	wide := wideFolder("wide")
	// The same folder with a link to the key in its first folder, which the
	// walk reads before the cap.
	linked := wideFolder("linked")
	if err := os.MkdirAll(filepath.Join(linked, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(linked, "a", "k")); err != nil {
		t.Fatal(err)
	}
	// $PWD is the empty folder: $PWD/<path> spells the absolute path.
	spell := func(head, dir, pattern string) string { return head + strings.TrimPrefix(dir, "/") + "/" + pattern }
	param, subst := "$"+"PWD/", "$("+"pwd)/"
	const unknown, block, atLeastUnknown, relOrUnknown = "unknown", "block", "at least unknown", "rel or unknown"
	rows := []struct{ command, want string }{
		{"cat " + spell(param, wide, "*/*"), unknown},
		{"cp " + spell(param, wide, "*/*") + " /tmp/staged", unknown},
		{"head -n1 " + spell(subst, wide, "[a-z]*/*"), unknown},
		{"grep -l k " + spell(subst, wide, "*/*"), unknown},
		{"cat " + spell(param, linked, "*/*"), block},
		{"head -n1 " + spell(subst, home, ".ssh/id_*"), block},
		// A key named whole through the head is no word the reader can read
		// (rel gives it the unknown tier of the GAP-1023 twin, not a block).
		{"cat " + spell(param, home, ".ssh/id_ed25519"), atLeastUnknown},
		// The gap's own cells, on the host's /: rel allows them.
		{"cat " + param + "*/*", relOrUnknown},
		{"cp " + param + "*/* /tmp/staged", relOrUnknown},
		{"head -n1 " + subst + "[a-z]*/*", relOrUnknown},
		{"grep -l k " + subst + "*/*", relOrUnknown},
	}
	capReason := bounded.ReasonCode + " cap=" + bounded.Paths.String()
	const bar = inspectScanTimeout / 2
	judged := 0
	servers := make([]*APIServer, len(gap0437Packs))
	generations := make([]*Generation, len(gap0437Packs))
	for i, p := range gap0437Packs {
		servers[i] = gap0437Server(t, p, "openclaw", "action")
		generations[i] = liveGeneration.Load()
		// The answers do not depend on the clock: a scan deadline the box's
		// load could reach would answer 504 for a bounded expansion too.
		servers[i].inspectToolScanTimeout = 30 * time.Second
	}
	runs := 1
	if !hookAnswerRaceBuild {
		runs = 3
	}
	answer := func(a *APIServer, command string) *httptest.ResponseRecorder {
		body := mustJSON(t, map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": ""}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.handleInspectTool(rec, req)
		return rec
	}
	// One untimed answer reads the first wide folder cold, so that the first
	// row's baseline (the default pack's) does not pay for it.
	if runs > 1 {
		answer(servers[0], rows[0].command)
	}
	// Row by row, every pack answers in turn, so the default pack's median is
	// the baseline of the same row measured at the same moment of the same box.
	for _, row := range rows {
		var baseline time.Duration
		// The host's share of a row that reads the host's / (the gap's own
		// cells), read just before the default pack answers it.
		var hostRead time.Duration
		if row.want == relOrUnknown && runs > 1 {
			hostRead = hostRootReadCPU(runs)
		}
		for i, p := range gap0437Packs {
			a := servers[i]
			// The pack's own live generation is the one in force while it answers.
			liveGeneration.Store(generations[i])
			tier := "alert"
			if p.pack == "strict" {
				tier = "block"
			}
			var times []time.Duration
			for range runs {
				start := processCPUTime()
				rec := answer(a, row.command)
				times = append(times, processCPUTime()-start)
				judged++
				if rec.Code == http.StatusGatewayTimeout && runs > 1 {
					// A run of the timed pack that passed the budget is a sample over
					// the bar: the median below judges it, so one slow run among three
					// (the first, cold read of a wide folder) does not fail the row.
					continue
				}
				if rec.Code != http.StatusOK {
					t.Errorf("%s %q: status %d, want 200 (body %s)", p.name, row.command, rec.Code, rec.Body.String())
					continue
				}
				var out map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
					t.Fatalf("%s %q: answer %q: %v", p.name, row.command, rec.Body.String(), err)
				}
				action, _ := out["action"].(string)
				if action == "" {
					action = "allow"
				}
				truncated := strings.Contains(rec.Body.String(), capReason)
				switch row.want {
				case unknown:
					if action != tier || !truncated {
						t.Errorf("%s %q: %s (truncated %v), want the unknown tier %s with %q", p.name, row.command, action, truncated, tier, capReason)
					}
				case block:
					if action != "block" {
						t.Errorf("%s %q: %s, want block", p.name, row.command, action)
					}
				case atLeastUnknown:
					if action != tier && action != "block" {
						t.Errorf("%s %q: %s, want at least the unknown tier %s", p.name, row.command, action, tier)
					}
				case relOrUnknown:
					if action != "allow" && (action != tier || !truncated) {
						t.Errorf("%s %q: %s (truncated %v), want rel's allow or the unknown tier %s", p.name, row.command, action, truncated, tier)
					}
				}
			}
			if runs > 1 {
				slices.Sort(times)
				median := times[len(times)/2]
				t.Logf("%s %.60q: median CPU %s of %v (host read %s)", p.name, row.command, median.Round(time.Millisecond), times, hostRead.Round(time.Millisecond))
				if p.name == "default" {
					baseline = median
					if median > bar+hostRead {
						t.Errorf("%s %q: median answer CPU time %s, want under %s (half the %s scan budget) plus the host read %s; runs %v",
							p.name, row.command, median.Round(time.Millisecond), bar, inspectScanTimeout, hostRead.Round(time.Millisecond), times)
					}
				} else if limit := baseline*packCostRatioNum/packCostRatioDen + packCostSlack; times[0] > limit {
					// GAP-2004: the other packs are held to their own baseline, the
					// default pack's median of this row, not to the absolute bar: the
					// work of a row that reads the host's folders is the host's. The
					// fastest of the answers is judged: a pack that costs more moves
					// every answer, the fastest too, while a box that answers a row in
					// about 50 ms or about 100 ms by turns moves one or two of them.
					t.Errorf("%s %q: fastest of %d answers took CPU time %s, want under %s (%d/%d of the default pack's median %s plus %s); runs %v",
						p.name, row.command, len(times), times[0].Round(time.Millisecond), limit.Round(time.Millisecond),
						packCostRatioNum, packCostRatioDen, baseline.Round(time.Millisecond), packCostSlack, times)
				}
			}
		}
	}
	if judged == 0 {
		t.Fatal("no cell judged")
	}
}

// A pack other than default answers a row in at most 3/2 of the default
// pack's median CPU time of that row plus this slack (rel-1-0-10:GAP-2004).
// The slack keeps a row of a few ms from failing on a ratio of noise; a pack
// that costs 120 ms more than default is far over it.
const (
	packCostRatioNum = 3
	packCostRatioDen = 2
	packCostSlack    = 20 * time.Millisecond
)

// hostRootReadCap is hookpaths' actionGlobEntryCap: the directory entries
// one pattern expansion reads at most.
const hostRootReadCap = 4096

// hostRootReadCPU is the median CPU time, of n reads, of reading this host's
// / the way any capped expansion of a two-level pattern under it has to: /
// and then each folder under it in name order, each read to its end, with one
// stat for every name, until hostRootReadCap names are read
// (rel-1-0-10:GAP-1784). It is what the host's folders cost, not the route's
// work: wide folders (a build box's) make it tens of milliseconds where a
// bench box reads its / in a few. A route that read past its cap, or stat-ed
// each name more than once, costs more than this on every host.
func hostRootReadCPU(n int) time.Duration {
	times := make([]time.Duration, 0, n)
	for range n {
		start := processCPUTime()
		readHostRootCapped(hostRootReadCap)
		times = append(times, processCPUTime()-start)
	}
	slices.Sort(times)
	return times[len(times)/2]
}

func readHostRootCapped(limit int) {
	root := string(filepath.Separator)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	read := len(entries)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		names, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, name := range names {
			if read >= limit {
				return
			}
			read++
			_, _ = os.Stat(filepath.Join(dir, name.Name()))
		}
	}
}

// processCPUTime is the CPU time this process has used (user plus system),
// the work of the answers measured, not the time a loaded box made them wait.
func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

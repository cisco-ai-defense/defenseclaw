// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestShellHookLoweredBodyCapOnlyTightens: DEFENSECLAW_HOOK_MAX_BODY in the
// agent's environment can only lower the hook's body cap, and a lowered cap
// can only tighten (rel-1-0-6:GAP-0337). With the cap at 16 the per-user
// open tier reviewed a 16-byte prefix, and Cursor read no event from it, so a
// gateway block answered {} with exit 0 and the call ran.
//
// For every shell hook, in the per-user open and closed tiers and the
// managed closed render, with a normal and a 70 KiB call:
//   - a call the hook blocks with the default cap stays blocked at every
//     lowered cap;
//   - a call under the lowered cap is answered as with the default cap, so
//     a lowered cap adds no block to normal work;
//   - a call over a cap lowered under the per-user transport's 900 KiB is
//     never sent as a bounded prefix review: it is refused.
//
// And Cursor denies a gateway block, or a closed failure, for a payload
// whose event it cannot read, and still allows an allowed one.
func TestShellHookLoweredBodyCapOnlyTightens(t *testing.T) {
	for _, tool := range []string{"jq", "curl", "awk"} {
		if _, err := lookPathForHostileTest(tool); err != nil {
			t.Skipf("%s is required", tool)
		}
	}
	scratch := t.TempDir()
	installNativeGatewayForHookTest(t, filepath.Join(scratch, "probe-gw"))
	installNativeHookPostForHookTest(t, filepath.Join(scratch, "probe-post"))
	base, err := os.MkdirTemp("/tmp", "dcl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	modes := hookGoldenModes()
	answers := map[string]hookGoldenAnswer{}
	for _, a := range hookGoldenAnswers() {
		answers[a.name] = a
	}
	const command = "cat ./hello.txt"
	padded := command + " #" + strings.Repeat("x", 70*1024)
	caps := []string{"16", "4096", "65535", "65536", "921599"}
	var cases []hookGoldenCase
	for _, h := range hookGoldenHooks() {
		event := h.events[0]
		stdins := map[string][]byte{
			"normal": h.payload(event, command, "<WORK>"),
			"70k":    h.payload(event, padded, "<WORK>"),
		}
		for _, m := range []hookGoldenMode{modes[0], modes[1], modes[5]} {
			for _, a := range []string{"allow", "block-bare", "block-output"} {
				for _, in := range []string{"normal", "70k"} {
					c := hookGoldenCase{hook: h, mode: m, answer: answers[a], event: event, stdin: stdins[in]}
					c.id = fmt.Sprintf("%s/%s/%s/%s", h.name, m.name, a, in)
					cases = append(cases, c)
					for _, n := range caps {
						lc := c
						lc.id += "/cap-" + n
						lc.env = []string{"DEFENSECLAW_HOOK_MAX_BODY=" + n}
						cases = append(cases, lc)
					}
				}
			}
		}
	}
	var cursor hookGoldenHook
	for _, h := range hookGoldenHooks() {
		if h.name == "cursor" {
			cursor = h
		}
	}
	unread := map[string][]byte{
		"no-event":      []byte(`{"conversation_id":"golden-conv","command":"cat ./hello.txt","cwd":"<WORK>"}`),
		"unknown-event": []byte(`{"hook_event_name":"beforeSomethingNew","conversation_id":"golden-conv","command":"cat ./hello.txt","cwd":"<WORK>"}`),
	}
	var cursorCases []hookGoldenCase
	for _, m := range []hookGoldenMode{modes[0], modes[1], modes[5]} {
		for _, a := range []string{"allow", "block-bare", "truncated-json"} {
			for _, in := range []string{"no-event", "unknown-event"} {
				c := hookGoldenCase{hook: cursor, mode: m, answer: answers[a], event: cursor.events[0], stdin: unread[in]}
				c.id = fmt.Sprintf("cursor-unread/%s/%s/%s", m.name, a, in)
				cursorCases = append(cursorCases, c)
			}
		}
	}
	all := append(append([]hookGoldenCase(nil), cases...), cursorCases...)
	var (
		mu       sync.Mutex
		verdicts = map[string]string{}
		reviewed = map[string]bool{}
		detail   = map[string]string{}
		next     atomic.Int64
		wg       sync.WaitGroup
	)
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(all) {
					return
				}
				obs, err := runHookGoldenCase(base, i, all[i])
				mu.Lock()
				if err != nil {
					verdicts[all[i].id] = "setup: " + err.Error()
				} else {
					verdicts[all[i].id] = hookHostileVerdict(obs)
					for _, r := range obs.Requests {
						if strings.Contains(r.Body, `"bounded_prefix_review":true`) {
							reviewed[all[i].id] = true
						}
					}
					detail[all[i].id] = fmt.Sprintf("exit %d stdout %q stderr %q", obs.Exit, obs.Stdout, review2Tail(obs.Stderr))
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	var failures []string
	sizes := map[string]int{}
	for _, c := range cases {
		parts := strings.Split(c.id, "/")
		if len(parts) == 4 {
			sizes[c.id] = len(c.stdin)
			continue
		}
		plain := strings.Join(parts[:4], "/")
		capBytes := 0
		_, _ = fmt.Sscanf(strings.TrimPrefix(parts[4], "cap-"), "%d", &capBytes)
		got, want := verdicts[c.id], verdicts[plain]
		// A hook registered for Stop does not block an oversized call there,
		// by the Stop contract (a block would keep the agent running).
		stopBound := c.hook.name == "codex-mismatch" && sizes[plain] > capBytes
		switch {
		case strings.HasPrefix(got, "setup") || strings.HasPrefix(want, "setup"):
			failures = append(failures, fmt.Sprintf("%s: %s / %s", c.id, got, want))
		case want == "deny" && got != "deny" && !stopBound:
			failures = append(failures, fmt.Sprintf("%s: %s, the default cap denies; %s", c.id, got, detail[c.id]))
		case sizes[plain] <= capBytes && got != want:
			failures = append(failures, fmt.Sprintf("%s: %s under the cap, default cap %s; %s", c.id, got, want, detail[c.id]))
		}
		if sizes[plain] > capBytes && reviewed[c.id] {
			failures = append(failures, fmt.Sprintf("%s: a call over a lowered cap was sent as a bounded prefix review; %s", c.id, detail[c.id]))
		}
	}
	for _, c := range cursorCases {
		// An allow stays an allow; a block and an unusable answer (closed in
		// every per-user tier, as for a readable event) deny.
		want := "deny"
		if strings.Contains(c.id, "/allow/") {
			want = "allow"
		}
		if got := verdicts[c.id]; got != want {
			failures = append(failures, fmt.Sprintf("%s: %s, want %s; %s", c.id, got, want, detail[c.id]))
		}
	}
	sort.Strings(failures)
	for i, f := range failures {
		if i == 40 {
			t.Errorf("... and %d more", len(failures)-40)
			break
		}
		t.Error(f)
	}
	t.Logf("%d lowered-cap and %d Cursor unread-event cases", len(cases), len(cursorCases))
}

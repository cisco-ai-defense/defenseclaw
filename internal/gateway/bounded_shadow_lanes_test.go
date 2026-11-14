// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// Shadow lanes of the bound rule.
//
// A lane that ships in shadow does not decide: its floor records a finding and the
// live verdict is the one without it. The lane table of TestBoundRuleEveryLaneCap
// asks every lane for the unknown tier past a cap and for a judge row that shows the
// floor standing without the judge; both would be false of a lane that does not
// decide, and registering such a lane there only to satisfy the table says nothing
// about the bound. A shadow lane registers here instead, with its own contract
// (boundedCheckShadowLanes, TestBoundRuleShadowLaneNeverDecides, and as a sub-test
// of TestBoundRuleEveryLaneCap), in every tier the hook route judges in:
//
//   - the live verdict past a cap (limit+1, 2*limit), in every shape the lane has,
//     is exactly the verdict with the lane off: action and findings;
//   - the lane's record of that call names the cap it hit (TRUNCATED), and the
//     record of the input at the cap names none;
//   - the lane still records what it read before the cap (the seen element).
//
// The day a lane is promoted it moves to boundedLanes with its own route and judge
// row, and the row here is deleted.

// boundedShadowLane is one cap of one shadow lane.
type boundedShadowLane struct {
	lane  string
	cap   bounded.Cap
	limit int
	gen   func(size int, shape boundedShape) (call boundedLaneCall, ok bool)
	seen  func() boundedLaneCall
	// route runs one call through the lane's route with the lane in the given
	// mode ("off" or "shadow") and returns the live action and findings and the
	// records the lane wrote for the call.
	route func(t *testing.T, api *APIServer, env boundedEnv, call boundedLaneCall, mode string) (action string, findings []string, records []string)
	// recordNamesCap reports whether a record of the lane names the cap hit.
	recordNamesCap func(record string, cap bounded.Cap) bool
}

var boundedShadowLanes []boundedShadowLane

func registerBoundedShadowLane(lanes ...boundedShadowLane) {
	boundedShadowLanes = append(boundedShadowLanes, lanes...)
}

// boundedShadowLaneTableErrors are the misuses of the shadow lane table.
func boundedShadowLaneTableErrors(lanes []boundedShadowLane) []string {
	var errs []string
	seen := map[string]bool{}
	for _, l := range lanes {
		name := l.lane + "/" + l.cap.String()
		if seen[name] {
			errs = append(errs, fmt.Sprintf("%s: registered twice", name))
		}
		seen[name] = true
		if l.gen == nil || l.seen == nil || l.route == nil || l.recordNamesCap == nil || l.limit <= 0 {
			errs = append(errs, fmt.Sprintf("%s: a shadow lane registers gen, seen, route, recordNamesCap and a positive limit", name))
		}
		for _, b := range boundedLanes {
			if b.lane == l.lane {
				errs = append(errs, fmt.Sprintf("%s: the lane is also in the deciding table (boundedLanes): a lane is one or the other", name))
			}
		}
	}
	return errs
}

// boundedCheckShadowLanes holds every registered shadow lane to its contract in
// every tier.
func boundedCheckShadowLanes(t *testing.T) {
	t.Helper()
	if errs := boundedShadowLaneTableErrors(boundedShadowLanes); len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
		return
	}
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, lane := range boundedShadowLanes {
			name := tier.name + "/" + lane.lane + "/" + lane.cap.String()
			// what the lane reads before a cap is still recorded, and without a cap
			seenAction, seenFindings, seenRecords := lane.route(t, api, env, lane.seen(), "shadow")
			offAction, offFindings, _ := lane.route(t, api, env, lane.seen(), "off")
			if seenAction != offAction || !slices.Equal(seenFindings, offFindings) {
				t.Errorf("%s: shadow changed the live verdict of the seen element: off %s %v, shadow %s %v", name, offAction, offFindings, seenAction, seenFindings)
			}
			if len(seenRecords) == 0 {
				t.Errorf("%s: the seen element was not recorded", name)
			}
			for _, r := range seenRecords {
				if lane.recordNamesCap(r, lane.cap) {
					t.Errorf("%s: the seen element alone is recorded as truncated: %s", name, r)
				}
			}
			for _, s := range boundedShapes {
				at, ok := lane.gen(lane.limit, s.shape)
				if !ok {
					if s.required {
						t.Errorf("%s: no %s shape (required)", name, s.name)
					}
					continue
				}
				if s.shape == (boundedShape{}) {
					// only the plain shape is exactly at the cap: the seen shape adds one element of its own
					_, _, atRecords := lane.route(t, api, env, at, "shadow")
					for _, r := range atRecords {
						if lane.recordNamesCap(r, lane.cap) {
							t.Errorf("%s %s: the input at the cap (%d) is recorded as truncated: %s", name, s.name, lane.limit, r)
						}
					}
				}
				for _, size := range []int{lane.limit + 1, 2 * lane.limit} {
					call, _ := lane.gen(size, s.shape)
					offAction, offFindings, offRecords := lane.route(t, api, env, call, "off")
					action, findings, records := lane.route(t, api, env, call, "shadow")
					if action != offAction || !slices.Equal(findings, offFindings) {
						t.Errorf("%s %s size=%d: the live verdict is not the one with the lane off: off %s %v, shadow %s %v", name, s.name, size, offAction, offFindings, action, findings)
					}
					if len(offRecords) != 0 {
						t.Errorf("%s %s size=%d: the lane wrote %d records while off", name, s.name, size, len(offRecords))
					}
					named := slices.ContainsFunc(records, func(r string) bool { return lane.recordNamesCap(r, lane.cap) })
					if !named {
						t.Errorf("%s %s size=%d: no record names the cap (TRUNCATED): %v", name, s.name, size, records)
					}
				}
			}
		}
	}
}

func TestBoundRuleShadowLaneNeverDecides(t *testing.T) {
	if len(boundedShadowLanes) == 0 {
		t.Skip("no shadow lane registered")
	}
	boundedCheckShadowLanes(t)
}

// The table check itself rejects each misuse it names.
func TestBoundRuleShadowLaneTableRejectsMisuse(t *testing.T) {
	ok := boundedShadowLane{lane: "x", cap: bounded.Items, limit: 1,
		gen:  func(int, boundedShape) (boundedLaneCall, bool) { return boundedLaneCall{}, true },
		seen: func() boundedLaneCall { return boundedLaneCall{} },
		route: func(*testing.T, *APIServer, boundedEnv, boundedLaneCall, string) (string, []string, []string) {
			return "", nil, nil
		},
		recordNamesCap: func(string, bounded.Cap) bool { return false }}
	if errs := boundedShadowLaneTableErrors([]boundedShadowLane{ok}); len(errs) != 0 {
		t.Fatalf("a complete row is rejected: %v", errs)
	}
	noRoute := ok
	noRoute.route = nil
	twice := []boundedShadowLane{ok, ok}
	for name, lanes := range map[string][]boundedShadowLane{"no route": {noRoute}, "twice": twice} {
		if errs := boundedShadowLaneTableErrors(lanes); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

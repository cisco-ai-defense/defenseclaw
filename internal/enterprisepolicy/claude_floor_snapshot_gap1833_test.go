// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// GAP-1833: the Windows version floor pass plans from files it reads before
// the Claude Code managed policy lock and applies the plan under the lock
// only while those files are unchanged. These rows change a source in that
// window. Each must end exactly as when the change lands before the pass
// starts (the pass that read everything under the lock): never a write or a
// kept floor from what the change replaced.
func TestGAP1833FloorChangedBetweenTheReadAndTheLockIsReadAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Publishing on a Windows host writes the floor owned by
		// Administrators, which a standard token may not assign; the rows run
		// on the Windows tree in TestGAP1833WindowsFloorChangedBetweenTheReadAndTheLockIsReadAgain.
		t.Skip("on Windows the rows run on the Windows tree (TestGAP1833WindowsFloorChangedBetweenTheReadAndTheLockIsReadAgain)")
	}
	runGAP1833FloorRaces(t, func(t *testing.T) gap1833FloorEnv {
		withHigherSources(t)
		return gap1833FloorEnv{opts: testOptions(t), write: writeFile}
	})
}

// gap1833FloorEnv is one fresh floor tree; write writes a file the way an
// administrator deploys it.
type gap1833FloorEnv struct {
	opts  Options
	write func(t *testing.T, path, content string)
}

// gap1833FloorOutcome is what a pass leaves.
type gap1833FloorOutcome struct {
	floor     string
	recorded  bool
	postimage string
	failed    bool
	changed   bool
}

func runGAP1833FloorRaces(t *testing.T, fresh func(t *testing.T) gap1833FloorEnv) {
	const adminKey = "{\"requiredMinimumVersion\": \"2.1.300\"}\n"
	type race struct {
		name string
		// published: the pass runs on a floor DefenseClaw already wrote.
		published bool
		// every: the change lands at every lock the pass takes (a busy
		// writer), not only the first.
		every  bool
		change func(t *testing.T, env gap1833FloorEnv)
		// stale is what a pass that applied the plan read before the change
		// would leave; the row fails if the pass leaves it.
		stale func(gap1833FloorOutcome) bool
	}
	base := func(env gap1833FloorEnv) string {
		return joinFor(env.opts, claudeDir(t, env.opts), "managed-settings.json")
	}
	races := []race{{
		name:      "administrator sets the key in managed-settings.json over DefenseClaw's floor",
		published: true,
		change:    func(t *testing.T, env gap1833FloorEnv) { env.write(t, base(env), adminKey) },
		stale:     func(o gap1833FloorOutcome) bool { return o.floor != "" },
	}, {
		name:      "administrator adds a drop-in that sorts after the floor",
		published: true,
		change: func(t *testing.T, env gap1833FloorEnv) {
			env.write(t, joinFor(env.opts, dirFor(env.opts, claudeFloorFile(t, env.opts)), "50-company.json"), adminKey)
		},
		stale: func(o gap1833FloorOutcome) bool { return o.floor != "" },
	}, {
		name:   "administrator sets the key before DefenseClaw's first write",
		change: func(t *testing.T, env gap1833FloorEnv) { env.write(t, base(env), adminKey) },
		stale:  func(o gap1833FloorOutcome) bool { return o.floor != "" || o.recorded },
	}, {
		name: "administrator deploys a file under the drop-in name before DefenseClaw's first write",
		change: func(t *testing.T, env gap1833FloorEnv) {
			env.write(t, claudeFloorFile(t, env.opts), "{\"requiredMinimumVersion\": \"9.9.9\"}\n")
		},
		stale: func(o gap1833FloorOutcome) bool {
			return o.floor != "{\"requiredMinimumVersion\": \"9.9.9\"}\n" || o.recorded
		},
	}, {
		name:      "administrator edits DefenseClaw's floor drop-in",
		published: true,
		change: func(t *testing.T, env gap1833FloorEnv) {
			env.write(t, claudeFloorFile(t, env.opts), "{\"requiredMinimumVersion\": \"2.1.999\"}\n")
		},
		stale: func(o gap1833FloorOutcome) bool { return o.floor != "{\"requiredMinimumVersion\": \"2.1.999\"}\n" },
	}, {
		name:      "a concurrent removal takes the floor and its record",
		published: true,
		change: func(t *testing.T, env gap1833FloorEnv) {
			if err := os.Remove(claudeFloorFile(t, env.opts)); err != nil {
				t.Fatal(err)
			}
			if err := deleteRecord(env.opts, claudeVersionFloorRecord); err != nil {
				t.Fatal(err)
			}
		},
		stale: func(o gap1833FloorOutcome) bool { return o.floor != wantClaudeFloorBytes || !o.recorded },
	}, {
		name:      "a busy administrator rewrites managed-settings.json at every lock",
		published: true,
		every:     true,
		change: func() func(t *testing.T, env gap1833FloorEnv) {
			n := 0
			return func(t *testing.T, env gap1833FloorEnv) {
				n++
				env.write(t, base(env), fmt.Sprintf("{\"requiredMinimumVersion\": \"2.1.%d\"}\n", 300+n%2))
			}
		}(),
		stale: func(o gap1833FloorOutcome) bool { return o.floor != "" },
	}, {
		name:      "the floor record is rewritten",
		published: true,
		change: func(t *testing.T, env gap1833FloorEnv) {
			record, err := loadRecord(env.opts, claudeVersionFloorRecord)
			if err != nil || record == nil {
				t.Fatalf("record: %v", err)
			}
			record.PostimageSHA256 = sha256Hex([]byte("another postimage"))
			if err := saveRecord(env.opts, record); err != nil {
				t.Fatal(err)
			}
		},
		// The drop-in still holds DefenseClaw's floor, so the pass adopts it
		// again; the plan from before kept the rewritten record.
		stale: func(o gap1833FloorOutcome) bool { return o.postimage != sha256Hex([]byte(wantClaudeFloorBytes)) },
	}}
	for _, race := range races {
		t.Run(race.name, func(t *testing.T) {
			// pass runs one floor pass on a fresh tree. With between, the
			// change lands after the pass read its files and before the lock;
			// without, before the pass starts.
			pass := func(between bool) gap1833FloorOutcome {
				env := fresh(t)
				dir := dirFor(env.opts, claudeFloorFile(t, env.opts))
				plain := func(fn func(string) error) error { return fn(dir) }
				var state State
				if race.published {
					if err := reconcileClaudeVersionFloorFor(env.opts, []string{"claudecode"}, plain, &state); err != nil {
						t.Fatal(err)
					}
					if readFile(t, claudeFloorFile(t, env.opts)) != wantClaudeFloorBytes {
						t.Fatal("the floor was not published")
					}
				}
				locked := plain
				if between {
					changed := false
					locked = func(fn func(string) error) error {
						if race.every || !changed {
							race.change(t, env)
							changed = true
						}
						return fn(dir)
					}
				} else {
					race.change(t, env)
				}
				state = State{}
				err := reconcileClaudeVersionFloorFor(env.opts, []string{"claudecode"}, locked, &state)
				outcome := gap1833FloorOutcome{failed: err != nil, changed: state.Changed}
				if data, err := os.ReadFile(claudeFloorFile(t, env.opts)); err == nil {
					outcome.floor = string(data)
				}
				if record, err := loadRecord(env.opts, claudeVersionFloorRecord); err == nil && record != nil {
					outcome.recorded, outcome.postimage = true, record.PostimageSHA256
				}
				return outcome
			}
			want, got := pass(false), pass(true)
			if race.stale(got) {
				t.Errorf("the pass applied a plan from before the change: %+v", got)
			}
			if got != want {
				t.Errorf("a change between the read and the lock left %+v, the same change before the pass left %+v", got, want)
			}
		})
	}
}

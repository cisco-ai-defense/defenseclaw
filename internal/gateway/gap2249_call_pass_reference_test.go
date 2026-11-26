// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP2249CallPassIsTheParentPass: the guest placement's script-call pass
// (guestPlacementPlan.placements) with its rel-1-0-10:GAP-2249 shortcuts (a
// cut, full pass skips plain candidates; each folder's first place read
// once; a repeated text offered only in the folders known since its last
// call) gives the same placements and cut as the pass before them
// (placementsReference, the 41e3f0e759 body), for both statement budgets,
// on the cost shapes, the gate calls and 400 generated scripts of repeated
// cds, unread commands, functions, loops and subshells.
func TestGAP2249CallPassIsTheParentPass(t *testing.T) {
	home := sandboxauth.SandboxHome
	fill := func(prefix, unit, tail string) string {
		var b strings.Builder
		b.WriteString(prefix)
		for i := 0; b.Len()+len(unit)+len(tail)+8 < 8192; i++ {
			b.WriteString(strings.ReplaceAll(unit, "%d", fmt.Sprint(i)))
		}
		return b.String() + tail
	}
	lines := func(k int, unit string) string {
		var b strings.Builder
		for i := range k {
			b.WriteString(strings.ReplaceAll(unit, "%d", fmt.Sprint(i)))
		}
		return b.String()
	}
	commands := []string{
		fill("cd .cache\n$CMD\n", "cd s%d; $C\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd d%d\n", "ls"),
		fill("cd .cache\nbash <<< 'true'\n", "touch f%d\n", "ls"),
		fill("cd .cache\nbash <<< 'true'\n$CMD\n"+lines(7, "cd s%d\n"), "touch f%d\n", "ls"),
		"cd .cache\n$CMD\n" + lines(7, "cd s%d\n") + lines(118, "touch f%d\n") + "ls",
		fill("bash <<< 'true'\n", "f%d() { cd d%d; }\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd s%d; $C; f; $C\n", "f() { cd x; }\nf\nls"),
		"cd .cache\nbash <<< 'true'\n" + lines(45, "cd /tmp/rk4r%d && ls\n") + "ls",
	}
	commands = append(commands, fx0999GateCommands(t, home)...)
	atoms := []string{"cd s1", "cd s2", "$C", "$CMD", "cd ..", "touch f1", "touch f2", "cat ../.ssh/id_ed25519", "f() { cd d; $C; }", "f",
		"for i in 1 2; do cd x; $C; done", "(cd ~/.ssh; ls)", "cd -", "bash <<< 'true'", "echo k >> authorized_keys", "pushd a", "popd",
		"export CDPATH=/etc", "cd ~/.defenseclaw && ls", "cd ../.ssh || exit", "eval $X", "ls", "cd \"$D\"", "D=~/.claude; cd \"$D\""}
	random := rand.New(rand.NewPCG(2249, 1))
	for range 400 {
		n := 3 + random.IntN(300)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = atoms[random.IntN(len(atoms))]
		}
		commands = append(commands, strings.Join(parts, "\n"))
	}
	checked := 0
	for _, cwd := range []string{home, home + "/p"} {
		for _, command := range commands {
			input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home}
			plan := (*guestReadingMemo)(nil).plan(input, actionfacts.Analyze(input))
			for _, budget := range []bool{true, false} {
				got, gotCut := plan.placements(budget)
				want, wantCut := plan.placementsReference(budget)
				checked += len(want)
				if gotCut != wantCut || !reflect.DeepEqual(slices.Clip(got), slices.Clip(want)) {
					t.Fatalf("cwd %s budget %v: %q: placements differ from the parent pass (cut %v / %v, %d / %d readings)",
						cwd, budget, command[:min(len(command), 200)], gotCut, wantCut, len(got), len(want))
				}
			}
		}
	}
	t.Logf("GAP2249CALLPASS commands=%d readings=%d", 2*len(commands), checked)
}

// placementsReference is guestPlacementPlan.placements at 41e3f0e759, before
// the rel-1-0-10:GAP-2249 call-pass shortcuts (TestGAP2249CallPassIsTheParentPass).
func (plan *guestPlacementPlan) placementsReference(statementBudget bool) (placements []guestPlacement, cut bool) {
	if plan.authoritative {
		return slices.Clone(plan.whole), plan.wholeCut
	}
	overBudget := false
	if statementBudget {
		plan.overBudgetOnce.Do(func() { plan.overBudgetSet = plan.overBudget() })
		overBudget = plan.overBudgetSet
	}
	type key = guestKey
	seen := map[key]int{}
	// pass counts the statements and readings of one pass.
	type pass struct {
		statements map[string]bool
		read       int
	}
	place := func(p *pass, text, cwd string, candidate bool) bool {
		if at, ok := seen[key{text, cwd}]; ok {
			placements[at].candidate = placements[at].candidate && candidate
			return true
		}
		if !p.statements[text] {
			if overBudget && len(p.statements) == maxSandboxGuestPlacedChildren {
				return false
			}
			p.statements[text] = true
		}
		if p.read == maxSandboxGuestPlacements {
			return false
		}
		p.read++
		seen[key{text, cwd}] = len(placements)
		placements = append(placements, guestPlacement{text: text, cwd: cwd, candidate: candidate})
		return true
	}
	placeAll := func(p *pass, list []guestPending) bool {
		var firsts, plains []guestPending
		for _, reading := range list {
			if guestReadingFirst(reading.text) {
				firsts = append(firsts, reading)
			} else {
				plains = append(plains, reading)
			}
		}
		slices.SortFunc(firsts, func(a, b guestPending) int { return a.seq - b.seq })
		for _, reading := range slices.Concat(firsts, plains) {
			if !place(p, reading.text, reading.cwd, reading.candidate) {
				return false
			}
		}
		return true
	}
	// A cut pass does not end the others: each has its own bound, and the
	// call is reported cut.
	simplesCut := !placeAll(&pass{statements: map[string]bool{}}, plan.simples) || plan.simplesDropped
	if !plan.rest {
		return placements, simplesCut
	}
	topCut := false
	top := &pass{statements: map[string]bool{}}
	for _, reading := range plan.top {
		if !place(top, reading.text, reading.cwd, false) {
			topCut = true
			break
		}
	}
	// The placed children (statementBudget) read each script call by
	// position; the hook-config guard only a call the laptop guard places
	// statement by statement (plan.byPosition; see newGuestPlacementPlan,
	// substrate-1 GAP-0988).
	byPosition := statementBudget || plan.byPosition
	var callReadings []guestPending
	callsDropped, callsListed, arrivals := false, map[key]int{}, 0
	var callsPlain []int
	for _, call := range plan.calls {
		for _, dir := range plan.dirs {
			if !byPosition || plan.known[dir] <= call.at {
				callReadings = guestCollect(callReadings, callsListed, &callsPlain, &callsDropped, &arrivals, guestPending{call.text, dir, false, 0})
			}
		}
		for _, dir := range plan.targets {
			if !byPosition || plan.known[dir] <= call.at {
				callReadings = guestCollect(callReadings, callsListed, &callsPlain, &callsDropped, &arrivals, guestPending{call.text, dir, true, 0})
			}
		}
	}
	callsCut := !placeAll(&pass{statements: map[string]bool{}}, callReadings) || callsDropped
	return placements, simplesCut || topCut || callsCut
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// maxSandboxGuestCandidateDirs bounds the directories a sandbox call may
// stand in that the guest placement keeps as candidates
// (sandboxGuestPlacements): the 64 places the laptop's statement reader
// keeps (hookpaths.TopLevelStatements). Past it the directories already kept
// stay and a later one is not added, as the laptop's private-key reader
// keeps its first candidate directories (actionPosixPrivateKeyRead): an
// earlier cd target a later relative read depends on is never dropped.
// Dropping the oldest one let cd .cache, a here-string, 63 cd /tmp/x && ls
// and cat ../.ssh/id_ed25519 read the guest's key where the laptop blocks
// (substrate-1 GAP-0499).
const maxSandboxGuestCandidateDirs = 64

// maxSandboxGuestPlacements bounds the readings of one pass of the guest
// placement: every statement the call's budget allows
// (maxSandboxGuestPlacedChildren) in every candidate directory, so a call
// within the laptop's statement budget is never cut by it. Only a call the
// laptop does not count (a here-string call parses invalid, rel-1-0-10
// statement budget) can reach it, and is then cut (fail-closed).
const maxSandboxGuestPlacements = maxSandboxGuestPlacedChildren * maxSandboxGuestCandidateDirs

// guestPlacement is one command text and the directory it is read in.
// candidate marks a directory the call may stand in only by a cd target that
// no command of the call is read in (a cd in a subshell or a function body,
// CDPATH): that reading judges only what the laptop's readers judge on a
// candidate directory, the private-key read proof and the hook-config write
// (sandboxGuestPlacedChildren, sandboxAgentHookConfigChange); every other
// owner keeps the directories the call's commands run in, so
// (cd ~/.defenseclaw || cd /tmp) && eval 'echo m > config.yaml' writes the
// starting directory's config.yaml, as on the laptop (S7's no-block rows).
type guestPlacement struct {
	text, cwd string
	candidate bool
}

// sandboxGuestPlacements lists, lexically, the commands of a sandbox call
// (input is placed in the guest's working directory, sandboxGuestPlacedInput)
// with each directory they may run in, for the guest placement
// (sandboxGuestPlacedChildren) and the sandbox hook-config guard
// (sandboxAgentHookConfigChange). A text repeated in the same directory is
// listed once. cut reports a call whose readings stop short; the caller
// gives it the evaluation-limit finding, never a clean allow
// (substrate-1 GAP-0304).
//
// A call the analysis read in full lists each simple command a static cd
// moved out of the guest's directory, in each directory the walk places it,
// up to maxSandboxGuestPlacedChildren statements (and
// maxSandboxGuestPlacements readings): its whole-call view judges the rest.
//
// A call the analysis did not read in full has no whole-call view that
// judges it (substrate-1 GAP-0363):
//   - A hook call that carries the command only in its arguments (Claude
//     Code) is split from its text: the split of an Args-only call the POSIX
//     reader rejects (a here-string, <(...), . /dev/stdin) placed nothing, so
//     a read after pushd, popd, cd -, { cd x; } or a function body went
//     unread (substrate-1 GAP-0378).
//   - Each simple command is read in its own directory and in every
//     directory the call stood in before it, the guest's included, and each
//     command of the script (a function body's too, guestScriptCalls) in
//     each of those directories and in each static cd or pushd target
//     (guestCDJoin) as a candidate: the CD-CANDIDATE rule of the laptop's
//     readers, which keep the earlier directories where the directory is
//     uncertain ((cd x), cd -, popd, CDPATH, a function that cds, a cd after
//     $CMD; substrate-1 GAP-0379). At most maxSandboxGuestCandidateDirs
//     directories are kept.
//   - Its top-level statements are read too, each in every directory the
//     laptop's statement reader places it (hookpaths.TopLevelStatements).
//
// Such a call is counted by statements, not readings: each pass is cut at
// maxSandboxGuestPlacedChildren statements only when the call is over the
// laptop's own statement budget (trustedCallOverStatementBudget, the call
// as the hook sent it), which gives the laptop the same limit. Charging
// every reading to that cap cut a script of 63 statements after one cd (two
// places each) where the laptop judges it in full (substrate-1 GAP-0377).
// The readings of a pass are bounded at maxSandboxGuestPlacements. The
// hook-config guard passes statementBudget false: like the laptop guard it
// reads a call past the statement budget too, so the call that carries the
// limit finding still names the write (substrate-1 GAP-0359).
func sandboxGuestPlacements(input actionfacts.Input, facts actionfacts.Facts, statementBudget bool) (placements []guestPlacement, cut bool) {
	return newGuestPlacementPlan(input, facts, nil, nil).placements(statementBudget)
}

// guestPending is a reading a pass of the guest placement lists before it is
// placed (guestPlacementPlan).
type guestPending struct {
	text, cwd string
	candidate bool
}

// guestPlacementPlan is the walk of sandboxGuestPlacements, made once for
// both statement budgets: the placements of a call the analysis read in
// full, or, for any other call, the readings each pass lists in order and
// whether a pass dropped one. Only placing them (placements) depends on the
// statement budget, which cuts a pass of a call over the laptop's own
// statement budget at maxSandboxGuestPlacedChildren statements. The
// placed-children reading and the sandbox hook-config guard each made the
// whole walk again, SimpleCommands included, for the same input; one plan
// serves both (guestReadingMemo, substrate-1 GAP-0923, GAP-1028).
type guestPlacementPlan struct {
	authoritative bool
	// whole and wholeCut are the placements of an authoritative call.
	whole    []guestPlacement
	wholeCut bool
	// The passes of any other call: the simple commands, the top-level
	// statements and every call of the script. rest is false when the
	// call has no top-level or script-call pass (no command text, or one
	// over agentHookConfigMaxPlacedBytes).
	simples        []guestPending
	simplesDropped bool
	rest           bool
	top            []guestPending
	calls          []guestPending
	callsDropped   bool
	// overBudget is trustedCallOverStatementBudget of the call as the hook
	// sent it, worked out once when a statement-budget placement asks.
	overBudget     func() bool
	overBudgetOnce sync.Once
	overBudgetSet  bool
}

// newGuestPlacementPlan walks input and facts for sandboxGuestPlacements.
// split is the simple-command split (actionfacts.SimpleCommands when nil):
// the call's own split serves the walk and the statement budget both.
// analyze reads a call sent as tool arguments as its command
// (actionfacts.Analyze when nil).
func newGuestPlacementPlan(input actionfacts.Input, facts actionfacts.Facts,
	split func(actionfacts.Input, actionfacts.Facts) []actionfacts.SimpleCommand,
	analyze func(actionfacts.Input) actionfacts.Facts) *guestPlacementPlan {
	if split == nil {
		split = actionfacts.SimpleCommands
	}
	if analyze == nil {
		analyze = actionfacts.Analyze
	}
	plan := &guestPlacementPlan{}
	if facts.Authoritative() {
		plan.authoritative = true
		plan.whole, plan.wholeCut = guestAuthoritativePlacements(input, split(input, facts))
		return plan
	}
	sent, sentFacts, swapped := input, facts, false
	if input.Command == "" {
		if command, ok := trustedBashCommandInput(input); ok {
			input.Command, input.Args, input.Argv = command, nil, nil
			facts = analyze(input)
			swapped = true
		}
	}
	simples := split(input, facts)
	plan.overBudget = func() bool {
		if swapped {
			return trustedCallOverStatementBudgetWith(sent, sentFacts, split(sent, sentFacts))
		}
		return trustedCallOverStatementBudgetWith(sent, sentFacts, simples)
	}
	type key struct{ text, cwd string }
	// dirs are the directories the call's commands run in, targets the cd
	// targets no command is read in yet; each keeps its first
	// maxSandboxGuestCandidateDirs entries, the guest's directory first
	// (substrate-1 GAP-0499).
	keep := func(list []string, dir string) []string {
		if !path.IsAbs(dir) || len(list) == maxSandboxGuestCandidateDirs || slices.Contains(list, path.Clean(dir)) {
			return list
		}
		return append(list, path.Clean(dir))
	}
	var dirs, targets []string
	dirs = keep(dirs, input.CWD)
	targets = keep(targets, input.CWD)
	// A pass first lists its readings in source order, as the folders evolve,
	// then places those whose text may name a path in another folder
	// before the rest (guestReadingFirst): when the readings bound cuts a
	// pass, it cuts touch f1 ... touch f150, not the cat ../.ssh/id_ed25519
	// after them, which read keeps the laptop's block next to the limit
	// (substrate-1 GAP-0501).
	//
	// collect keeps the distinct readings of a pass, at most
	// maxSandboxGuestPlacements. Past the bound the pass is cut (dropped): a
	// plain reading is not kept, and a first reading (guestReadingFirst)
	// takes the place of the last plain one kept, so the list stays at the
	// bound (substrate-1 GAP-0624: a here-string call listed ~200k readings)
	// and a protected tail is still read next to the limit (GAP-0501).
	// plain holds the indexes of the plain readings kept; listed maps each
	// reading kept to its index.
	//
	// A reading listed as a candidate that comes again in a directory the
	// call runs in is no longer a candidate: every owner reads it, as place
	// does for a reading placed twice. The split reads a body after a cd that
	// may fail in each folder the chain may leave (rel-1-0-10:GAP-1144), so
	// cd ~/.defenseclaw || cd /tmp && sh -c 'x=config.yaml; echo m > $x'
	// gives echo m > 'config.yaml' in ~/.defenseclaw after the earlier cd
	// listed that folder as a target. Kept as a candidate, judged only for a
	// private-key read and a hook-config write, it let the actor allow the
	// write the laptop blocks with tamper.detector_state_write
	// (substrate-1 GAP-0645).
	collect := func(list []guestPending, listed map[key]int, plain *[]int, dropped *bool, reading guestPending) []guestPending {
		at := key{reading.text, reading.cwd}
		if index, ok := listed[at]; ok {
			list[index].candidate = list[index].candidate && reading.candidate
			return list
		}
		first := guestReadingFirst(reading.text)
		if len(list) >= maxSandboxGuestPlacements {
			*dropped = true
			if !first || len(*plain) == 0 {
				return list
			}
			last := (*plain)[len(*plain)-1]
			*plain = (*plain)[:len(*plain)-1]
			delete(listed, key{list[last].text, list[last].cwd})
			listed[at] = last
			list[last] = reading
			return list
		}
		if !first {
			*plain = append(*plain, len(list))
		}
		listed[at] = len(list)
		return append(list, reading)
	}
	simplesListed := map[key]int{}
	var simplesPlain []int
	// stoodIn is the folder of the last command that is not a directory
	// change, held until the next command of the split shows whether the
	// call still stands there. When the split places the next command in
	// another folder with no directory change between them, a ( ... )
	// group, a pipeline stage before the last or a command substitution
	// ended: its folder is a candidate for the later commands (the
	// laptop's CD-CANDIDATE rule), not a folder they run in. Kept as a
	// folder the call runs in,
	// it gave (cd ~/.defenseclaw && ls); echo m > config.yaml the reading
	// echo m > config.yaml in ~/.defenseclaw, and the actor blocked with
	// tamper.detector_state_write where the laptop allows
	// (substrate-1 GAP-0648). A next reading in another folder the same
	// statement may run in (OtherFolder), or in a folder the split cannot
	// tell, settles nothing: the folder stays one the call runs in.
	// The folder of a command in the last stage of a pipeline or in an &
	// list (LastStageOrBackground) is one the call runs in at once, as
	// before GAP-0648: zsh and Bash with lastpipe run the last stage in the
	// shell itself, and the laptop keeps both folders, so
	// true | { cd ~/.claude && ls; }; echo x > settings.json keeps the
	// laptop's tamper.agent_hook_config_write alert (GAP-0648 review P2-1).
	cd := &guestCDMemo{home: input.ActiveHome, texts: map[string]guestCDReading{}}
	stoodIn, standing := "", false
	settle := func(simple actionfacts.SimpleCommand) {
		if !standing || simple.OtherFolder {
			return
		}
		standing = false
		if !simple.UnresolvedFolder && path.IsAbs(simple.CWD) && path.Clean(simple.CWD) != stoodIn {
			targets = keep(targets, stoodIn)
			return
		}
		dirs = keep(dirs, stoodIn)
	}
	for _, simple := range simples {
		settle(simple)
		if guestPlacementSkips(simple) {
			continue
		}
		cwd := simple.CWD
		if path.IsAbs(cwd) {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, cwd, false})
		}
		for _, dir := range dirs {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, dir, false})
		}
		for _, dir := range targets {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, dir, true})
		}
		bases := slices.Concat(dirs, targets)
		if path.IsAbs(cwd) {
			bases = []string{cwd}
		}
		// The split gives a cd the directory its walk reached, as if every
		// cd before it ran: (cd ~/.defenseclaw || cd /tmp) runs cd /tmp only
		// where the first cd failed. A directory change's own directory is
		// a candidate; the directory of any other command is one the call
		// runs in, once the next command shows the call still stands there
		// (stoodIn).
		reading := cd.reading(simple.Text)
		switch {
		case reading.changes:
			targets = keep(targets, cwd)
		case simple.OtherFolder || simple.UnresolvedFolder || simple.LastStageOrBackground || !path.IsAbs(cwd):
			dirs = keep(dirs, cwd)
		default:
			stoodIn, standing = path.Clean(cwd), true
		}
		for _, target := range guestCDJoin(reading, bases, input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	if standing {
		dirs = keep(dirs, stoodIn)
	}
	command := input.Command
	if command == "" || len(command) > agentHookConfigMaxPlacedBytes {
		return plan
	}
	plan.rest = true
	if statements, ok := hookpaths.TopLevelStatements(command, input.CWD, input.ActiveHome); ok {
		for _, statement := range statements {
			if path.IsAbs(statement.Dir) {
				plan.top = append(plan.top, guestPending{statement.Command, statement.Dir, false})
			}
		}
	}
	// Every call of the script, a function body's included: the split stops
	// at a construct it cannot read (f() { cd .cache; }; f; $CMD gives one
	// parse failure), while a static cd anywhere in the text is still a
	// directory the laptop's readers keep.
	callsListed := map[key]int{}
	var callsPlain []int
	for _, call := range guestScriptCalls(command) {
		for _, dir := range dirs {
			plan.calls = collect(plan.calls, callsListed, &callsPlain, &plan.callsDropped, guestPending{call, dir, false})
		}
		for _, dir := range targets {
			plan.calls = collect(plan.calls, callsListed, &callsPlain, &plan.callsDropped, guestPending{call, dir, true})
		}
		for _, target := range guestCDJoin(cd.reading(call), slices.Concat(dirs, targets), input.ActiveHome) {
			targets = keep(targets, target)
		}
	}
	return plan
}

// guestAuthoritativePlacements places the simple commands of a call the
// analysis read in full (sandboxGuestPlacements).
func guestAuthoritativePlacements(input actionfacts.Input, simples []actionfacts.SimpleCommand) (placements []guestPlacement, cut bool) {
	type key struct{ text, cwd string }
	seen := map[key]bool{}
	// Counted by statements, as the laptop counts them: the walk reads a
	// command after a cd that may not run in every directory it may run
	// in, so after three such cds each later command has seven readings
	// outside the guest's directory, and a cap on readings cut a 24-line
	// script the laptop allows (a here-string call, judged by its
	// authoritative twin, substrate-1 GAP-0377).
	statements := map[string]bool{}
	for _, simple := range simples {
		cwd := simple.CWD
		if guestPlacementSkips(simple) || !path.IsAbs(cwd) || cwd == input.CWD {
			continue
		}
		if seen[key{simple.Text, cwd}] {
			continue
		}
		if !statements[simple.Text] {
			if len(statements) == maxSandboxGuestPlacedChildren {
				return placements, true
			}
			statements[simple.Text] = true
		}
		if len(placements) == maxSandboxGuestPlacements {
			return placements, true
		}
		seen[key{simple.Text, cwd}] = true
		placements = append(placements, guestPlacement{text: simple.Text, cwd: cwd})
	}
	return placements, false
}

// placements places the plan's readings, each pass in turn
// (sandboxGuestPlacements); statementBudget cuts a pass of a call over the
// laptop's statement budget at maxSandboxGuestPlacedChildren statements.
func (plan *guestPlacementPlan) placements(statementBudget bool) (placements []guestPlacement, cut bool) {
	if plan.authoritative {
		return slices.Clone(plan.whole), plan.wholeCut
	}
	overBudget := false
	if statementBudget {
		plan.overBudgetOnce.Do(func() { plan.overBudgetSet = plan.overBudget() })
		overBudget = plan.overBudgetSet
	}
	type key struct{ text, cwd string }
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
		for _, first := range []bool{true, false} {
			for _, reading := range list {
				if guestReadingFirst(reading.text) == first && !place(p, reading.text, reading.cwd, reading.candidate) {
					return false
				}
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
	callsCut := !placeAll(&pass{statements: map[string]bool{}}, plan.calls) || plan.callsDropped
	return placements, simplesCut || topCut || callsCut
}

// guestReadingMemo keeps, for one hook evaluation, the simple-command split
// of each guest-placed input and its guest placement plan: the
// placed-children reading, the split-gap reading and the sandbox hook-config
// guard each made them from the start for the same input, up to four
// SimpleCommands passes a hook (substrate-1 GAP-0923, GAP-1028). An entry
// serves only an input and facts equal to the ones it was made for; any
// other is read afresh. A copy of the request shares it; a nil memo keeps
// nothing.
type guestReadingMemo struct {
	mu     sync.Mutex
	splits []guestSplitEntry
	plans  []guestPlanEntry
	// readings are the guest readings of the hook (analyze), and children
	// their placed children (sandboxGuestPlacedChildren).
	readings []guestAnalysisEntry
	children []guestChildrenEntry
	// relative keeps the relative-operand answers of every split of the
	// hook (actionfacts.RelativeOperandMemo).
	relative actionfacts.RelativeOperandMemo
}

type guestSplitEntry struct {
	input   actionfacts.Input
	facts   actionfacts.Facts
	simples []actionfacts.SimpleCommand
}

type guestPlanEntry struct {
	input actionfacts.Input
	facts actionfacts.Facts
	plan  *guestPlacementPlan
}

type guestAnalysisEntry struct {
	input actionfacts.Input
	facts actionfacts.Facts
}

type guestChildrenEntry struct {
	input                actionfacts.Input
	facts                actionfacts.Facts
	children, candidates []actionfacts.Facts
	cut                  bounded.CapSet
}

// guestReadingMemoEntries bounds each list of a guestReadingMemo: a hook
// reads a few guest inputs (the call, its twins), and an older entry gives
// way to a newer one.
const guestReadingMemoEntries = 4

// simpleCommands is actionfacts.SimpleCommands(input, facts).
func (memo *guestReadingMemo) simpleCommands(input actionfacts.Input, facts actionfacts.Facts) []actionfacts.SimpleCommand {
	if memo == nil {
		return actionfacts.SimpleCommands(input, facts)
	}
	memo.mu.Lock()
	for _, entry := range memo.splits {
		if reflect.DeepEqual(entry.input, input) && reflect.DeepEqual(entry.facts, facts) {
			memo.mu.Unlock()
			return slices.Clone(entry.simples)
		}
	}
	memo.mu.Unlock()
	simples := actionfacts.SimpleCommandsWith(input, facts, &memo.relative)
	memo.mu.Lock()
	if len(memo.splits) == guestReadingMemoEntries {
		memo.splits = slices.Delete(memo.splits, 0, 1)
	}
	memo.splits = append(memo.splits, guestSplitEntry{input: input, facts: facts, simples: slices.Clone(simples)})
	memo.mu.Unlock()
	return simples
}

// analyze is actionfacts.Analyze(input). Each dispatch of a hook reads the
// guest reading of its call (sandboxGuestPlacedInput) up to five times, the
// sandbox hook-config guard and the high-write proof read it again, and a
// hook dispatches the same call many times: one sandbox call was analyzed
// about fifty times a hook for the same input (substrate-1 GAP-1028). The
// analysis is lexical and depends on the input alone. Each caller gets the
// facts with every list at its length (clippedFacts), so an append by one
// never writes into the array another holds.
func (memo *guestReadingMemo) analyze(input actionfacts.Input) actionfacts.Facts {
	if memo == nil {
		return actionfacts.Analyze(input)
	}
	memo.mu.Lock()
	for _, entry := range memo.readings {
		if reflect.DeepEqual(entry.input, input) {
			memo.mu.Unlock()
			return clippedFacts(entry.facts)
		}
	}
	memo.mu.Unlock()
	facts := actionfacts.Analyze(input)
	memo.mu.Lock()
	if len(memo.readings) == guestReadingMemoReadings {
		memo.readings = slices.Delete(memo.readings, 0, 1)
	}
	memo.readings = append(memo.readings, guestAnalysisEntry{input: input, facts: facts})
	memo.mu.Unlock()
	return clippedFacts(facts)
}

// guestReadingMemoReadings bounds the guest readings a guestReadingMemo
// keeps: the call, its twins and the statements the dispatch reads alone.
const guestReadingMemoReadings = 8

// clippedFacts is facts with each of its lists at its length.
func clippedFacts(facts actionfacts.Facts) actionfacts.Facts {
	value := reflect.ValueOf(&facts).Elem()
	for at := range value.NumField() {
		if field := value.Field(at); field.Kind() == reflect.Slice && field.CanSet() && !field.IsNil() {
			field.Set(field.Slice3(0, field.Len(), field.Len()))
		}
	}
	return facts
}

// placedChildren is sandboxGuestPlacedChildren(memo, input, facts) for a
// hook that already read them: every dispatch of the call reads the same
// children again.
func (memo *guestReadingMemo) placedChildren(input actionfacts.Input, facts actionfacts.Facts) (children, candidates []actionfacts.Facts, cut bounded.CapSet, ok bool) {
	if memo == nil {
		return nil, nil, bounded.CapSet{}, false
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	for _, entry := range memo.children {
		if reflect.DeepEqual(entry.input, input) && reflect.DeepEqual(entry.facts, facts) {
			return clippedFactsList(entry.children), clippedFactsList(entry.candidates), entry.cut, true
		}
	}
	return nil, nil, bounded.CapSet{}, false
}

// keepPlacedChildren keeps the placed children of input and facts.
func (memo *guestReadingMemo) keepPlacedChildren(input actionfacts.Input, facts actionfacts.Facts, children, candidates []actionfacts.Facts, cut bounded.CapSet) {
	if memo == nil {
		return
	}
	entry := guestChildrenEntry{input: input, facts: facts, children: clippedFactsList(children), candidates: clippedFactsList(candidates), cut: cut}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if len(memo.children) == guestReadingMemoEntries {
		memo.children = slices.Delete(memo.children, 0, 1)
	}
	memo.children = append(memo.children, entry)
}

// clippedFactsList is a copy of list with each facts clipped (clippedFacts).
func clippedFactsList(list []actionfacts.Facts) []actionfacts.Facts {
	if list == nil {
		return nil
	}
	out := make([]actionfacts.Facts, len(list))
	for at, facts := range list {
		out[at] = clippedFacts(facts)
	}
	return out
}

// plan is newGuestPlacementPlan(input, facts) over the memo's splits.
func (memo *guestReadingMemo) plan(input actionfacts.Input, facts actionfacts.Facts) *guestPlacementPlan {
	if memo == nil {
		return newGuestPlacementPlan(input, facts, nil, nil)
	}
	memo.mu.Lock()
	for _, entry := range memo.plans {
		if reflect.DeepEqual(entry.input, input) && reflect.DeepEqual(entry.facts, facts) {
			memo.mu.Unlock()
			return entry.plan
		}
	}
	memo.mu.Unlock()
	plan := newGuestPlacementPlan(input, facts, memo.simpleCommands, memo.analyze)
	memo.mu.Lock()
	if len(memo.plans) == guestReadingMemoEntries {
		memo.plans = slices.Delete(memo.plans, 0, 1)
	}
	memo.plans = append(memo.plans, guestPlanEntry{input: input, facts: facts, plan: plan})
	memo.mu.Unlock()
	return plan
}

// guestReadingFirst reports a command text whose reading in another folder
// may reach a different protected path: a word with a dot or a slash
// (../.ssh/id_ed25519, .bashrc, a/b), a ~, an expansion or a pattern. A text
// of plain words (touch f1, ls, cd sub) is read after them.
func guestReadingFirst(text string) bool {
	return strings.ContainsAny(text, "./~$`*?[{\\")
}

// withSandboxGuestFolderTier gives a sandbox call the unknown tier the
// laptop gives the same call in its own folder (withUnresolvedFolderTier,
// rel-1-0-10:GAP-0871): an operand that may name a protected file in a
// folder the call does not give, after a function that cds or a $CMD. A
// copy-mode call names no folder, so the tier is read on the call placed in
// the guest's working directory (sandboxGuestPlacedInput), as the laptop
// reads it in its own. It is decided on that whole-call reading alone: the
// commands the guest placement reads one by one (sandboxGuestPlacements) are
// the laptop's piece readings, whose proof comes after the laptop's tier, so
// their proof does not take the tier away here either. f() { cd .cache; };
// f; $CMD; rm .defenseclaw/audit.db blocked in both, and only the laptop
// named ACTION-COMPOUND-LIMIT (substrate-1 GAP-0377 at FU8). The reading is
// lexical and only adds a finding.
func withSandboxGuestFolderTier(findings []RuleFinding, request trustedActionRequest, facts actionfacts.Facts) []RuleFinding {
	if request.simpleCommandPass || request.hostTwinDepth != 0 || request.stateProofOnly {
		return findings
	}
	guest, ok := sandboxGuestPlacedInput(request, facts)
	if !ok {
		return findings
	}
	guestFacts := request.guestMemo.analyze(guest)
	if !guestFacts.MayRunInUnresolvedFolder() {
		return findings
	}
	placed := request
	placed.Input, placed.SandboxGuestCWD = guest, ""
	return withSimpleCommandFindings(findings, withUnresolvedFolderTier(nil, placed, guestFacts, false))
}

// withSandboxGuestSplitGapEffects judges the files a sandbox call with a
// parse gap touches as the laptop judges the same call in its own folder
// (withSplitGapEffects): on the call placed in the guest's working directory
// (sandboxGuestPlacedInput). The effect twins name each file in its resolved
// spelling, and a copy-mode call names no folder, so a relative operand
// resolved nowhere and no twin was judged: cd .cache; cd -; $CMD; rm
// ../.bash_history was an allow where the laptop alerts with
// ACTION-COMPOUND-LIMIT (cd -, cd "$D", a function that cds), and $CMD; rm
// .bash_history named PATH-HISTORY without the laptop's limit (substrate-1
// GAP-0363, GAP-0377). The same at rel 5597ca2b83, before the guest
// placement. It is read only when the split of the call placed there has a
// parse gap, as the laptop's is: a copy-mode split with no folder may have
// one where the laptop's has none (cd .cache; rm ../.bash_history), and the
// laptop judges that call by its split alone. The reading is lexical and
// only adds findings.
func withSandboxGuestSplitGapEffects(ctx context.Context, request trustedActionRequest, generation *compiledRulePackCategories,
	budget *trustedActionBudget, facts actionfacts.Facts, wholeCommand string, findings []RuleFinding) []RuleFinding {
	guest, ok := sandboxGuestPlacedInput(request, facts)
	if !ok {
		return findings
	}
	guestFacts := request.guestMemo.analyze(guest)
	if !slices.ContainsFunc(request.guestMemo.simpleCommands(guest, guestFacts), splitGapUnreadPart) {
		return findings
	}
	// The twins are judged in full (dispatchTrustedAction), in a folder of
	// the guest: no twin reads a host file spelled at a guest path, for any
	// connector (claudecode and codex already skip it for every sandbox
	// call).
	placed := request
	placed.Input = guest
	placed.SkipLocalFilesystemResolution = true
	return withSplitGapEffects(ctx, placed, generation, budget, guestFacts, wholeCommand, findings)
}

// guestPlacementSkips reports a simple command the guest placement does not
// read: one with no complete view, an opaque assignment, literal output, or
// a guessed login.
func guestPlacementSkips(simple actionfacts.SimpleCommand) bool {
	return simple.EvaluationFailure != "" || simple.OpaqueValueAssignment || simple.LiteralOutputOnly || simple.LoginGuess
}

// guestCallRunsUnreadCommand reports, lexically, a script with a command the
// statement split cannot read and that may change the folder: a program word
// that is not static ($CMD), or one of cmdRedefiningCommands (eval, source,
// ., trap, alias, ...) or mapfile and readarray (-C runs a string), also
// behind builtin, command or exec (the sandbox hook-config guard,
// substrate-1 GAP-0500). A script that does not parse counts, and so does a
// wrapper with options.
func guestCallRunsUnreadCommand(command, home string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return true
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) == 0 {
			return !found
		}
		for index, word := range call.Args {
			program, static := hookpaths.StaticWord(word, home)
			if !static || cmdRedefiningCommands[program] || program == "mapfile" || program == "readarray" {
				found = true
				break
			}
			// builtin, command and exec run the word after their options.
			if (program != "builtin" && program != "command" && program != "exec") || index == len(call.Args)-1 {
				break
			}
			if next, known := hookpaths.StaticWord(call.Args[index+1], home); known && strings.HasPrefix(next, "-") {
				found = true // an option word: read it as unread rather than parse every wrapper option
				break
			}
		}
		return !found
	})
	return found
}

// guestCall parses a command text that is one simple command.
func guestCall(text string) (*syntax.CallExpr, bool) {
	parser := guestParsers.Get().(*syntax.Parser)
	file, err := parser.Parse(strings.NewReader(text), "")
	// Parse returned, so the parser is done working and may be reused
	// (syntax.Parser.Parse); a panic does not return it.
	guestParsers.Put(parser)
	if err != nil || len(file.Stmts) != 1 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	return call, ok && len(call.Args) != 0
}

// guestParsers keeps Bash parsers for guestCall: a parser allocates two 1 KB
// buffers, and the guest placement reads every command text of a call
// (substrate-1 GAP-0923).
var guestParsers = sync.Pool{New: func() any { return syntax.NewParser(syntax.Variant(syntax.LangBash)) }}

// guestCDReading is what the lexical cd readers make of one command text:
// changes reports a cd, pushd or popd command;
// moves a cd or pushd whose words are static, with operand its operand ("" for
// none), which guestCDJoin places.
type guestCDReading struct {
	changes, moves bool
	operand        string
}

// readGuestCD reads, lexically, the cd of a command text.
func readGuestCD(text, home string) (reading guestCDReading) {
	call, ok := guestCall(text)
	if !ok {
		return reading
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	reading.changes = static && (program == "cd" || program == "pushd" || program == "popd")
	if !static || program != "cd" && program != "pushd" {
		return reading
	}
	operand := ""
	for _, word := range call.Args[1:] {
		value, static := hookpaths.StaticWord(word, home)
		if !static {
			return reading
		}
		if value == "--" || operand == "" && strings.HasPrefix(value, "-") && value != "-" {
			continue
		}
		operand = value
		break
	}
	reading.moves, reading.operand = true, operand
	return reading
}

// guestOtherProgramText reports, without a parse, a command text whose cd
// reading (guestCDReading) is the zero one: it starts with a word of plain
// name bytes (letters, digits, _ . / -) ended by a blank, a ; & or | or the
// end of the text, and that word is none of cd, pushd, popd, builtin or
// command. Such a word is static as it is (hookpaths.StaticWord) and is no
// assignment, so the text parses as a call of that program, as no simple
// call at all (a keyword, a pipeline) or not at all, and none of these
// changes or moves the folder. A guest call of thousands of commands parsed
// each command text again only to learn that, some 2 MB a hook on an 8 KB
// call (substrate-1 GAP-1028).
func guestOtherProgramText(text string) bool {
	end := 0
	for end < len(text) && guestPlainProgramByte(text[end]) {
		end++
	}
	if end == 0 {
		return false
	}
	if end < len(text) {
		switch text[end] {
		case ' ', '\t', '\n', ';', '&', '|':
		default:
			return false
		}
	}
	switch text[:end] {
	case "cd", "pushd", "popd", "builtin", "command":
		return false
	}
	return true
}

// guestPlainProgramByte reports a byte of a plain program word
// (guestOtherProgramText).
func guestPlainProgramByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '/' || c == '-'
}

// guestCDMemo reads each command text of one guest placement once
// (readGuestCD): the simples pass read every text twice, and the script-call
// pass again, each with a parse of its own (substrate-1 GAP-0923, GAP-1028).
// The reading is lexical: a text reads the same in one home every time.
type guestCDMemo struct {
	home  string
	texts map[string]guestCDReading
}

func (memo *guestCDMemo) reading(text string) guestCDReading {
	if guestOtherProgramText(text) {
		return guestCDReading{}
	}
	if reading, ok := memo.texts[text]; ok {
		return reading
	}
	reading := readGuestCD(text, memo.home)
	memo.texts[text] = reading
	return reading
}

// guestCDJoin returns, lexically, the directories a cd or pushd reading
// (readGuestCD) moves to from each of bases: a static operand joined to each
// base, an absolute or ~ operand as it is, the home for a bare cd. A dynamic
// operand, cd - and popd add none (they return to a directory already a
// candidate, or to one no static word names).
func guestCDJoin(reading guestCDReading, bases []string, home string) []string {
	if !reading.moves {
		return nil
	}
	operand := reading.operand
	switch {
	case operand == "-":
		return nil
	case operand == "" || operand == "~":
		if path.IsAbs(home) {
			return []string{path.Clean(home)}
		}
		return nil
	case strings.HasPrefix(operand, "~/") && path.IsAbs(home):
		return []string{path.Join(home, operand[2:])}
	case path.IsAbs(operand):
		return []string{path.Clean(operand)}
	}
	var targets []string
	for _, base := range bases {
		if path.IsAbs(base) {
			targets = append(targets, path.Join(base, operand))
		}
	}
	return targets
}

// guestScriptCalls returns, in source order, the source text of every
// simple-command statement of a Bash script, with its redirections, nested
// ones included (a function body, a group, a subshell, a process
// substitution), lexically; nil when the script does not parse.
func guestScriptCalls(command string) []string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	var calls []string
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if call, isCall := stmt.Cmd.(*syntax.CallExpr); !isCall || len(call.Args) == 0 {
			return true
		}
		// The statement's span keeps its redirections (> ../.claude/settings.json).
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start >= 0 && end <= len(command) && start < end {
			calls = append(calls, command[start:end])
		}
		return true
	})
	return calls
}

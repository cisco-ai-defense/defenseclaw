// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"math"
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
// (guestPlacementPlan): the 64 places the laptop's statement reader
// keeps (hookpaths.TopLevelStatements). Past it the directories already kept
// stay and a later one is not added, as the laptop's private-key reader
// keeps its first candidate directories (actionPosixPrivateKeyRead): an
// earlier cd target a later relative read depends on is never dropped.
// Dropping the oldest one let cd .cache, a here-string, 63 cd /tmp/x && ls
// and cat ../.ssh/id_ed25519 read the guest's key where the laptop blocks
// (substrate-1 GAP-0499).
const maxSandboxGuestCandidateDirs = 64

// maxSandboxGuestOwnShellFolders bounds the folders guestOwnShellFolders
// follows at once: each cd that may fail can double them, as the laptop's
// statement reader counts (cd .cache; $CMD; cd s0 .. s6; cd ../.ssh).
const maxSandboxGuestOwnShellFolders = 256

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

// guestPending is a reading a pass of the guest placement lists before it is
// placed (guestPlacementPlan).
type guestPending struct {
	text, cwd string
	candidate bool
	// seq is the reading's place in the order the pass lists its readings
	// (guestCollect).
	seq int
}

// guestKey is a reading of the guest placement: a command text in a folder.
type guestKey struct{ text, cwd string }

// guestPlacementPlan lists, lexically, the commands of a sandbox call
// (input is placed in the guest's working directory, sandboxGuestPlacedInput)
// with each directory they may run in, for the guest placement
// (sandboxGuestPlacedChildren) and the sandbox hook-config guard
// (sandboxAgentHookConfigChange). A text repeated in the same directory is
// listed once. The cut of placements reports a call whose readings stop
// short; the caller gives it the evaluation-limit finding, never a clean allow
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
//
// A plan is that walk, made once for both statement budgets: the
// placements of a call the analysis read in full, or, for any other call,
// the readings each pass lists in order and
// whether a pass dropped one. Only placing them (placements) depends on the
// statement budget: it cuts a pass of a call over the laptop's own statement
// budget at maxSandboxGuestPlacedChildren statements, and the placed
// children read every script call by position (byPosition). The
// placed-children reading and the sandbox hook-config guard each made the
// whole walk again, SimpleCommands and guestScriptCalls included, for the
// same input; one plan serves both (guestReadingMemo, substrate-1 GAP-0923,
// GAP-1028). A plan is not changed once made.
type guestPlacementPlan struct {
	authoritative bool
	// whole and wholeCut are the placements of an authoritative call.
	whole    []guestPlacement
	wholeCut bool
	// The passes of any other call: the simple commands, the top-level
	// statements and every call of the script the split did not read
	// (calls), with the folders the walk ended with (dirs, targets) and the
	// place each folder is known from (known). rest is false when the call
	// has no top-level or script-call pass (no command text, or one over
	// agentHookConfigMaxPlacedBytes). byPosition reports a call the laptop
	// guard places statement by statement.
	simples        []guestPending
	simplesDropped bool
	rest           bool
	top            []guestPending
	calls          []guestScriptCall
	dirs, targets  []string
	known          map[string]int
	byPosition     bool
	// overBudget is trustedCallOverStatementBudget of the call as the hook
	// sent it, worked out once when a statement-budget placement asks.
	overBudget     func() bool
	overBudgetOnce sync.Once
	overBudgetSet  bool
}

// newGuestPlacementPlan walks input and facts for the guest placement.
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
	type key = guestKey
	// dirs are the directories the call's commands run in, targets the cd
	// targets no command is read in yet; each keeps its first
	// maxSandboxGuestCandidateDirs entries, the guest's directory first
	// (substrate-1 GAP-0499). Past the bound a folder that may hold
	// protected files (guestDirFirst: the home, a hidden folder such as
	// ~/.ssh) takes the place of the last plain one kept: cd .cache; $CMD;
	// cd s0; ...; cd s6 lists 2^7 plain folders, and the cd ../.ssh after
	// them was never kept, so the authorized_keys write there was not read
	// where the laptop blocks (substrate-1 GAP-0628).
	// keepClean is keep of a clean absolute folder, which it does not clean
	// again: a cd chain of an 8 KB call makes folders of kilobytes, and
	// cleaning each of the thousands guestKnownFolders offers rescanned
	// them all (rel-1-0-10:GAP-2249).
	var keepClean func(list []string, dir string) []string
	keep := func(list []string, dir string) []string {
		if !path.IsAbs(dir) {
			return list
		}
		return keepClean(list, path.Clean(dir))
	}
	keepClean = func(list []string, dir string) []string {
		// A full list keeps no plain folder, listed or not, so it is not
		// searched for one: guestKnownFolders offers every cd target of an
		// 8 KB call to a full list (rel-1-0-10:GAP-2226).
		first := len(list) < maxSandboxGuestCandidateDirs || guestDirFirst(dir, input.ActiveHome)
		if !first || slices.Contains(list, dir) {
			return list
		}
		if len(list) < maxSandboxGuestCandidateDirs {
			return append(list, dir)
		}
		for at := len(list) - 1; at > 0; at-- {
			if !guestDirFirst(list[at], input.ActiveHome) {
				list[at] = dir
				return list
			}
		}
		return list
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
	arrivals := 0
	// collect keeps the distinct readings of a pass, at most
	// maxSandboxGuestPlacements. Past the bound the pass is cut (dropped): a
	// plain reading is not kept, and a first reading (guestReadingFirst)
	// takes the place of the last plain one kept, so the list stays at the
	// bound (substrate-1 GAP-0624: a here-string call listed ~200k readings)
	// and a protected tail is still read next to the limit (GAP-0501). Each
	// reading keeps the order it was listed in (seq), so a first reading
	// that takes an early plain slot is still placed after the first
	// readings listed before it (substrate-1 GAP-0637).
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
		return guestCollect(list, listed, plain, dropped, &arrivals, reading)
	}
	// placeAll places the first readings of a pass in the order they were
	// listed, then the plain ones: under the statement budget an earlier
	// protected reading is never skipped for a later one.
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
	stoodIn, standing := "", false
	// splitRead holds the texts the simples pass read, each in the folders
	// known at its own place in the call.
	splitRead := map[string]bool{}
	// followed counts, for each folder, the cd and pushd statements of the
	// split that reach it through a value the split followed (a variable, a
	// guessed login, a ~ it spelled out): guestKnownFolders. A statement the
	// split reads again at once, in another folder it may run in, counts
	// once (previous).
	followed := map[string]int{}
	previous := ""
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
	cdMemo := newGuestCDMemo(input.ActiveHome)
	for _, simple := range simples {
		settle(simple)
		if guestPlacementSkips(simple) {
			continue
		}
		splitRead[simple.Text] = true
		cwd := simple.CWD
		if path.IsAbs(cwd) {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, cwd, false, 0})
		}
		for _, dir := range dirs {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, dir, false, 0})
		}
		for _, dir := range targets {
			plan.simples = collect(plan.simples, simplesListed, &simplesPlain, &plan.simplesDropped, guestPending{simple.Text, dir, true, 0})
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
		reading := cdMemo.reading(simple.Text)
		switch {
		case reading.changes:
			targets = keep(targets, cwd)
		case simple.OtherFolder || simple.UnresolvedFolder || simple.LastStageOrBackground || !path.IsAbs(cwd):
			dirs = keep(dirs, cwd)
		default:
			stoodIn, standing = path.Clean(cwd), true
		}
		var moved []string
		if reading.moves {
			moved = guestCDJoin(reading.operand, bases, input.ActiveHome)
		}
		for _, target := range moved {
			targets = keep(targets, target)
		}
		if !simple.OtherFolder && simple.Text != previous && (simple.ResolvedVariable || simple.UnresolvedBoundVariable || simple.LoginGuess) {
			for _, dir := range moved {
				followed[path.Clean(dir)]++
			}
		}
		previous = simple.Text
	}
	if standing {
		dirs = keep(dirs, stoodIn)
	}
	command := input.Command
	if command == "" || len(command) > agentHookConfigMaxPlacedBytes {
		return plan
	}
	plan.rest = true
	// byPosition reads each call of the script below only in the folders
	// known at its own place. The hook-config guard (statementBudget false)
	// reads by position only a call the laptop guard places statement by
	// statement (agentHookConfigPlacedCommands: a cd and a TopLevelStatements
	// split). The laptop guard reads any other call whole, each write operand
	// in every folder the call's cds name, a later static cd's included: after
	// cd -, popd, cd "$D", a called function, a group or a loop that cds,
	// echo x > settings.json; cd ~/.claude && ls alerts
	// tamper.agent_hook_config_write on the laptop and both rels, and the
	// actor allowed it once every call was read by position (substrate-1
	// GAP-0988).
	if statements, ok := hookpaths.TopLevelStatements(command, input.CWD, input.ActiveHome); ok {
		plan.byPosition = len(statements) != 0 && hookpaths.ChangesDirectory(command)
		for _, statement := range statements {
			if path.IsAbs(statement.Dir) {
				plan.top = append(plan.top, guestPending{statement.Command, statement.Dir, false, 0})
			}
		}
	}
	// Every call of the script, a function body's included: the split stops
	// at a construct it cannot read (f() { cd .cache; }; f; $CMD gives one
	// parse failure), while a static cd anywhere in the text is still a
	// directory the laptop's readers keep. Each call is read only in the
	// folders known at its own place in the text (guestScriptCall.at): a
	// folder a static cd reaches (guestCDJoin) is known from that cd on,
	// so a folder only a later cd reaches is not one an earlier call runs in.
	// Read in every folder of the call, echo m > config.yaml; cd
	// ~/.defenseclaw && ls gave the reading echo m > config.yaml in
	// ~/.defenseclaw, and the strict actor blocked with
	// tamper.detector_state_write where the laptop and rel allow
	// (substrate-1 GAP-0883); a call the split read was skipped, but only
	// where its text was the split's, so after pushd src; popd, cd -, cd
	// "$D", a function, a group or a loop (each statement ending in ;) the
	// block stayed (substrate-1 GAP-0947). The guest's folder, a folder the
	// split reached through a followed value (followed) or that no static cd
	// of the text names are known from the start, as before; after a
	// statement that may set CDPATH, a folder a later relative cd may reach
	// through it is known from that cd (guestKnownFolders). The hook-config guard reads a call
	// the laptop guard does not place in every folder (byPosition,
	// substrate-1 GAP-0988). A call the simples pass read
	// (splitRead) is not read again: it was read in the folders known at its
	// own place. Its cd targets are still kept.
	scriptCalls, cdpath := guestScriptCalls(command, input.ActiveHome)
	var known map[string]int
	targets, known = guestKnownFolders(scriptCalls, dirs, targets, followed, input.CWD, input.ActiveHome, cdpath, keepClean, cdMemo)
	for _, call := range scriptCalls {
		if !splitRead[call.text] {
			plan.calls = append(plan.calls, call)
		}
	}
	plan.dirs, plan.targets, plan.known = dirs, targets, known
	return plan
}

// guestAuthoritativePlacements places the simple commands of a call the
// analysis read in full (guestPlacementPlan).
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
// (guestPlacementPlan); statementBudget cuts a pass of a call over the
// laptop's statement budget at maxSandboxGuestPlacedChildren statements and
// reads each script call only in the folders known at its own place
// (byPosition).
func (plan *guestPlacementPlan) placements(statementBudget bool) (placements []guestPlacement, cut bool) {
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
	// Each folder's first place is read once, not for every call: an 8 KB
	// call looked up 128 long folder keys for each of its 1,100 calls
	// (rel-1-0-10:GAP-2249). A folder missing from known is read as 0, as
	// the map gives it.
	firstPlaces := func(dirs []string) []int {
		places := make([]int, len(dirs))
		if byPosition {
			for at, dir := range dirs {
				places[at] = plan.known[dir]
			}
		}
		return places
	}
	dirsKnown, targetsKnown := firstPlaces(plan.dirs), firstPlaces(plan.targets)
	// offered keeps, for each call text, the latest place a call of it was
	// offered from. A text offered again in a folder it was offered in
	// before changes nothing: a listed reading keeps its candidate mark
	// (candidate && the same mark), and one not listed was dropped from the
	// full list, as it would be again (a full list only loses plain
	// readings, so a first one dropped there finds no plain slot later);
	// its arrival is not counted, which keeps the order of the later
	// readings. So a repeated text is offered only in the folders known
	// first between its last call and this one: an 8 KB call of 550 $C
	// statements offered each in all 128 folders (rel-1-0-10:GAP-2249).
	offered := map[string]int{}
	for _, call := range plan.calls {
		last, again := offered[call.text]
		if !again || call.at > last {
			offered[call.text] = call.at
		}
		if again && (!byPosition || call.at <= last) {
			continue
		}
		fresh := func(place int) bool {
			if !byPosition {
				return true
			}
			return place <= call.at && (!again || place > last)
		}
		for at, dir := range plan.dirs {
			if fresh(dirsKnown[at]) {
				callReadings = guestCollect(callReadings, callsListed, &callsPlain, &callsDropped, &arrivals, guestPending{call.text, dir, false, 0})
			}
		}
		// Once the pass is cut and full, a plain candidate reading changes
		// nothing: one listed stays a candidate, and one not listed is
		// dropped (guestCollect). Its arrival is not counted, which keeps
		// the order of the later readings. An 8 KB cd chain offered each of
		// its 1,100 calls in 64 targets to the full list (rel-1-0-10:GAP-2249).
		if callsDropped && len(callReadings) >= maxSandboxGuestPlacements && !guestReadingFirst(call.text) {
			continue
		}
		for at, dir := range plan.targets {
			if fresh(targetsKnown[at]) {
				callReadings = guestCollect(callReadings, callsListed, &callsPlain, &callsDropped, &arrivals, guestPending{call.text, dir, true, 0})
			}
		}
	}
	callsCut := !placeAll(&pass{statements: map[string]bool{}}, callReadings) || callsDropped
	return placements, simplesCut || topCut || callsCut
}

// guestCollect is collect of the guest placement walk (newGuestPlacementPlan,
// guestPlacementPlan.placements); arrivals counts the readings of the pass.
func guestCollect(list []guestPending, listed map[guestKey]int, plain *[]int, dropped *bool, arrivals *int, reading guestPending) []guestPending {
	at := guestKey{reading.text, reading.cwd}
	if index, ok := listed[at]; ok {
		list[index].candidate = list[index].candidate && reading.candidate
		return list
	}
	first := guestReadingFirst(reading.text)
	reading.seq = *arrivals
	(*arrivals)++
	if len(list) >= maxSandboxGuestPlacements {
		*dropped = true
		if !first || len(*plain) == 0 {
			return list
		}
		last := (*plain)[len(*plain)-1]
		*plain = (*plain)[:len(*plain)-1]
		delete(listed, guestKey{list[last].text, list[last].cwd})
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

// guestReadingMemo keeps, for one hook evaluation, the simple-command split
// of each guest-placed input and its guest placement plan: the
// placed-children reading, the split-gap reading and the sandbox hook-config
// guard each made them from the start for the same input, up to four
// SimpleCommands passes a hook (substrate-1 GAP-0923, GAP-1028). An entry
// serves only an input and facts equal to the ones it was made for (a split
// or a plan whatever the input's walk wait, guestLexicalKey); any other is
// read afresh. A copy of the request shares it; a nil memo keeps
// nothing.
type guestReadingMemo struct {
	mu     sync.Mutex
	splits []guestSplitEntry
	plans  []guestPlanEntry
	// readings are the guest readings of the hook (analyze), and children
	// their placed children (sandboxGuestPlacedChildren).
	readings []guestAnalysisEntry
	children []guestChildrenEntry
	// placed keeps the placed readings of the hook's walks
	// (placedReader).
	placed []*guestPlacedEntry
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

// guestPlacedEntry keeps the readings of the placements of every guest input
// equal to base but for its command and folder (placedReader), by text and
// folder.
type guestPlacedEntry struct {
	base     actionfacts.Input
	readings map[guestPlacedKey]actionfacts.Facts
}

type guestPlacedKey struct{ text, cwd string }

// guestReadingMemoEntries bounds each list of a guestReadingMemo: a hook
// reads a few guest inputs (the call, its twins), and an older entry gives
// way to a newer one.
const guestReadingMemoEntries = 4

// simpleCommands is actionfacts.SimpleCommands(input, facts).
func (memo *guestReadingMemo) simpleCommands(input actionfacts.Input, facts actionfacts.Facts) []actionfacts.SimpleCommand {
	if memo == nil {
		return actionfacts.SimpleCommands(input, facts)
	}
	key := guestLexicalKey(input)
	memo.mu.Lock()
	for _, entry := range memo.splits {
		if reflect.DeepEqual(entry.input, key) && reflect.DeepEqual(entry.facts, facts) {
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
	memo.splits = append(memo.splits, guestSplitEntry{input: key, facts: facts, simples: slices.Clone(simples)})
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
	if facts, ok := memo.placedReading(input); ok {
		memo.mu.Unlock()
		return clippedFacts(facts)
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
// keeps: the call, its twins, the statements the dispatch reads alone and
// the last placed children of their walks (placedReader keeps all of them
// by text and folder, GAP-2215, rel-1-0-10:GAP-2226).
const guestReadingMemoReadings = 16

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

// placedReader reads a placement of input, its command text in its folder
// (sandboxGuestPlacedChildrenWalk), as actionfacts.Analyze reads input with
// that command and folder and no tool arguments. A hook walks the call and
// its twins (an Args-only call and its command form, a here-string and its
// pipe twin), whose placements are mostly the same texts in the same
// folders: each reading is kept for the hook by text and folder, for every
// input equal to this one but for its command, folder and arguments, so a
// later walk reads only what an earlier one did not. The reading depends on
// the input alone, as analyze's does. A nil memo keeps nothing.
func (memo *guestReadingMemo) placedReader(input actionfacts.Input) func(guestPlacement) actionfacts.Facts {
	childOf := func(placement guestPlacement) actionfacts.Input {
		child := input
		child.Command, child.CWD = placement.text, placement.cwd
		child.Args, child.Argv = nil, nil
		return child
	}
	if memo == nil {
		return func(placement guestPlacement) actionfacts.Facts { return actionfacts.Analyze(childOf(placement)) }
	}
	base := childOf(guestPlacement{})
	memo.mu.Lock()
	var entry *guestPlacedEntry
	for _, kept := range memo.placed {
		if reflect.DeepEqual(kept.base, base) {
			entry = kept
			break
		}
	}
	if entry == nil {
		entry = &guestPlacedEntry{base: base, readings: map[guestPlacedKey]actionfacts.Facts{}}
		if len(memo.placed) == guestReadingMemoEntries {
			memo.placed = slices.Delete(memo.placed, 0, 1)
		}
		memo.placed = append(memo.placed, entry)
	}
	memo.mu.Unlock()
	return func(placement guestPlacement) actionfacts.Facts {
		key := guestPlacedKey{placement.text, placement.cwd}
		memo.mu.Lock()
		facts, ok := entry.readings[key]
		memo.mu.Unlock()
		if ok {
			return clippedFacts(facts)
		}
		// A placed reading is kept here only: through analyze, each of a
		// walk's thousands of readings was compared with its sixteen
		// readings first, and pushed out the call's own (rel-1-0-10:GAP-2226).
		// analyze still finds it (placedReading).
		facts = actionfacts.Analyze(childOf(placement))
		memo.mu.Lock()
		entry.readings[key] = facts
		memo.mu.Unlock()
		return clippedFacts(facts)
	}
}

// placedReading is the placed reading kept for input (placedReader), when
// input is a placement of one of the inputs a walk read: no tool arguments,
// and equal to that input but for its command and folder. The caller holds
// memo.mu.
func (memo *guestReadingMemo) placedReading(input actionfacts.Input) (actionfacts.Facts, bool) {
	if len(memo.placed) == 0 || input.Args != nil || input.Argv != nil {
		return actionfacts.Facts{}, false
	}
	key := guestPlacedKey{input.Command, input.CWD}
	base := input
	base.Command, base.CWD = "", ""
	for _, entry := range memo.placed {
		if facts, ok := entry.readings[key]; ok && reflect.DeepEqual(entry.base, base) {
			return facts, true
		}
	}
	return actionfacts.Facts{}, false
}

// guestCandidateMayReadKey reports a candidate reading's text that may read
// an SSH private key's content in some folder, the one thing a reading in a
// candidate folder counts for (sandboxGuestPlacedChildren): a text with a
// quote, an escape, an expansion or a pattern, or one that names a program
// of sshPrivateKeyContentReaders. The analysis takes a command's program
// from a word of its text (its base name, or less an .exe or .cmd suffix),
// so a text of plain words that names none of them has no reader command in
// any folder, and its readings there prove nothing (rel-1-0-10:GAP-2226).
// That rests on how actionfacts names a program: the lowercased base name of
// a literal word, with ASCII lowering only and no Unicode folding, so a name
// the text spells in any case, path or suffix still contains the reader's
// name once lowered, and a lookalike letter names no reader at all
// (TestGAP2226CandidateFilterProgramNames). A change to that naming must
// change this filter with it.
func guestCandidateMayReadKey(text string) bool {
	if strings.ContainsAny(text, "'\"\\$`^%!*?[{") {
		return true
	}
	lower := strings.ToLower(text)
	return slices.ContainsFunc(sshPrivateKeyContentReaders, func(program string) bool { return strings.Contains(lower, program) })
}

// guestLexicalKey is input as the memo's splits and plans compare it: without
// the hook call's wait for walk slots (Input.CredentialWalkBudget). A split
// and a plan are lexical readings of the call (command texts, folders and
// flags) and neither reads the wait, which only the facts' credential walk
// draws on. The rule dispatch carries the hook's wait on its input
// (dispatchTrustedActionOnce) and the lanes judge the call as the hook sent
// it, with none, so since the wait was put on the input (substrate-1
// GAP-1083) the sandbox hook-config guard made again the plan the placed
// children had just made for the same call, its SimpleCommands and Analyze
// passes included: a long copy-mode call took about 10% longer
// (rel-1-0-10:GAP-2239). Every other field still has to match, and the
// analysis cache (analyze) keeps the wait in its key: its facts carry it.
func guestLexicalKey(input actionfacts.Input) actionfacts.Input {
	input.CredentialWalkBudget = nil
	return input
}

// plan is newGuestPlacementPlan(input, facts) over the memo's splits.
func (memo *guestReadingMemo) plan(input actionfacts.Input, facts actionfacts.Facts) *guestPlacementPlan {
	if memo == nil {
		return newGuestPlacementPlan(input, facts, nil, nil)
	}
	key := guestLexicalKey(input)
	memo.mu.Lock()
	for _, entry := range memo.plans {
		if reflect.DeepEqual(entry.input, key) && reflect.DeepEqual(entry.facts, facts) {
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
	memo.plans = append(memo.plans, guestPlanEntry{input: key, facts: facts, plan: plan})
	memo.mu.Unlock()
	return plan
}

// guestReadingFirst reports a command text whose reading in another folder
// may reach a different protected path: a word with a dot or a slash
// (../.ssh/id_ed25519, .bashrc, a/b), a ~, an expansion or a pattern, or a
// bare name the laptop protects in a folder it cannot name (authorized_keys,
// a private key id_*, the account and credential files:
// unresolvedFolderWriteNames, unresolvedFolderReadNames; substrate-1
// GAP-0625). A text of plain words (touch f1, ls, cd sub) is read after
// them. The scan allocates nothing.
func guestReadingFirst(text string) bool {
	if strings.ContainsAny(text, "./~$`*?[{\\") {
		return true
	}
	for start := 0; start < len(text); {
		end := start
		for end < len(text) && guestNameByte(text[end]) {
			end++
		}
		if end == start {
			start++
			continue
		}
		word := text[start:end]
		if strings.HasPrefix(word, "id_") || slices.Contains(unresolvedFolderWriteNames, word) ||
			slices.Contains(unresolvedFolderReadNames, word) {
			return true
		}
		start = end
	}
	return false
}

// guestDirFirst reports a folder kept before plain ones past the guest
// placement's folder bound: the home, or a folder whose name starts with a
// dot (~/.ssh, ~/.aws, ~/.defenseclaw, a project's .git or .claude).
func guestDirFirst(dir, home string) bool {
	// Cleaning never makes a path longer, so a folder longer than home is
	// not the home and home is not cleaned for it: the walks ask this of
	// each folder they keep or sort, thousands a call (rel-1-0-10:GAP-2249).
	if len(dir) <= len(home) && dir == path.Clean(home) {
		return true
	}
	return strings.HasPrefix(path.Base(dir), ".")
}

// guestPlainFolder reports a folder in which a plain reading (one
// guestReadingFirst does not read first: touch f17, ls, rm -f out) names no
// file the laptop protects by its folder, so the guest placement keeps the
// reading there a candidate even where the call's own shell may stand in
// the folder (sandboxGuestPlacedChildrenWalk): a folder strictly below the
// home each of whose names below the home is a plain name (letters, digits,
// _ and -), except that the first may be .cache, the cache folder, outside
// its huggingface folder (the token file the credentials table keeps there,
// .cache/huggingface/token). Never the home, a hidden folder or one below
// it (~/.ssh, ~/.aws, ~/.config, a project's .git or .claude), ~/Library,
// ~/AppData or ~/bin (the macOS and Windows agent and startup folders and
// the user's own commands), a folder outside the home (/etc, /tmp) or one
// the credentials table keeps whole (appdata/roaming/gcloud/legacy_credentials).
// Library and AppData are matched in any case, as macOS and Windows, whose
// file systems fold case, spell them in any case; bin is matched as written:
// it is the commands folder a profile puts on the PATH of the Linux guest,
// whose names do not fold, so ~/Bin there is a plain folder.
// Promoting each plain reading of fan-out shapes (cd .cache; bash <<< true;
// $CMD; 7 cds; touch f0 ... f1000) made every semantic owner judge 8,125
// placed views a call where the 1.0.10 line judged 133, and the copy-mode
// actor took twice its time, with no other verdict (rel-1-0-10:GAP-2249).
// dir is clean.
func guestPlainFolder(dir, home string) bool {
	home = path.Clean(home)
	if !path.IsAbs(home) || home == "/" {
		return false
	}
	rest, ok := strings.CutPrefix(dir, home+"/")
	if !ok || rest == "" {
		return false
	}
	for first := true; rest != ""; first = false {
		name, after, _ := strings.Cut(rest, "/")
		rest = after
		if first && name == ".cache" {
			if next, _, _ := strings.Cut(after, "/"); strings.EqualFold(next, "huggingface") {
				return false
			}
			continue
		}
		if first && (strings.EqualFold(name, "Library") || strings.EqualFold(name, "AppData") || name == "bin") {
			return false
		}
		if name == "" || name[0] == '-' {
			return false
		}
		for at := 0; at < len(name); at++ {
			if !guestNameByte(name[at]) {
				return false
			}
		}
	}
	_, kept := actionfacts.MatchCredentialFileShape(dir + "/f")
	return !kept
}

// guestNameByte reports a byte of a bare file name: a letter, a digit, _
// or -.
func guestNameByte(c byte) bool {
	return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// withSandboxGuestFolderTier gives a sandbox call the unknown tier the
// laptop gives the same call in its own folder (withUnresolvedFolderTier,
// rel-1-0-10:GAP-0871): an operand that may name a protected file in a
// folder the call does not give, after a function that cds or a $CMD. A
// copy-mode call names no folder, so the tier is read on the call placed in
// the guest's working directory (sandboxGuestPlacedInput), as the laptop
// reads it in its own. It is decided on that whole-call reading alone: the
// commands the guest placement reads one by one (guestPlacementPlan) are
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
// only adds findings. judged is what the host-placed reading of the call
// already judged (withSplitGapEffects): a twin it judged that names no
// folder is not judged again here, so the call spends its budget on it once,
// as the laptop does (substrate-1 GAP-0725).
func withSandboxGuestSplitGapEffects(ctx context.Context, request trustedActionRequest, generation *compiledRulePackCategories,
	budget *trustedActionBudget, facts actionfacts.Facts, wholeCommand string, findings []RuleFinding, judged *splitGapJudged) []RuleFinding {
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
	findings, _ = withSplitGapEffects(ctx, placed, generation, budget, guestFacts, wholeCommand, findings, judged)
	return findings
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
	return guestNodeRunsUnreadCommand(file, home)
}

// guestNodeRunsUnreadCommand is guestCallRunsUnreadCommand over a parsed
// node.
func guestNodeRunsUnreadCommand(root syntax.Node, home string) bool {
	found := false
	syntax.Walk(root, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && !found {
			found = guestCallUnread(call, home)
		}
		return !found
	})
	return found
}

// guestCallUnread reports one simple command the statement split cannot read
// (guestCallRunsUnreadCommand), not counting the commands nested in its
// words.
func guestCallUnread(call *syntax.CallExpr, home string) bool {
	for index, word := range call.Args {
		program, static := hookpaths.StaticWord(word, home)
		if !static || cmdRedefiningCommands[program] || program == "mapfile" || program == "readarray" {
			return true
		}
		// builtin, command and exec run the word after their options.
		if (program != "builtin" && program != "command" && program != "exec") || index == len(call.Args)-1 {
			return false
		}
		if next, known := hookpaths.StaticWord(call.Args[index+1], home); known && strings.HasPrefix(next, "-") {
			return true // an option word: read it as unread rather than parse every wrapper option
		}
	}
	return false
}

// guestShellReading is one statement of a call, by its source text, and a
// folder the call's own shell may stand in when it runs (guestOwnShellFolders).
type guestShellReading struct{ text, dir string }

// guestShellReadings are the readings of guestOwnShellWalk: for each simple
// command text, the folder lists the walk read it in. A list is one the walk
// made and never changes, so a text keeps its lists, not an entry per
// folder: a call of 900 cds after $CMD made 230,000 entries a walk, a third
// of a copy-mode actor's time on it (rel-1-0-10:GAP-2226). A list holds its
// folders as ids of the walk's folder tree (guestFolderTree), not as
// strings: after $CMD an 8 KB cd chain reads 1,000 lists of 256 folders
// whose names grow with the chain, 260,000 strings of 81 MB, and the kept
// walk (guestWalks) held them, so every later call ran on a heap five times
// the 1.0.10 line's and faulted in fresh pages a run in two at random
// (rel-1-0-10:GAP-2249). A nil *guestShellReadings has no reading. It is
// only read once made.
type guestShellReadings struct {
	texts   map[string][]int
	lists   [][]int32
	folders *guestFolderTree
}

// has reports the reading of text in folder dir.
func (readings *guestShellReadings) has(text, dir string) bool {
	if readings == nil {
		return false
	}
	lists := readings.texts[text]
	if len(lists) == 0 {
		return false
	}
	id, ok := readings.folders.lookup(dir)
	if !ok {
		return false
	}
	for _, at := range lists {
		if slices.Contains(readings.lists[at], id) {
			return true
		}
	}
	return false
}

// add notes text read in each folder of in, a list the walk never changes.
func (readings *guestShellReadings) add(text string, in []int32) {
	at := len(readings.lists) - 1
	if at < 0 || len(readings.lists[at]) != len(in) || &readings.lists[at][0] != &in[0] {
		readings.lists = append(readings.lists, in)
		at++
	}
	if kept := readings.texts[text]; len(kept) == 0 || kept[len(kept)-1] != at {
		readings.texts[text] = append(kept, at)
	}
}

// guestFolderTree is the folders of one own-shell walk, each clean and
// absolute, as ids: 0 is /, and any other folder is a name (no slash, not .
// or ..) in its parent folder, made once (child), so two folders are two
// ids and a folder's string is its parents' names joined by slashes (path).
// A folder is found by a 64-bit FNV-1a hash of its string, checked against
// the tree (child by its parent and name, lookup name by name), so a hash
// that two strings share never answers for the other. Once the walk ends,
// only lookup and path read it.
type guestFolderTree struct {
	nodes  []guestFolderNode
	hashes []uint64 // each folder's hash, the walk's while it makes folders
	byHash map[uint64]int32
	more   map[uint64][]int32 // the folders whose hash an earlier one has
}

// guestFolderNode is a folder of a guestFolderTree: its name in its parent.
type guestFolderNode struct {
	parent int32
	name   string
}

// The 64-bit FNV-1a offset basis and prime.
const (
	guestFolderHashOffset uint64 = 14695981039346656037
	guestFolderHashPrime  uint64 = 1099511628211
)

func newGuestFolderTree() *guestFolderTree {
	root := guestFolderHashOffset
	root = (root ^ '/') * guestFolderHashPrime
	return &guestFolderTree{
		nodes:  []guestFolderNode{{parent: -1}},
		hashes: []uint64{root},
		byHash: map[uint64]int32{root: 0},
	}
}

// child is the folder name in folder parent: the parent's string, a slash
// unless the parent is /, and name. A folder of the same parent and name has
// the same string and so the same hash, so it is found under that hash. A
// folder it makes holds a copy of name when keep is set.
func (tree *guestFolderTree) child(parent int32, name string, keep bool) int32 {
	hash := tree.hashes[parent]
	if parent != 0 {
		hash = (hash ^ '/') * guestFolderHashPrime
	}
	for at := 0; at < len(name); at++ {
		hash = (hash ^ uint64(name[at])) * guestFolderHashPrime
	}
	first, taken := tree.byHash[hash]
	if taken {
		if node := tree.nodes[first]; node.parent == parent && node.name == name {
			return first
		}
		for _, id := range tree.more[hash] {
			if node := tree.nodes[id]; node.parent == parent && node.name == name {
				return id
			}
		}
	}
	if keep {
		name = strings.Clone(name)
	}
	id := int32(len(tree.nodes))
	tree.nodes = append(tree.nodes, guestFolderNode{parent: parent, name: name})
	tree.hashes = append(tree.hashes, hash)
	if !taken {
		tree.byHash[hash] = id
	} else {
		if tree.more == nil {
			tree.more = map[uint64][]int32{}
		}
		tree.more[hash] = append(tree.more[hash], id)
	}
	return id
}

// folder is the id of dir, a clean absolute folder. A name it makes is
// copied, so the tree never holds dir.
func (tree *guestFolderTree) folder(dir string) int32 {
	id := int32(0)
	for rest := dir[1:]; rest != ""; {
		name, after, _ := strings.Cut(rest, "/")
		id = tree.child(id, name, true)
		rest = after
	}
	return id
}

// path is the string of folder id.
func (tree *guestFolderTree) path(id int32) string {
	if id == 0 {
		return "/"
	}
	size := 0
	for at := id; at != 0; at = tree.nodes[at].parent {
		size += 1 + len(tree.nodes[at].name)
	}
	out := make([]byte, size)
	for at := id; at != 0; at = tree.nodes[at].parent {
		name := tree.nodes[at].name
		size -= len(name)
		copy(out[size:], name)
		size--
		out[size] = '/'
	}
	return string(out)
}

// is reports folder id's string is dir.
func (tree *guestFolderTree) is(id int32, dir string) bool {
	if id == 0 {
		return dir == "/"
	}
	for ; id != 0; id = tree.nodes[id].parent {
		rest, ok := strings.CutSuffix(dir, tree.nodes[id].name)
		if !ok {
			return false
		}
		if dir, ok = strings.CutSuffix(rest, "/"); !ok {
			return false
		}
	}
	return dir == ""
}

// lookup is the id of folder dir, false when the tree has no such folder.
func (tree *guestFolderTree) lookup(dir string) (int32, bool) {
	hash := guestFolderHashOffset
	for at := 0; at < len(dir); at++ {
		hash = (hash ^ uint64(dir[at])) * guestFolderHashPrime
	}
	if id, ok := tree.byHash[hash]; ok && tree.is(id, dir) {
		return id, true
	}
	for _, id := range tree.more[hash] {
		if tree.is(id, dir) {
			return id, true
		}
	}
	return 0, false
}

// cdTargets is, as ids, the folders a cd or pushd command text moves to from
// each of bases: a static operand joined to each base, an absolute or ~
// operand as it is, the home for a bare cd (guestCDJoin). A dynamic operand,
// cd - and popd add none (they return to a folder already a candidate, or to
// one no static word names). A plain name (cd d5) is the child of each base
// in the tree, the base's string, a slash and the name; any other operand is
// joined to the bases' strings, and every target is clean and absolute.
func (tree *guestFolderTree) cdTargets(text string, bases []int32, home string) []int32 {
	operand, ok := guestCDOperand(text, home)
	if !ok {
		return nil
	}
	if guestCDPlainOperand(operand) {
		if len(bases) == 0 {
			return nil
		}
		targets := make([]int32, len(bases))
		for at, base := range bases {
			targets[at] = tree.child(base, operand, false)
		}
		return targets
	}
	var names []string
	if guestCDJoinReadsBases(operand, home) {
		names = make([]string, len(bases))
		for at, base := range bases {
			names[at] = tree.path(base)
		}
	}
	joined := guestCDJoin(operand, names, home)
	if len(joined) == 0 {
		return nil
	}
	targets := make([]int32, len(joined))
	for at, dir := range joined {
		targets[at] = tree.folder(dir)
	}
	return targets
}

// done drops what only the walk that makes folders reads.
func (tree *guestFolderTree) done() {
	tree.hashes = nil
}

// guestOwnShellFolders returns, lexically, each simple command of the call
// that runs after a command the statement split cannot read ($CMD, eval,
// source; guestCallRunsUnreadCommand), with each folder the call's own shell
// may stand in when that command runs: the folders a static cd or pushd
// moves it to from cwd, when that cd runs in the shell itself, at top level
// or on the path an && runs. The laptop keeps such a folder as one the later
// commands run in, and so does sandboxGuestPlacedChildren (cd .cache; bash
// <<< true; $CMD; cd s0; ...; cd ../.ssh; echo k >> authorized_keys blocks,
// substrate-1 GAP-0628). Each command is keyed with the folders known at its
// own place, never with those of a later cd: a folder set for the whole call
// promoted echo m > config.yaml in ~/.defenseclaw for (cd ~/.defenseclaw ||
// cd /tmp); $CMD; echo m > config.yaml; cd ~/.defenseclaw && ls, a block
// where the laptop allows (substrate-1 GAP-0883). As in the laptop's
// statement reader (hookpaths.TopLevelStatements) a cd may fail: the shell
// then stays where it was, so a statement after ; runs in both folders and
// one an && runs after the cd only in the new one; after cd X || exit (or
// return) the shell goes on only in X, as on the laptop (substrate-1
// GAP-0884). A cd anywhere else never moves the shell the later commands run
// in: a ( ... ) subshell, a function that is never called, an & list ((cd
// ~/.defenseclaw || cd /tmp); $CMD; echo m > config.yaml stays the laptop's
// allow). A directory change the walk cannot follow (cd -, cd "$D", popd,
// CDPATH, a called function that cds, another alternative of ||, one in a
// group, loop or pipeline) leaves the folder unknown: no folder after it is
// kept until a static cd names one. At most maxSandboxGuestOwnShellFolders
// folders are followed at once, those that may hold protected files first
// (guestDirFirst). The walk reads each statement once, so its cost grows
// with the statements times the folders followed (substrate-1 GAP-0885).
// nil when the script does not parse or runs no unread command.
func guestOwnShellFolders(command, cwd, home string) *guestShellReadings {
	readings, _ := guestOwnShellWalk(command, cwd, home)
	return readings
}

// guestOwnShellWalk is guestOwnShellFolders with, for each simple command
// text, whether the walk placed it at every place it comes: true when each
// is a statement of the call shell, read where the walk knew the folders the
// shell may stand in (at top level, or on the path an && or a cd X || exit
// runs); false when one sits inside another command (a subshell, a group,
// an if, a loop, a function body, a pipeline, an || list) or comes after a
// directory change the walk cannot follow. A text missing from it was not
// read by the walk. The sandbox hook-config guard reads a candidate folder
// of a placed text only where the walk says the shell may stand in it, and
// keeps every candidate folder of a text the walk did not place
// (agent_hook_config_guard.go, substrate-1 GAP-0888, B43).
func guestOwnShellWalk(command, cwd, home string) (*guestShellReadings, map[string]bool) {
	if len(command) > agentHookConfigMaxPlacedBytes {
		return guestOwnShellWalkText(command, cwd, home)
	}
	guestWalks.Lock()
	for _, walk := range guestWalks.last {
		if walk.command == command && walk.cwd == cwd && walk.home == home {
			guestWalks.Unlock()
			return walk.readings, walk.placed
		}
	}
	guestWalks.Unlock()
	readings, placed := guestOwnShellWalkText(command, cwd, home)
	guestWalks.Lock()
	guestWalks.last[guestWalks.next] = guestWalk{command: command, cwd: cwd, home: home, readings: readings, placed: placed}
	guestWalks.next = (guestWalks.next + 1) % len(guestWalks.last)
	guestWalks.Unlock()
	return readings, placed
}

// guestWalks holds the last walks of guestOwnShellWalk. A copy-mode call is
// walked by its placed children (sandboxGuestPlacedChildren) and again by
// the sandbox hook-config guard, with the same script, folder and home: the
// second walk made a long call up to 87% slower than before the guard read
// the walk (substrate-1 GAP-0956). The walk is lexical, so a call walks
// once. Its maps are only read.
var guestWalks struct {
	sync.Mutex
	last [4]guestWalk
	next int
}

// guestWalk is one walk kept in guestWalks.
type guestWalk struct {
	command, cwd, home string
	readings           *guestShellReadings
	placed             map[string]bool
}

// guestOwnShellWalkText walks the script (guestOwnShellWalk).
func guestOwnShellWalkText(command, cwd, home string) (*guestShellReadings, map[string]bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil || !path.IsAbs(cwd) {
		return nil, nil
	}
	cdpath := strings.Contains(command, "CDPATH")
	// Functions whose body changes the folder; a call of one leaves it unknown.
	moving := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil && guestNodeChangesDirectory(decl.Body, home, nil) {
			moving[decl.Name.Value] = true
		}
		return true
	})
	text := func(node syntax.Node) string {
		start, end := int(node.Pos().Offset()), int(node.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			return ""
		}
		return command[start:end]
	}
	// The walk's folders are ids of one tree (guestFolderTree), each clean
	// and absolute: the call's folder cleaned, then only the targets
	// cdTargets gives. homeID is the tree's folder of the cleaned home, -1
	// when that is not absolute, so first is guestDirFirst of a folder: the
	// home, or a name with a leading dot.
	folders := newGuestFolderTree()
	homeID := int32(-1)
	if clean := path.Clean(home); path.IsAbs(clean) {
		homeID = folders.folder(clean)
	}
	dirFirst := func(id int32) bool {
		return id == homeID || id != 0 && strings.HasPrefix(folders.nodes[id].name, ".")
	}
	// seen is join's, a mark per folder that each join moves on: a fresh map
	// for each statement was most of the walk's allocations on a long call
	// (rel-1-0-10:GAP-2226).
	var seen []uint32
	mark := uint32(0)
	join := func(sets ...[]int32) []int32 {
		var out []int32
		if mark++; mark == 0 {
			clear(seen)
			mark = 1
		}
		if size := len(folders.nodes); size > len(seen) {
			seen = slices.Grow(seen, size-len(seen))[:size]
		}
		for _, set := range sets {
			for _, id := range set {
				if seen[id] != mark {
					seen[id] = mark
					out = append(out, id)
				}
			}
		}
		if len(out) > maxSandboxGuestOwnShellFolders {
			// The folders that may hold protected files first (guestDirFirst),
			// each part in its own order, up to the bound: the stable sort
			// that did it asked guestDirFirst n log n times a join
			// (rel-1-0-10:GAP-2249).
			kept := make([]int32, 0, maxSandboxGuestOwnShellFolders)
			for _, first := range [2]bool{true, false} {
				for _, id := range out {
					if len(kept) == maxSandboxGuestOwnShellFolders {
						break
					}
					if dirFirst(id) == first {
						kept = append(kept, id)
					}
				}
			}
			out = kept
		}
		return out
	}
	unread := false
	var readings *guestShellReadings
	placed := map[string]bool{}
	// read keys every simple command of node (one statement, run from the
	// folders in) with each of those folders, once a command before it may
	// have moved the shell, and notes in placed whether the walk placed it.
	read := func(node syntax.Node, in []int32) {
		syntax.Walk(node, func(inner syntax.Node) bool {
			stmt, ok := inner.(*syntax.Stmt)
			if !ok {
				return true
			}
			if call, isCall := stmt.Cmd.(*syntax.CallExpr); !isCall || len(call.Args) == 0 {
				return true
			}
			span := text(stmt)
			if span == "" {
				return true
			}
			if inner != node || len(in) == 0 {
				placed[span] = false
			} else if _, seen := placed[span]; !seen {
				placed[span] = true
			}
			if unread && len(in) != 0 {
				if readings == nil {
					readings = &guestShellReadings{texts: map[string][]int{}, folders: folders}
				}
				readings.add(span, in)
			}
			return true
		})
	}
	// step runs one statement from the folders in: the folders the shell
	// stands in where it succeeded and where it failed.
	var step func(*syntax.Stmt, []int32) (succeeded, failed []int32)
	step = func(stmt *syntax.Stmt, in []int32) (succeeded, failed []int32) {
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && !stmt.Background && len(stmt.Redirs) == 0 {
			switch {
			case pair.Op == syntax.AndStmt:
				leftOK, leftFailed := step(pair.X, in)
				rightOK, rightFailed := step(pair.Y, leftOK)
				return rightOK, join(leftFailed, rightFailed)
			case pair.Op == syntax.OrStmt && guestStmtLeaves(pair.Y, home):
				leftOK, _ := step(pair.X, in)
				return leftOK, nil
			}
		}
		read(stmt, in)
		defer func() { unread = unread || guestNodeRunsUnreadCommand(stmt, home) }()
		if stmt.Background {
			return in, in // an & list runs in a subshell
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				return in, in
			}
			program, static := hookpaths.StaticWord(cmd.Args[0], home)
			switch {
			case !static:
			case moving[program] || program == "popd":
				return nil, nil
			case program == "cd" || program == "pushd":
				if cdpath || len(cmd.Assigns) != 0 {
					return nil, nil
				}
				moved := folders.cdTargets(text(stmt), in, home)
				if len(moved) == 0 {
					return nil, nil
				}
				return join(moved), in
			}
			return in, in
		case *syntax.Subshell, *syntax.FuncDecl:
			return in, in
		}
		if guestNodeChangesDirectory(stmt.Cmd, home, moving) {
			return nil, nil
		}
		return in, in
	}
	current := []int32{folders.folder(path.Clean(cwd))}
	for _, stmt := range file.Stmts {
		succeeded, failed := step(stmt, current)
		current = join(succeeded, failed)
	}
	folders.done()
	return readings, placed
}

// guestStmtLeaves reports, lexically, a statement that is a plain exit or
// return: the shell does not go on past it.
func guestStmtLeaves(stmt *syntax.Stmt, home string) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || len(call.Args) == 0 {
		return false
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	return static && (program == "exit" || program == "return")
}

// guestNodeChangesDirectory reports, lexically, a cd, pushd or popd, or a
// call of one of moving (functions that change the folder), anywhere in node
// outside a ( ... ) subshell.
func guestNodeChangesDirectory(node syntax.Node, home string, moving map[string]bool) bool {
	found := false
	syntax.Walk(node, func(inner syntax.Node) bool {
		if found {
			return false
		}
		switch inner := inner.(type) {
		case *syntax.Subshell:
			return false
		case *syntax.CallExpr:
			if len(inner.Args) != 0 {
				program, static := hookpaths.StaticWord(inner.Args[0], home)
				found = static && (program == "cd" || program == "pushd" || program == "popd" || moving[program])
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

// guestCDOperand returns, lexically, the static operand of a cd or pushd
// command text ("" for a bare cd), behind builtin or command too
// (guestCDWords); false for any other text, a dynamic operand and cd -.
func guestCDOperand(text, home string) (string, bool) {
	call, ok := guestCall(text)
	if !ok {
		return "", false
	}
	return guestCallCDOperand(call, home)
}

// guestCallCDOperand is guestCDOperand of a parsed call.
func guestCallCDOperand(call *syntax.CallExpr, home string) (string, bool) {
	words := guestCDWords(call.Args, home)
	if words == nil {
		return "", false
	}
	operand := ""
	for _, word := range words[1:] {
		value, static := hookpaths.StaticWord(word, home)
		if !static {
			return "", false
		}
		if value == "--" || operand == "" && strings.HasPrefix(value, "-") && value != "-" {
			continue
		}
		operand = value
		break
	}
	return operand, operand != "-"
}

// guestCDReading is what the lexical cd readers make of one command text:
// changes reports a cd, pushd or popd command; moves a cd or pushd with a
// static operand (guestCDOperand), "" for a bare cd.
type guestCDReading struct {
	changes, moves bool
	operand        string
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

// guestCDMemo reads each command text of one placement once
// (guestCDReading): an 8 KB call repeats a few texts hundreds of times ($C;
// f0() { :; }; $C; f1() { :; }; ...), and parsing each again for the
// simples pass and for every script call (guestKnownFolders) made some 6 MB
// a hook on such a call, 15-25 ms over rel with the collections it caused
// (substrate-1 GAP-1028). The readings are lexical: a text reads the same
// in one home every time.
type guestCDMemo struct {
	home  string
	texts map[string]guestCDReading
}

func newGuestCDMemo(home string) *guestCDMemo {
	return &guestCDMemo{home: home, texts: map[string]guestCDReading{}}
}

func (memo *guestCDMemo) reading(text string) guestCDReading {
	if guestOtherProgramText(text) {
		return guestCDReading{}
	}
	if reading, ok := memo.texts[text]; ok {
		return reading
	}
	var reading guestCDReading
	if call, ok := guestCall(text); ok {
		program, static := hookpaths.StaticWord(call.Args[0], memo.home)
		reading.changes = static && (program == "cd" || program == "pushd" || program == "popd")
		reading.operand, reading.moves = guestCallCDOperand(call, memo.home)
	}
	memo.texts[text] = reading
	return reading
}

// guestCDWords returns the words of a cd or pushd call from its program word
// on, past a builtin or command wrapper with no option: builtin cd
// ~/.defenseclaw moves the shell as cd does, and read as a command that may
// go anywhere it made every earlier write a strict block in ~/.defenseclaw
// where the laptop and both rels allow (substrate-1 GAP-0989). nil for any
// other call (a wrapper option, command -v cd).
func guestCDWords(args []*syntax.Word, home string) []*syntax.Word {
	program, static := hookpaths.StaticWord(args[0], home)
	if static && (program == "builtin" || program == "command") && len(args) > 1 {
		args = args[1:]
		program, static = hookpaths.StaticWord(args[0], home)
	}
	if !static || program != "cd" && program != "pushd" {
		return nil
	}
	return args
}

// guestCDPathLooksUp reports a cd or pushd operand Bash may look up in
// CDPATH: a relative one that does not start with . or .. (as
// hookpaths.pushdBypassesCDPath).
func guestCDPathLooksUp(operand string) bool {
	return operand != "" && operand != "~" && !strings.HasPrefix(operand, "~/") && !path.IsAbs(operand) &&
		operand != "." && operand != ".." && !strings.HasPrefix(operand, "./") && !strings.HasPrefix(operand, "../")
}

// guestCDPathMayReach reports a folder a cd to operand may reach through a
// CDPATH entry the text does not name: one that ends in the operand, or any
// folder for an operand that climbs out of its entry (a/.., ../x).
func guestCDPathMayReach(dir, operand string) bool {
	operand = path.Clean(operand)
	if operand == "." || operand == ".." || strings.HasPrefix(operand, "../") {
		return true
	}
	return strings.HasSuffix(dir, "/"+operand)
}

// guestNamesCDPath reports, lexically, a text that spells CDPATH once its
// quotes and backslashes are removed (export CD""PATH=$HOME). It allocates
// nothing.
func guestNamesCDPath(text string) bool {
	const name = "CDPATH"
	matched := 0
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case '"', '\'', '\\':
		case name[matched]:
			matched++
			if matched == len(name) {
				return true
			}
		case name[0]:
			matched = 1
		default:
			matched = 0
		}
	}
	return false
}

// guestCDJoin returns the directories a cd to operand (guestCDOperand) moves
// to from each of bases: an absolute or ~ operand as it is, the home for a
// bare cd, a relative one joined to each base.
func guestCDJoin(operand string, bases []string, home string) []string {
	switch {
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

// guestCDPlainOperand reports a cd operand that is a plain name: not empty,
// ~, . or .., and with no slash. guestCDJoin joins it to each absolute base.
func guestCDPlainOperand(operand string) bool {
	return operand != "" && operand != "~" && operand != "." && operand != ".." && !strings.ContainsRune(operand, '/')
}

// guestCDJoinReadsBases reports an operand guestCDJoin joins to the bases:
// one it does not take as it is (an absolute one, or ~ with an absolute
// home) or answer with the home (a bare cd, ~).
func guestCDJoinReadsBases(operand, home string) bool {
	return operand != "" && operand != "~" && (!strings.HasPrefix(operand, "~/") || !path.IsAbs(home)) && !path.IsAbs(operand)
}

// guestCDJoinClean is guestCDJoin for bases that are each clean
// (path.Clean's answer), as the walks' own folder lists are. A plain name
// (cd d5) joined to a clean folder is that folder, a slash and the name,
// path.Join's answer without its clean, and the targets are clean too: a
// long call joins each of its cds to up to 128 folders, and cleaning each
// join rescanned folders that grow with the chain (rel-1-0-10:GAP-2226,
// GAP-2249).
func guestCDJoinClean(operand string, bases []string, home string) []string {
	if !guestCDPlainOperand(operand) {
		return guestCDJoin(operand, bases, home)
	}
	// The targets are cut from one string: an 8 KB cd chain joins each of
	// its 1,100 cds to up to 128 folders, and a string each was most of
	// guestKnownFolders' allocations (rel-1-0-10:GAP-2249).
	size, count := 0, 0
	for _, base := range bases {
		switch {
		case base == "/":
			size, count = size+1+len(operand), count+1
		case path.IsAbs(base):
			size, count = size+len(base)+1+len(operand), count+1
		}
	}
	if count == 0 {
		return nil
	}
	var joined strings.Builder
	joined.Grow(size)
	for _, base := range bases {
		if base == "/" || path.IsAbs(base) {
			if base != "/" {
				joined.WriteString(base)
			}
			joined.WriteByte('/')
			joined.WriteString(operand)
		}
	}
	all := joined.String()
	targets := make([]string, 0, count)
	for _, base := range bases {
		size := 0
		switch {
		case base == "/":
			size = 1 + len(operand)
		case path.IsAbs(base):
			size = len(base) + 1 + len(operand)
		}
		if size != 0 {
			targets = append(targets, all[:size])
			all = all[size:]
		}
	}
	return targets
}

// guestKnownFolders gives each folder of the guest placement's lists the
// first place in the text from which a call may stand in it (known), and
// returns the cd targets list grown by the static cd and pushd calls of the
// script (calls). A call's targets are joined only to the folders known
// where it may run (at): pushd src before a later cd ~/.defenseclaw does not
// reach ~/.defenseclaw/src. A target is known from where the call starts,
// so a cd in a loop or a function body counts for every statement after it
// in the text, and one in a function body from the first call of the
// function (guestScriptCall.first). The guest's folder and a folder of the
// lists no static cd of the script reaches are known from the start (-1).
// cdpath is the first place a statement may set CDPATH
// (guestScriptCalls; -1 when the text names it outside every statement):
// a folder a relative cd that may run after it can reach through a CDPATH
// entry (guestCDPathMayReach) is known from that cd. Every folder known from
// the start for any text that named CDPATH made export CDPATH=.; cd src;
// echo m > config.yaml; cd ~/.defenseclaw && ls a strict block where the
// laptop and both rels allow (substrate-1 GAP-0989). A folder the split's cds reach through a
// followed value more often than the static cds of the script do (followed:
// D=~/.claude; cd "$D" before a later cd ~/.claude) is known from the first
// call the split may follow a value in (guestScriptCall.dynamic), or from
// the start. The walk runs again while a round knows a folder earlier, at
// most four rounds; past them every folder is known from the start. It
// returns the grown targets and known.
func guestKnownFolders(calls []guestScriptCall, dirs, targets []string, followed map[string]int, cwd, home string, cdpath int,
	keep func([]string, string) []string, cdMemo *guestCDMemo) ([]string, map[string]int) {
	type move struct {
		operand string
		at      int
	}
	var moves []move
	dynamic := -1
	for at, call := range calls {
		if call.dynamic && dynamic < 0 {
			dynamic = call.start
		}
		if reading := cdMemo.reading(call.text); reading.moves {
			moves = append(moves, move{reading.operand, at})
		}
	}
	// known is made at about the size it reaches: a relative cd is joined
	// to at most every listed folder, an absolute or ~ one names one. An
	// 8 KB cd chain grew it to 140,000 folders a split at a time
	// (rel-1-0-10:GAP-2249).
	listed := slices.Concat(dirs, targets)
	size := len(listed)
	for _, move := range moves {
		if path.IsAbs(move.operand) || move.operand == "~" || strings.HasPrefix(move.operand, "~/") {
			size++
		} else {
			size += len(dirs) + maxSandboxGuestCandidateDirs
		}
	}
	known := make(map[string]int, min(size, guestKnownFoldersSizeMax))
	// dirs and targets are clean (newGuestPlacementPlan's keep cleans each),
	// so every target guestCDJoinClean makes from them is clean, and keep
	// takes it as it is.
	for _, dir := range listed {
		if cdpath < 0 || dir == path.Clean(cwd) {
			known[dir] = -1
		}
	}
	grown := targets
	var bases []string
	reached := map[string]int{}
	// joins holds, per move, the bases it was joined to in the last round
	// that changed them, and the targets of that join. A move whose bases
	// are the same in a later round reaches the same targets, and each of
	// them is already known from call.first or earlier (a folder's place
	// only moves earlier), so it is not joined or looked up again: the
	// round that only confirms the walk redid every join of an 8 KB cd
	// chain (rel-1-0-10:GAP-2249).
	type moveJoin struct{ bases, targets []string }
	joins := make([]moveJoin, len(moves))
	for round := 0; ; round++ {
		if round == 4 {
			for _, dir := range slices.Concat(listed, grown) {
				known[dir] = -1
			}
			return grown, known
		}
		changed := false
		grown = slices.Clone(targets)
		clear(reached)
		var pool []string
		for at, move := range moves {
			call := calls[move.at]
			bases = bases[:0]
			for _, list := range [2][]string{dirs, grown} {
				for _, dir := range list {
					if since, ok := known[dir]; ok && since <= call.at {
						bases = append(bases, dir)
					}
				}
			}
			join := &joins[at]
			same := round > 0 && slices.Equal(join.bases, bases)
			if !same {
				start := len(pool)
				pool = append(pool, bases...)
				join.bases, join.targets = pool[start:len(pool):len(pool)], guestCDJoinClean(move.operand, bases, home)
			}
			for _, target := range join.targets {
				// reached is read only against followed, which counts no
				// folder when the split followed no value.
				if len(followed) != 0 {
					reached[target]++
				}
				grown = keep(grown, target)
				if same {
					continue
				}
				if since, ok := known[target]; !ok || call.first < since {
					known[target] = call.first
					changed = true
				}
			}
			if call.at < cdpath || !guestCDPathLooksUp(move.operand) {
				continue
			}
			for _, dir := range slices.Concat(listed, grown) {
				if since, ok := known[dir]; guestCDPathMayReach(dir, move.operand) && (!ok || call.first < since) {
					known[dir] = call.first
					changed = true
				}
			}
		}
		for _, dir := range slices.Concat(listed, grown) {
			since, ok := known[dir]
			switch {
			case !ok:
				known[dir] = -1
				changed = true
			case followed[dir] > reached[dir] && since > dynamic:
				known[dir] = dynamic
				changed = true
			}
		}
		if !changed {
			return grown, known
		}
	}
}

// guestKnownFoldersSizeMax bounds the size guestKnownFolders makes its map
// at: past it the map grows as it fills.
const guestKnownFoldersSizeMax = 1 << 17

// guestScriptCall is a simple-command statement of a script
// (guestScriptCalls): its source text, with its redirections, where it
// starts (the first place it may run from), and at, the latest place in the
// text it may run from. That is where it starts, the end
// of a loop it sits in (it runs again after the later statements of the
// loop), or the place of the last call of the function whose body holds it:
// the end of the script where the function may be called another way (a
// command the split cannot read, the name in a string, a recursive call),
// and the declaration of a function that is never called.
type guestScriptCall struct {
	text      string
	start, at int
	// first is the earliest place in the text it may run from: where it
	// starts, or the first call of the function whose body holds it when the
	// function runs only where the text calls it and no command the split
	// cannot read comes in the script (f() { cd ~/.defenseclaw && ls; }; echo
	// m > config.yaml; f writes the starting folder's config.yaml; substrate-1
	// GAP-0989).
	first int
	// dynamic marks a call whose program word, or a cd or pushd operand,
	// is not static, or one of cmdRedefiningCommands (eval, source, ...) or
	// a builtin or command wrapper: the split may follow a value there.
	dynamic bool
}

// guestScriptCalls returns, in source order, every simple-command statement
// of a Bash script, nested ones included (a function body, a group, a
// subshell, a process substitution), lexically; nil when the script does not
// parse. cdpath is the start of the first statement that names CDPATH
// (guestNamesCDPath), -1 when the text names it outside every statement or
// does not parse, math.MaxInt when it never does.
func guestScriptCalls(command, home string) (calls []guestScriptCall, cdpath int) {
	return guestScriptCallsWork(command, home, nil)
}

// guestScriptCallsWork is guestScriptCalls; when work is not nil it adds the
// span visits the placement made after the parse (each loop or function body
// span checked against a position), so a test can pin how the work grows with
// the script (substrate-1 GAP-1009: the GAP-0991 loop pass visited every
// unread command for every function and every span, cubic on an 8 KB loop).
func guestScriptCallsWork(command, home string, work *int) (calls []guestScriptCall, cdpath int) {
	names := guestNamesCDPath(command)
	cdpath = math.MaxInt
	if names {
		cdpath = -1
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, cdpath
	}
	cdpath = math.MaxInt
	type span struct {
		start, end int
		name       string
	}
	var loops, bodies []span
	// programs holds the static program word of each call, "" for none;
	// callNodes every call of the script, in walk order (unread, below).
	var programs []string
	var callNodes []*syntax.CallExpr
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			callNodes = append(callNodes, node)
		case *syntax.ForClause, *syntax.WhileClause:
			loops = append(loops, span{start: int(node.Pos().Offset()), end: int(node.End().Offset())})
		case *syntax.FuncDecl:
			if node.Name != nil {
				bodies = append(bodies, span{int(node.Pos().Offset()), int(node.End().Offset()), node.Name.Value})
			}
		case *syntax.Stmt:
			// The statement's span keeps its redirections (> ../.claude/settings.json).
			start, end := int(node.Pos().Offset()), int(node.End().Offset())
			spans := start >= 0 && end <= len(command) && start < end
			if names && spans && start < cdpath && guestNamesCDPath(command[start:end]) {
				cdpath = start
			}
			call, isCall := node.Cmd.(*syntax.CallExpr)
			if !isCall || len(call.Args) == 0 || !spans {
				return true
			}
			program, static := hookpaths.StaticWord(call.Args[0], home)
			if !static {
				program = ""
			}
			var words []*syntax.Word
			if program == "cd" || program == "pushd" || program == "builtin" || program == "command" {
				words = guestCDWords(call.Args, home)
			}
			dynamic := !static || cmdRedefiningCommands[program] || (program == "builtin" || program == "command") && words == nil
			for index := 1; index < len(words); index++ {
				if _, static := hookpaths.StaticWord(words[index], home); !static {
					dynamic = true
				}
			}
			calls = append(calls, guestScriptCall{text: command[start:end], start: start, at: start, first: start, dynamic: dynamic})
			programs = append(programs, program)
		}
		return true
	})
	if names && cdpath == math.MaxInt {
		cdpath = -1 // a comment or a here-document: every folder, as before
	}
	if len(loops) == 0 && len(bodies) == 0 {
		return calls, cdpath
	}
	sites := map[string][]int{}
	if len(bodies) != 0 {
		for at, program := range programs {
			if program != "" {
				sites[program] = append(sites[program], calls[at].start)
			}
		}
	}
	// unread holds where each command the split cannot read starts
	// (guestCallUnread). A function may be called another way only by one
	// that may run after its declaration: after it in the text, in a loop
	// that goes on past it, or in a function body. $CMD before g() { echo m
	// > config.yaml; }; g; cd ~/.defenseclaw && ls cannot call g, and
	// counting it ran the body at the end of the script, a strict block
	// where the laptop and both rels allow (substrate-1 GAP-0989).
	// The calls come from the walk above, in the same order a second walk
	// of the tree visited them (FIX-F3PERF).
	var unread []int
	if len(bodies) != 0 {
		for _, call := range callNodes {
			if guestCallUnread(call, home) {
				unread = append(unread, int(call.Pos().Offset()))
			}
		}
	}
	visits := 0
	if work != nil {
		defer func() { *work += visits }()
	}
	// furthest answers, for spans, the end of the furthest span holding pos,
	// -1 when none holds it: of the spans that start at or before pos, the
	// one that ends furthest holds pos exactly when it ends past pos. A
	// binary search, not a pass over every span (substrate-1 GAP-1009).
	furthest := func(spans []span) func(pos int) int {
		sorted := slices.SortedFunc(slices.Values(spans), func(a, b span) int { return cmp.Compare(a.start, b.start) })
		reach := make([]int, len(sorted))
		for i, s := range sorted {
			reach[i] = s.end
			if i > 0 {
				reach[i] = max(reach[i], reach[i-1])
			}
		}
		return func(pos int) int {
			visits++
			n, _ := slices.BinarySearchFunc(sorted, pos+1, func(s span, target int) int { return cmp.Compare(s.start, target) })
			if n == 0 || reach[n-1] <= pos {
				return -1
			}
			return reach[n-1]
		}
	}
	// loopEnd is the end of the furthest loop holding pos, bodyEnd that of
	// the furthest function body; -1 when none holds it.
	loopEnd, bodyEnd := furthest(loops), furthest(bodies)
	// open marks a function that may be called another way than where the
	// text calls it: an unread command after its declaration in the text or
	// in a function body, or a word of its name that is neither a call nor
	// the declaration. An unread command before the declaration in a loop
	// that goes on past it may call the function only on a later pass, so it
	// counts as a call site where the loop may run (pass, then place), not
	// as the end of the script: for i in 1 2; do $CMD; g() { echo m >
	// config.yaml; }; done; g; cd ~/.defenseclaw && ls was a strict block
	// where the laptop and both rels allow (substrate-1 GAP-0991). A trap it
	// may set on a later pass, the first pass may set too (GAP-0990).
	//
	// Such a command is in no function body, so it runs where its loops end:
	// pass is the furthest loop end of the unread commands before the
	// declaration, -1 for none, worked out once per unread command in source
	// order (reach is its running maximum), not once per function and span
	// (substrate-1 GAP-1009).
	slices.Sort(unread)
	unreadInBody := false
	reach := make([]int, len(unread))
	for i, pos := range unread {
		unreadInBody = unreadInBody || bodyEnd(pos) >= 0
		reach[i] = loopEnd(pos)
		if i > 0 {
			reach[i] = max(reach[i], reach[i-1])
		}
	}
	open := make([]bool, len(bodies))
	pass := make([]int, len(bodies))
	// A name of name bytes only is counted from one pass over the text
	// (guestWordCounts), not one search of the text per function (substrate-1
	// GAP-1028).
	var words map[string]int
	for at, body := range bodies {
		visits++
		count := 0
		if guestAllNameBytes(body.name) {
			if words == nil {
				words = guestWordCounts(command)
			}
			count = words[body.name]
		} else {
			count = guestWordCount(command, body.name)
		}
		open[at] = count != 1+len(sites[body.name]) ||
			unreadInBody || len(unread) != 0 && unread[len(unread)-1] >= body.start
		pass[at] = -1
		if before, _ := slices.BinarySearch(unread, body.start); before != 0 {
			pass[at] = reach[before-1]
		}
	}
	// holders lists, in declaration order, the function bodies that hold
	// pos. Bodies nest (one is inside another or apart from it), so they are
	// the enclosing chain of the last body that starts at or before pos: a
	// binary search and a walk up the chain, not a pass over every body for
	// every call (substrate-1 GAP-1028). Spans that do not nest fall back to
	// the pass over every body.
	order := make([]int, len(bodies))
	for at := range order {
		order[at] = at
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(bodies[a].start, bodies[b].start) })
	parent := make([]int, len(bodies))
	nested := true
	var stack []int
	for _, at := range order {
		for len(stack) != 0 && bodies[stack[len(stack)-1]].end <= bodies[at].start {
			stack = stack[:len(stack)-1]
		}
		parent[at] = -1
		if len(stack) != 0 {
			parent[at] = stack[len(stack)-1]
			nested = nested && bodies[at].end <= bodies[parent[at]].end
		}
		stack = append(stack, at)
	}
	holders := func(pos int) []int {
		var held []int
		if !nested {
			for at, body := range bodies {
				visits++
				if pos >= body.start && pos < body.end {
					held = append(held, at)
				}
			}
			return held
		}
		visits++
		n, _ := slices.BinarySearchFunc(order, pos+1, func(at, target int) int { return cmp.Compare(bodies[at].start, target) })
		if n == 0 {
			return nil
		}
		for at := order[n-1]; at >= 0; at = parent[at] {
			visits++
			if pos < bodies[at].end {
				held = append(held, at)
			}
		}
		slices.Sort(held)
		return held
	}
	runs := map[int]int{}
	var place func(pos, depth int) int
	place = func(pos, depth int) int {
		out := max(pos, loopEnd(pos))
		for _, at := range holders(pos) {
			body := bodies[at]
			from, ok := runs[at]
			if !ok {
				from = len(command)
				if !open[at] && depth < 8 {
					from = max(body.start, pass[at])
					for _, site := range sites[body.name] {
						if site >= body.start && site < body.end {
							from = len(command)
							break
						}
						from = max(from, place(site, depth+1))
					}
				}
				runs[at] = from
			}
			out = max(out, from)
		}
		return out
	}
	// early is the earliest place pos may run from: the first call of the
	// function whose body holds it, when that function runs only where the
	// text calls it (no unread command, every word of its name a call or the
	// declaration, no call in its own body); else where it starts.
	firsts := map[int]int{}
	var early func(pos, depth int) int
	early = func(pos, depth int) int {
		out := pos
		for _, at := range holders(pos) {
			body := bodies[at]
			from, ok := firsts[at]
			if !ok {
				from = body.start
				if len(unread) == 0 && !open[at] && depth < 8 && len(sites[body.name]) != 0 {
					from = len(command)
					for _, site := range sites[body.name] {
						if site >= body.start && site < body.end {
							from = body.start
							break
						}
						from = min(from, early(site, depth+1))
					}
				}
				firsts[at] = from
			}
			out = max(out, from)
		}
		return out
	}
	for at := range calls {
		calls[at].first = early(calls[at].start, 0)
		calls[at].at = place(calls[at].at, 0)
	}
	return calls, cdpath
}

// guestWordCounts counts each word of text, a longest run of name bytes
// (guestNameByte): for a name of name bytes only, words[name] is
// guestWordCount(text, name), as a place the name stands with no name byte
// next to it is exactly such a run.
func guestWordCounts(text string) map[string]int {
	words := map[string]int{}
	for at := 0; at < len(text); {
		if !guestNameByte(text[at]) {
			at++
			continue
		}
		end := at + 1
		for end < len(text) && guestNameByte(text[end]) {
			end++
		}
		words[text[at:end]]++
		at = end
	}
	return words
}

// guestAllNameBytes reports a name of one or more name bytes only.
func guestAllNameBytes(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		if !guestNameByte(name[index]) {
			return false
		}
	}
	return true
}

// guestWordCount counts the places name stands in text as a whole word, with
// no name byte (guestNameByte) next to it.
func guestWordCount(text, name string) int {
	count := 0
	for from := 0; name != "" && from < len(text); {
		at := strings.Index(text[from:], name)
		if at < 0 {
			break
		}
		at += from
		end := at + len(name)
		if (at == 0 || !guestNameByte(text[at-1])) && (end == len(text) || !guestNameByte(text[end])) {
			count++
		}
		from = at + 1
	}
	return count
}

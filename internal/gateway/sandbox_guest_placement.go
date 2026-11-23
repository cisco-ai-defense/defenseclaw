// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
//     (guestCDTargets) as a candidate: the CD-CANDIDATE rule of the laptop's
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
	type key struct{ text, cwd string }
	seen := map[key]int{}
	if facts.Authoritative() {
		// Counted by statements, as the laptop counts them: the walk reads a
		// command after a cd that may not run in every directory it may run
		// in, so after three such cds each later command has seven readings
		// outside the guest's directory, and a cap on readings cut a 24-line
		// script the laptop allows (a here-string call, judged by its
		// authoritative twin, substrate-1 GAP-0377).
		statements := map[string]bool{}
		for _, simple := range actionfacts.SimpleCommands(input, facts) {
			cwd := simple.CWD
			if guestPlacementSkips(simple) || !path.IsAbs(cwd) || cwd == input.CWD {
				continue
			}
			if _, ok := seen[key{simple.Text, cwd}]; ok {
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
			seen[key{simple.Text, cwd}] = len(placements)
			placements = append(placements, guestPlacement{text: simple.Text, cwd: cwd})
		}
		return placements, false
	}
	overBudget := statementBudget && trustedCallOverStatementBudget(input, facts)
	if input.Command == "" {
		if command, ok := trustedBashCommandInput(input); ok {
			input.Command, input.Args, input.Argv = command, nil, nil
			facts = actionfacts.Analyze(input)
		}
	}
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
	// dirs are the directories the call's commands run in, targets the cd
	// targets no command is read in yet; each keeps its first
	// maxSandboxGuestCandidateDirs entries, the guest's directory first
	// (substrate-1 GAP-0499). Past the bound a folder that may hold
	// protected files (guestDirFirst: the home, a hidden folder such as
	// ~/.ssh) takes the place of the last plain one kept: cd .cache; $CMD;
	// cd s0; ...; cd s6 lists 2^7 plain folders, and the cd ../.ssh after
	// them was never kept, so the authorized_keys write there was not read
	// where the laptop blocks (substrate-1 GAP-0628).
	keep := func(list []string, dir string) []string {
		if !path.IsAbs(dir) {
			return list
		}
		dir = path.Clean(dir)
		if slices.Contains(list, dir) {
			return list
		}
		if len(list) < maxSandboxGuestCandidateDirs {
			return append(list, dir)
		}
		if !guestDirFirst(dir, input.ActiveHome) {
			return list
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
	type pending struct {
		text, cwd string
		candidate bool
		// seq is the reading's place in the order the pass lists its
		// readings (collect).
		seq int
	}
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
	collect := func(list []pending, listed map[key]int, plain *[]int, dropped *bool, reading pending) []pending {
		at := key{reading.text, reading.cwd}
		if index, ok := listed[at]; ok {
			list[index].candidate = list[index].candidate && reading.candidate
			return list
		}
		first := guestReadingFirst(reading.text)
		reading.seq = arrivals
		arrivals++
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
	// placeAll places the first readings of a pass in the order they were
	// listed, then the plain ones: under the statement budget an earlier
	// protected reading is never skipped for a later one.
	placeAll := func(p *pass, list []pending) bool {
		var firsts, plains []pending
		for _, reading := range list {
			if guestReadingFirst(reading.text) {
				firsts = append(firsts, reading)
			} else {
				plains = append(plains, reading)
			}
		}
		slices.SortFunc(firsts, func(a, b pending) int { return a.seq - b.seq })
		for _, reading := range slices.Concat(firsts, plains) {
			if !place(p, reading.text, reading.cwd, reading.candidate) {
				return false
			}
		}
		return true
	}
	simples := &pass{statements: map[string]bool{}}
	var simpleReadings []pending
	simplesDropped, simplesListed := false, map[key]int{}
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
	for _, simple := range actionfacts.SimpleCommands(input, facts) {
		settle(simple)
		if guestPlacementSkips(simple) {
			continue
		}
		splitRead[simple.Text] = true
		cwd := simple.CWD
		if path.IsAbs(cwd) {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, cwd, false, 0})
		}
		for _, dir := range dirs {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, dir, false, 0})
		}
		for _, dir := range targets {
			simpleReadings = collect(simpleReadings, simplesListed, &simplesPlain, &simplesDropped, pending{simple.Text, dir, true, 0})
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
		switch {
		case guestChangesDirectory(simple.Text, input.ActiveHome):
			targets = keep(targets, cwd)
		case simple.OtherFolder || simple.UnresolvedFolder || simple.LastStageOrBackground || !path.IsAbs(cwd):
			dirs = keep(dirs, cwd)
		default:
			stoodIn, standing = path.Clean(cwd), true
		}
		moved := guestCDTargets(simple.Text, bases, input.ActiveHome)
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
	// A cut pass does not end the others: each has its own bound, and the
	// call is reported cut.
	simplesCut := !placeAll(simples, simpleReadings) || simplesDropped
	command := input.Command
	if command == "" || len(command) > agentHookConfigMaxPlacedBytes {
		return placements, simplesCut
	}
	topCut := false
	if statements, ok := hookpaths.TopLevelStatements(command, input.CWD, input.ActiveHome); ok {
		top := &pass{statements: map[string]bool{}}
		for _, statement := range statements {
			if path.IsAbs(statement.Dir) && !place(top, statement.Command, statement.Dir, false) {
				topCut = true
				break
			}
		}
	}
	// Every call of the script, a function body's included: the split stops
	// at a construct it cannot read (f() { cd .cache; }; f; $CMD gives one
	// parse failure), while a static cd anywhere in the text is still a
	// directory the laptop's readers keep. Each call is read only in the
	// folders known at its own place in the text (guestScriptCall.at): a
	// folder a static cd reaches (guestCDTargets) is known from that cd on,
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
	// of the text names, and every folder of a call that names CDPATH are
	// known from the start, as before. A call the simples pass read
	// (splitRead) is not read again: it was read in the folders known at its
	// own place. Its cd targets are still kept.
	scriptCalls := guestScriptCalls(command, input.ActiveHome)
	known := map[string]int{}
	targets = guestKnownFolders(scriptCalls, dirs, targets, followed, input.CWD, input.ActiveHome, strings.Contains(command, "CDPATH"), keep, known)
	calls := &pass{statements: map[string]bool{}}
	var callReadings []pending
	callsDropped, callsListed := false, map[key]int{}
	var callsPlain []int
	for _, call := range scriptCalls {
		if splitRead[call.text] {
			continue
		}
		for _, dir := range dirs {
			if known[dir] <= call.at {
				callReadings = collect(callReadings, callsListed, &callsPlain, &callsDropped, pending{call.text, dir, false, 0})
			}
		}
		for _, dir := range targets {
			if known[dir] <= call.at {
				callReadings = collect(callReadings, callsListed, &callsPlain, &callsDropped, pending{call.text, dir, true, 0})
			}
		}
	}
	callsCut := !placeAll(calls, callReadings) || callsDropped
	return placements, simplesCut || topCut || callsCut
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
	return dir == path.Clean(home) || strings.HasPrefix(path.Base(dir), ".")
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
	guestFacts := actionfacts.Analyze(guest)
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
	guestFacts := actionfacts.Analyze(guest)
	if !slices.ContainsFunc(actionfacts.SimpleCommands(guest, guestFacts), splitGapUnreadPart) {
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

// guestChangesDirectory reports, lexically, a cd, pushd or popd command
// text.
func guestChangesDirectory(text, home string) bool {
	call, ok := guestCall(text)
	if !ok {
		return false
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	return static && (program == "cd" || program == "pushd" || program == "popd")
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

// guestShellReading is one statement of a call, by its source text, and a
// folder the call's own shell may stand in when it runs (guestOwnShellFolders).
type guestShellReading struct{ text, dir string }

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
func guestOwnShellFolders(command, cwd, home string) map[guestShellReading]bool {
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
func guestOwnShellWalk(command, cwd, home string) (map[guestShellReading]bool, map[string]bool) {
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
	join := func(sets ...[]string) []string {
		var out []string
		seen := map[string]bool{}
		for _, set := range sets {
			for _, dir := range set {
				if dir = path.Clean(dir); path.IsAbs(dir) && !seen[dir] {
					seen[dir] = true
					out = append(out, dir)
				}
			}
		}
		if len(out) > maxSandboxGuestOwnShellFolders {
			slices.SortStableFunc(out, func(a, b string) int {
				first := func(dir string) int {
					if guestDirFirst(dir, home) {
						return 0
					}
					return 1
				}
				return first(a) - first(b)
			})
			out = out[:maxSandboxGuestOwnShellFolders]
		}
		return out
	}
	unread := false
	var readings map[guestShellReading]bool
	placed := map[string]bool{}
	// mark keys every simple command of node (one statement, run from the
	// folders in) with each of those folders, once a command before it may
	// have moved the shell, and notes in placed whether the walk placed it.
	mark := func(node syntax.Node, in []string) {
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
					readings = map[guestShellReading]bool{}
				}
				for _, dir := range in {
					readings[guestShellReading{span, dir}] = true
				}
			}
			return true
		})
	}
	// step runs one statement from the folders in: the folders the shell
	// stands in where it succeeded and where it failed.
	var step func(*syntax.Stmt, []string) (succeeded, failed []string)
	step = func(stmt *syntax.Stmt, in []string) (succeeded, failed []string) {
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
		mark(stmt, in)
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
				moved := guestCDTargets(text(stmt), in, home)
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
	current := []string{path.Clean(cwd)}
	for _, stmt := range file.Stmts {
		succeeded, failed := step(stmt, current)
		current = join(succeeded, failed)
	}
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil || len(file.Stmts) != 1 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	return call, ok && len(call.Args) != 0
}

// guestCDTargets returns, lexically, the directories a cd or pushd command
// text moves to from each of bases: a static operand joined to each base,
// an absolute or ~ operand as it is, the home for a bare cd. A dynamic
// operand, cd - and popd add none (they return to a directory already a
// candidate, or to one no static word names).
func guestCDTargets(text string, bases []string, home string) []string {
	operand, ok := guestCDOperand(text, home)
	if !ok {
		return nil
	}
	return guestCDJoin(operand, bases, home)
}

// guestCDOperand returns, lexically, the static operand of a cd or pushd
// command text ("" for a bare cd); false for any other text, a dynamic
// operand and cd -.
func guestCDOperand(text, home string) (string, bool) {
	call, ok := guestCall(text)
	if !ok {
		return "", false
	}
	program, static := hookpaths.StaticWord(call.Args[0], home)
	if !static || program != "cd" && program != "pushd" {
		return "", false
	}
	operand := ""
	for _, word := range call.Args[1:] {
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

// guestKnownFolders gives each folder of the guest placement's lists the
// first place in the text from which a call may stand in it (known), and
// returns the cd targets list grown by the static cd and pushd calls of the
// script (calls). A call's targets are joined only to the folders known
// where it may run (at): pushd src before a later cd ~/.defenseclaw does not
// reach ~/.defenseclaw/src. A target is known from where the call starts,
// so a cd in a loop or a function body counts for every statement after it
// in the text. The guest's folder, every folder when the script names
// CDPATH, and a folder of the lists no static cd of the script reaches are
// known from the start (-1). A folder the split's cds reach through a
// followed value more often than the static cds of the script do (followed:
// D=~/.claude; cd "$D" before a later cd ~/.claude) is known from the first
// call the split may follow a value in (guestScriptCall.dynamic), or from
// the start. The walk runs again while a round knows a folder earlier, at
// most four rounds; past them every folder is known from the start.
func guestKnownFolders(calls []guestScriptCall, dirs, targets []string, followed map[string]int, cwd, home string, cdpath bool,
	keep func([]string, string) []string, known map[string]int) []string {
	listed := slices.Concat(dirs, targets)
	for _, dir := range listed {
		if cdpath || dir == path.Clean(cwd) {
			known[dir] = -1
		}
	}
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
		if operand, ok := guestCDOperand(call.text, home); ok {
			moves = append(moves, move{operand, at})
		}
	}
	grown := targets
	var bases []string
	reached := map[string]int{}
	for round := 0; ; round++ {
		if round == 4 {
			for _, dir := range slices.Concat(listed, grown) {
				known[dir] = -1
			}
			return grown
		}
		changed := false
		grown = slices.Clone(targets)
		clear(reached)
		for _, move := range moves {
			call := calls[move.at]
			bases = bases[:0]
			for _, dir := range slices.Concat(dirs, grown) {
				if since, ok := known[dir]; ok && since <= call.at {
					bases = append(bases, dir)
				}
			}
			for _, target := range guestCDJoin(move.operand, bases, home) {
				reached[target]++
				grown = keep(grown, target)
				if since, ok := known[target]; !ok || call.start < since {
					known[target] = call.start
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
			return grown
		}
	}
}

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
	// dynamic marks a call whose program word, or a cd or pushd operand,
	// is not static, or one of cmdRedefiningCommands (eval, source, ...) or
	// a builtin or command wrapper: the split may follow a value there.
	dynamic bool
}

// guestScriptCalls returns, in source order, every simple-command statement
// of a Bash script, nested ones included (a function body, a group, a
// subshell, a process substitution), lexically; nil when the script does not
// parse.
func guestScriptCalls(command, home string) []guestScriptCall {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	type span struct {
		start, end int
		name       string
	}
	var loops, bodies []span
	var calls []guestScriptCall
	// programs holds the static program word of each call, "" for none.
	var programs []string
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.ForClause, *syntax.WhileClause:
			loops = append(loops, span{start: int(node.Pos().Offset()), end: int(node.End().Offset())})
		case *syntax.FuncDecl:
			if node.Name != nil {
				bodies = append(bodies, span{int(node.Pos().Offset()), int(node.End().Offset()), node.Name.Value})
			}
		case *syntax.Stmt:
			call, isCall := node.Cmd.(*syntax.CallExpr)
			if !isCall || len(call.Args) == 0 {
				return true
			}
			// The statement's span keeps its redirections (> ../.claude/settings.json).
			start, end := int(node.Pos().Offset()), int(node.End().Offset())
			if start >= 0 && end <= len(command) && start < end {
				program, static := hookpaths.StaticWord(call.Args[0], home)
				if !static {
					program = ""
				}
				dynamic := !static || cmdRedefiningCommands[program] || program == "builtin" || program == "command"
				if program == "cd" || program == "pushd" {
					for _, word := range call.Args[1:] {
						if _, static := hookpaths.StaticWord(word, home); !static {
							dynamic = true
						}
					}
				}
				calls = append(calls, guestScriptCall{text: command[start:end], start: start, at: start, dynamic: dynamic})
				programs = append(programs, program)
			}
		}
		return true
	})
	if len(loops) == 0 && len(bodies) == 0 {
		return calls
	}
	sites := map[string][]int{}
	if len(bodies) != 0 {
		for at, program := range programs {
			if program != "" {
				sites[program] = append(sites[program], calls[at].start)
			}
		}
	}
	unread := len(bodies) != 0 && guestNodeRunsUnreadCommand(file, home)
	runs := map[int]int{}
	var place func(pos, depth int) int
	place = func(pos, depth int) int {
		out := pos
		for _, loop := range loops {
			if loop.start <= pos && pos < loop.end {
				out = max(out, loop.end)
			}
		}
		for at, body := range bodies {
			if pos < body.start || pos >= body.end {
				continue
			}
			from, ok := runs[at]
			if !ok {
				from = len(command)
				if !unread && depth < 8 && guestWordCount(command, body.name) == 1+len(sites[body.name]) {
					from = body.start
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
	for at := range calls {
		calls[at].at = place(calls[at].at, 0)
	}
	return calls
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

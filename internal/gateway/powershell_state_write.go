// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"maps"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// provenPowerShellStateWrite judges the PowerShell reading of a Windows-home
// command for the state-write proof (GAP-2414). Codex names its PowerShell
// tool Bash and shell_command may run PowerShell, and one statement the
// parser does not model (” | Out-File, an expression, a .NET call) leaves
// the whole command partial, so a write of DefenseClaw state next to it had
// no proof. Each statement and pipeline element that names DefenseClaw is
// read as a PowerShell command of its own, and each file an expression
// writes (a redirect target, a provider-path variable assignment
// ${C:\...} = x, the path of a .NET file write) is read as the write
// Set-Content -LiteralPath <target> it is. Only a twin whose own reading
// proves the mutation of active state counts. The caller has already seen a
// DefenseClaw state mention. A command that reaches the state only through a
// link (a junction onto the state directory) does not spell DefenseClaw: it
// is read when the mention scan, which walks the link on the file system as
// the cmdlet route does, places it in the state, and the reading then follows
// the text and values that scan places there (GAP-1023 IB34). A managed
// gateway cannot walk the user's links: there the text and values are those
// that spell a path the hook client lists in the state tree, as the user's
// walk placed it (clientStateSpellings).
// unknown reports no proven write but a .NET open that may write active
// state by a mode or path known only at run time (powerShellWriteReading).
func provenPowerShellStateWrite(request trustedActionRequest) (proven, unknown bool) {
	for _, command := range powerShellReadingCommands(request) {
		written, maybe := provenPowerShellStateWriteOf(request, command)
		if written {
			return true, false
		}
		unknown = unknown || maybe
	}
	return false, unknown
}

// provenPowerShellStateWriteOf is provenPowerShellStateWrite for one
// PowerShell reading command of the call.
func provenPowerShellStateWriteOf(request trustedActionRequest, command powerShellReadingCommand) (proven, unknown bool) {
	home := request.Input.ActiveHome
	var mentions func(string) bool
	if !strings.Contains(strings.ToLower(command.text), "defenseclaw") {
		cwd := request.Input.CWD
		mentions = func(text string) bool { return request.targetMemo.ActionStateTargetMention(text, cwd, home) }
		if request.ProtectedHomeHook {
			spellings := clientStateSpellings(request.ResolvedWriteTargets, home)
			mentions = func(text string) bool { return psSpellsAny(text, spellings) }
		}
		if !mentions(command.text) {
			return false, false
		}
	}
	return powerShellWriteReading(request, command, mentions, provenStateMutationPath, psStateProtectedPaths(home))
}

// powerShellReadingCommand is one command text the PowerShell reading judges
// (powerShellReadingCommands).
type powerShellReadingCommand struct {
	text string
	// posixTool is the command of a PowerShell tool call of a Linux or macOS
	// home. Its reading proves only what it reads within its bounds: past
	// them the shared readers judge the call with their own bounds, as they
	// did before the reading read it (statement-padded state readings,
	// rel-1-0-6:GAP-0448).
	posixTool bool
}

// powerShellReadingCommands are the command texts of a call the PowerShell
// reading judges: a call of a Windows home (a drive path) that runs in
// PowerShell, or in a shell the gateway cannot tell from it (no hint, or
// POSIX: Codex names its PowerShell tool Bash); for a POSIX call of a Linux
// or macOS home, the script of each PowerShell launcher it runs (pwsh
// -Command BODY, actionfacts.PowerShellLauncherScripts): its .NET file
// writes, New-Item -Value and home spellings were read nowhere else
// (rel-1-0-10:GAP-1134); and the command of a PowerShell tool call of such a
// home (Claude Code's PowerShell tool on Linux or macOS), which pwsh runs as
// that script: its .NET file writes and New-Item -Value of the DefenseClaw
// state or a hook config were allowed (rel-1-0-10:GAP-1214). A cmd call is
// not one.
func powerShellReadingCommands(request trustedActionRequest) []powerShellReadingCommand {
	home := request.Input.ActiveHome
	hint := request.Input.DialectHint
	switch {
	case len(home) >= 2 && home[1] == ':' &&
		(hint == "" || hint == actionfacts.DialectPOSIX || hint == actionfacts.DialectPowerShell):
		if command, known := trustedBashCommandInput(request.Input); known {
			return []powerShellReadingCommand{{text: command}}
		}
		return nil
	case strings.HasPrefix(home, "/"):
		// Only the PowerShell tool command is a Linux or macOS reading: a
		// Windows hook host with a '/' home (unresolvedCallerHome: a managed
		// peer with no Home, a service gateway with no identity home) runs
		// that tool in Windows PowerShell (GAP-1254). The launcher scripts
		// are read for every '/' home, as rel read them (GAP-1300).
		var commands []powerShellReadingCommand
		if !request.Input.WindowsHookHost && (hint == "" || hint == actionfacts.DialectPowerShell) {
			if trustedPowerShellExecutionTool(request.Input.Tool) {
				if command, known := trustedBashCommandInput(request.Input); known {
					commands = append(commands, powerShellReadingCommand{text: command, posixTool: true})
				}
			}
		}
		for _, script := range actionfacts.PowerShellLauncherScripts(request.Input) {
			commands = append(commands, powerShellReadingCommand{text: script})
		}
		return commands
	}
	return nil
}

// powerShellWriteReading is the one reader of the files a PowerShell reading
// of command writes, for every protected class: the DefenseClaw state
// (provenPowerShellStateWrite), the agent hook configs
// (agentHookConfigPowerShellWrite) and whichever class proves passes on.
// Each statement and pipeline element that follows names (or spells
// DefenseClaw) is read as a PowerShell command of its own, and each file an
// expression writes (a redirect, a provider-path assignment, a .NET file
// method: psFileWriteMethod) as Set-Content -LiteralPath <target>; ActionFacts
// reads each such twin, as the redirect and every write cmdlet
// (Add-Content, Set-Content, Out-File, Tee-Object, New-Item, Copy-Item and
// Move-Item destinations) are read, and proves judges the twin's facts. A
// command past the reading bounds is the write (true without proves), but
// for the command of a PowerShell tool of a Linux or macOS home
// (powerShellReadingCommand.posixTool), which the shared readers judge with
// their bounds. unknown reports no proven write but a .NET open that may
// write a file proves accepts, by a mode or path known only at run time: the
// caller gives it the unknown tier of the pack (rel-1-0-10:GAP-1138).
// protected are the files of the class a wildcard path of a write cmdlet may
// match: each one it can match is such an unknown twin (psWildcardWriteTwins,
// rel-1-0-10:GAP-1272).
func powerShellWriteReading(request trustedActionRequest, command powerShellReadingCommand, follows func(string) bool,
	proves func(actionfacts.Facts, trustedActionRequest) bool, protected psProtectedPaths) (written, unknown bool) {
	forms, unknownForms, placed, bounded, ok := powerShellStateWriteForms(command.text, request.Input.ActiveHome, request.Input.CWD, request.ResolvedWriteTargets, follows, protected)
	if !ok {
		return false, false
	}
	// The files a wildcard pattern the hook client placed may match, at the
	// folder the client walked to (psWildcardElementTwins).
	resolved := request.ResolvedWriteTargets
	if len(placed) > 0 {
		resolved = make(map[string]string, len(request.ResolvedWriteTargets)+len(placed))
		for spelling, target := range request.ResolvedWriteTargets {
			resolved[spelling] = target
		}
		for spelling, target := range placed {
			if _, known := resolved[spelling]; !known {
				resolved[spelling] = target
			}
		}
	}
	// Bound the twins a crafted command can ask for and the text the
	// reading copies; past a bound the state-naming command counts as the
	// write (over-block, RV10-3, RV14-2).
	const maxForms = 128
	pastBounds := !command.posixTool
	if bounded || len(forms)+len(unknownForms) > maxForms {
		return pastBounds, false
	}
	proven := func(form string) bool {
		input := request.Input
		input.Command, input.Args, input.Argv = form, nil, nil
		input.DialectHint = actionfacts.DialectPowerShell
		// Under a Linux or macOS home each command it reads is a script pwsh
		// runs (powerShellReadingCommands).
		input.PowerShellLauncherBody = strings.HasPrefix(request.Input.ActiveHome, "/")
		// pwsh on Linux and macOS writes the POSIX path a twin names, which
		// the PowerShell reading places as a Windows one (no drive, so no
		// file): the twin of a literal path there is the file write tool's
		// write of it (rel-1-0-10:GAP-1138).
		if args, ok := psPOSIXWriteTwin(form, request.Input.ActiveHome, request.Input.CWD); ok {
			input.Tool, input.Command, input.Args, input.DialectHint = "Write", "", args, ""
		}
		twin := request
		twin.Input = input
		twin.ResolvedWriteTargets = resolved
		return proves(actionfacts.Analyze(input), twin)
	}
	const maxVariants = 256
	variants := 0
	for _, form := range forms {
		// PowerShell takes any unique parameter prefix (-ErrorA, -Verb,
		// -Fo), and the reader leaves an unknown parameter partial, which
		// dropped the proof. A mutator's prefixes are resolved; one that
		// stays unknown or ambiguous is read without it, alone and with
		// its value, and any reading that writes state is the write
		// (over-block, checker it15 RV15-2).
		// plain is form, or, when a parameter can only take the next word
		// as its value, form without both (psParameterReadings): the
		// PowerShell reader skips the unknown parameter and reads its value
		// as an operand, so mv -t <folder> <file> moved the folder
		// (rel-1-0-10:GAP-1209). A parameter the cmdlet binds is never
		// dropped, so -L and -Fi keep the proof (rel-1-0-10:GAP-1232).
		readings, plain, bounded := psParameterReadings(form)
		variants += len(readings)
		if bounded || variants > maxVariants {
			return pastBounds, false
		}
		if proven(plain) {
			return true, false
		}
		for _, variant := range readings {
			if proven(variant) {
				return true, false
			}
		}
		// A value PowerShell reads at run time (a here-string, a variable)
		// leaves the statement partial, although it names none of the files
		// the cmdlet writes: Set-Content -Path <state> -Value @" ... "@ was
		// allowed in every pack (rel-1-0-10:GAP-0750). Each such word is read
		// as a plain one, in plain: a value bound to a dropped parameter
		// names no file (rel-1-0-10:GAP-1209).
		opaque, bounded := psOpaqueValueReadings(plain)
		variants += len(opaque)
		if bounded || variants > maxVariants {
			return pastBounds, false
		}
		for _, variant := range opaque {
			if proven(variant) {
				return true, false
			}
		}
		// The content a cmdlet writes leaves which file it opens alone,
		// but ActionFacts keeps New-Item -Value partial (it may name a link
		// target): the reading without it proves the write of -Path
		// (rel-1-0-10:GAP-1115).
		if variant, ok := psContentFreeReading(plain); ok && proven(variant) {
			return true, false
		}
	}
	for _, form := range unknownForms {
		if proven(form) {
			return false, true
		}
	}
	return false, false
}

// psContentParameters are, per mutator cmdlet, the parameters that carry
// only what is written (content, or the target a new link points to),
// never which item is written.
var psContentParameters = map[string][]string{
	"new-item": {"value", "target"},
	"ni":       {"value", "target"},
}

// psContentFreeReading returns form without the content parameters of its
// cmdlet (psContentParameters) and their values, false when it has none.
// A parameter spelled with its value (-Value:x) drops as one word.
func psContentFreeReading(form string) (string, bool) {
	budget := &psBudget{}
	words := psWords(form, budget)
	if budget.over || len(words) < 2 {
		return "", false
	}
	content := psContentParameters[strings.ToLower(words[0].text)]
	if content == nil {
		return "", false
	}
	kept := make([]string, 0, len(words))
	dropped := false
	for k := 0; k < len(words); k++ {
		word := words[k]
		name, _, joined := strings.Cut(strings.ToLower(strings.TrimPrefix(word.text, "-")), ":")
		if k > 0 && !word.quoted && strings.HasPrefix(word.text, "-") && slices.Contains(content, name) {
			dropped = true
			if !joined {
				k++
			}
			continue
		}
		kept = append(kept, word.text)
	}
	return strings.Join(kept, " "), dropped
}

// psMaxOpaqueValues bounds the words of one statement that
// psOpaqueValueReadings reads: past it the statement is bounded.
const psMaxOpaqueValues = 8

// psOpaqueValueReadings returns the readings of a statement with, in each,
// one word that PowerShell evaluates at run time (a here-string or a
// variable, never the cmdlet name) replaced by the plain word x. The value
// of such a word cannot name another file of a cmdlet that writes the path
// it is given, but it leaves the statement partial, and a partial statement
// proves no mutation of the active state. A reading whose other words prove
// the mutation is the mutation: no value changes which file Set-Content,
// Add-Content or Out-File opens. bounded reports more words than
// psMaxOpaqueValues, or a statement past the reading budget.
func psOpaqueValueReadings(form string) (readings []string, bounded bool) {
	budget := &psBudget{}
	r := []rune(form)
	scan := newPSScan(r, budget)
	type span struct{ start, end int }
	var spans []span
	for i, word := 0, 0; i < len(r) && budget.step(); word++ {
		if r[i] == ' ' || r[i] == '\t' || r[i] == '\r' || r[i] == '\n' {
			i++
			word--
			continue
		}
		start := i
		opaque := r[i] == '$'
		if r[i] == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && scan.hereStringOpen(i+2) {
			i = scan.hereString(i)
			opaque = true
		} else {
			for i < len(r) && r[i] != ' ' && r[i] != '\t' && r[i] != '\r' && r[i] != '\n' && budget.step() {
				switch {
				case r[i] == '`':
					i += 2
				case psSingleQuote(r[i]):
					i = scan.singleQuoted(i)
				case psDoubleQuote(r[i]):
					i = scan.doubleQuoted(i)
				default:
					i++
				}
			}
		}
		if i > len(r) {
			i = len(r)
		}
		if opaque && word > 0 {
			spans = append(spans, span{start, i})
		}
	}
	if budget.over || len(spans) > psMaxOpaqueValues {
		return nil, true
	}
	for _, at := range spans {
		readings = append(readings, string(r[:at.start])+"x"+string(r[at.end:]))
	}
	return readings, false
}

// clientStateSpellings returns the spellings (psLinkKey) of the paths the
// hook client's map places in the active state tree of home, also relative to
// the folder the client ran the call in. The client walks a quoted path of a
// PowerShell call as the user and lists it when it reaches the state
// (hookpaths stateOperand), where a gateway that cannot read the home sees
// neither the link nor where it leads.
func clientStateSpellings(targets map[string]string, home string) []string {
	state := psLinkKey(home + `\.defenseclaw`)
	cwd := psLinkKey(targets[hookpaths.CWDKey])
	var spellings []string
	for key, value := range targets {
		if key == "" || strings.HasPrefix(key, "\x00") {
			continue
		}
		if physical := psLinkKey(value); physical != state && !strings.HasPrefix(physical, state+`\`) {
			continue
		}
		spelling := psLinkKey(key)
		spellings = append(spellings, spelling)
		if rest, ok := strings.CutPrefix(spelling, cwd+`\`); ok && cwd != "" {
			spellings = append(spellings, rest)
		}
	}
	return spellings
}

// psSpellsAny reports text that spells one of spellings (psLinkKey).
func psSpellsAny(text string, spellings []string) bool {
	if len(spellings) == 0 {
		return false
	}
	text = strings.ToLower(strings.ReplaceAll(text, "/", `\`))
	for _, spelling := range spellings {
		if spelling != "" && strings.Contains(text, spelling) {
			return true
		}
	}
	return false
}

// psParameter is one parameter of a mutator cmdlet as PowerShell binds it:
// its name and aliases, whether it is a switch (no value of its own), and
// whether its value names an item the cmdlet writes, moves or removes.
type psParameter struct {
	name     string
	aliases  []string
	isSwitch bool
	path     bool
}

func psValued(name string, aliases ...string) psParameter {
	return psParameter{name: name, aliases: aliases}
}

func psSwitch(name string, aliases ...string) psParameter {
	return psParameter{name: name, aliases: aliases, isSwitch: true}
}

func psPath(name string, aliases ...string) psParameter {
	return psParameter{name: name, aliases: aliases, path: true}
}

// psMutatorParameters are, per mutator cmdlet and alias (one that writes,
// renames, moves, copies over, empties or removes the item its path
// parameters name), the parameters it binds in Windows PowerShell 5.1 and
// PowerShell 7: its own, the FileSystem provider's dynamic ones (Stream,
// Encoding, NoNewline, AsByteStream), the common parameters and, where it
// supports them, WhatIf, Confirm and UseTransaction. PowerShell binds a
// prefix against the parameters of the cmdlet it runs, not of any other
// (rel-1-0-10:GAP-1232).
var psMutatorParameters = func() map[string][]psParameter {
	common := []psParameter{
		psSwitch("Verbose", "vb"), psSwitch("Debug", "db"),
		psValued("ErrorAction", "ea"), psValued("WarningAction", "wa"),
		psValued("InformationAction", "infa"), psValued("ProgressAction", "proga"),
		psValued("ErrorVariable", "ev"), psValued("WarningVariable", "wv"),
		psValued("InformationVariable", "iv"), psValued("OutVariable", "ov"),
		psValued("OutBuffer", "ob"), psValued("PipelineVariable", "pv"),
	}
	shouldProcess := slices.Concat(common, []psParameter{psSwitch("WhatIf", "wi"), psSwitch("Confirm", "cf")})
	literal := psPath("LiteralPath", "PSPath", "LP")
	provider := slices.Concat(shouldProcess, []psParameter{
		psPath("Path"), literal, psSwitch("Force"), psValued("Credential"),
		psSwitch("UseTransaction", "usetx"),
	})
	filtered := slices.Concat(provider, []psParameter{psValued("Filter"), psValued("Include"), psValued("Exclude")})
	content := slices.Concat(filtered, []psParameter{
		psValued("Value"), psSwitch("PassThru"), psValued("Encoding"), psValued("Stream"),
		psSwitch("NoNewline"), psSwitch("AsByteStream"),
	})
	rename := slices.Concat(provider, []psParameter{psPath("NewName"), psSwitch("PassThru")})
	move := slices.Concat(filtered, []psParameter{psPath("Destination"), psSwitch("PassThru")})
	copyItem := slices.Concat(move, []psParameter{
		psSwitch("Container"), psSwitch("Recurse"), psValued("FromSession"), psValued("ToSession"),
	})
	remove := slices.Concat(filtered, []psParameter{psSwitch("Recurse"), psValued("Stream")})
	clearContent := slices.Concat(filtered, []psParameter{psValued("Stream")})
	setItem := slices.Concat(filtered, []psParameter{psValued("Value"), psSwitch("PassThru")})
	newItem := slices.Concat(shouldProcess, []psParameter{
		psPath("Path"), psPath("Name"), psValued("ItemType", "Type"), psValued("Value", "Target"),
		psSwitch("Force"), psValued("Credential"), psSwitch("UseTransaction", "usetx"),
	})
	outFile := slices.Concat(shouldProcess, []psParameter{
		psPath("FilePath", "Path"), literal, psValued("Encoding"), psSwitch("Append"),
		psSwitch("Force"), psSwitch("NoClobber", "NoOverwrite"), psValued("Width"),
		psSwitch("NoNewline"), psValued("InputObject"),
	})
	tee := slices.Concat(common, []psParameter{
		psPath("FilePath", "Path"), literal, psSwitch("Append"), psValued("Variable"),
		psValued("InputObject"), psValued("Encoding"),
	})
	table := map[string][]psParameter{}
	for _, cmdlet := range []struct {
		params []psParameter
		words  []string
	}{
		{rename, []string{"rename-item", "rni", "ren"}},
		{move, []string{"move-item", "mi", "mv", "move"}},
		{copyItem, []string{"copy-item", "cpi", "cp", "copy"}},
		{remove, []string{"remove-item", "ri", "rm", "rmdir", "rd", "del", "erase"}},
		{clearContent, []string{"clear-content", "clc"}},
		{content, []string{"set-content", "sc", "add-content", "ac"}},
		{outFile, []string{"out-file"}},
		{newItem, []string{"new-item", "ni"}},
		{filtered, []string{"clear-item", "cli"}},
		{setItem, []string{"set-item", "si"}},
		{tee, []string{"tee-object", "tee"}},
	} {
		for _, word := range cmdlet.words {
			table[word] = cmdlet.params
		}
	}
	return table
}()

// psAnyMutatorParameters are the parameters of every mutator cmdlet
// (psMutatorParameters), one per name with the aliases of all.
var psAnyMutatorParameters = func() []psParameter {
	var all []psParameter
	at := map[string]int{}
	for _, word := range slices.Sorted(maps.Keys(psMutatorParameters)) {
		for _, param := range psMutatorParameters[word] {
			k, seen := at[param.name]
			if !seen {
				at[param.name] = len(all)
				param.aliases = slices.Clone(param.aliases)
				all = append(all, param)
				continue
			}
			for _, alias := range param.aliases {
				if !slices.Contains(all[k].aliases, alias) {
					all[k].aliases = append(all[k].aliases, alias)
				}
			}
		}
	}
	return all
}()

// psMatchParameters returns the parameters of params that name binds: the
// one it spells (a name or an alias), else each one whose name or alias it
// starts, once.
func psMatchParameters(params []psParameter, name string) []psParameter {
	spells := func(text string) bool { return strings.EqualFold(text, name) }
	starts := func(text string) bool {
		return len(name) <= len(text) && strings.EqualFold(text[:len(name)], name)
	}
	for _, param := range params {
		if spells(param.name) || slices.ContainsFunc(param.aliases, spells) {
			return []psParameter{param}
		}
	}
	var matches []psParameter
	for _, param := range params {
		if starts(param.name) || slices.ContainsFunc(param.aliases, starts) {
			matches = append(matches, param)
		}
	}
	return matches
}

// psParameterReadings reads the parameters of a mutator statement as its
// cmdlet binds them (psMutatorParameters). A name, alias or prefix that
// names one parameter of the cmdlet is that parameter, spelled out: -L and
// -LP are -LiteralPath, -Fi of Out-File is -FilePath (rel-1-0-10:GAP-1232).
// PowerShell refuses the statement for any other word, but a parameter the
// table lacks would bind, so each is read on as the parameters it may stand
// for: those of the cmdlet it starts, else those of any mutator
// (psAnyMutatorParameters). When one of them is a switch or names a path,
// or it starts none, the word is read without it alone and without it and
// its value, and the form keeps its proof (checker it15 RV15-2). When all
// of them take a value that names no path (-t of mv: ItemType, Value,
// ToSession), it binds, if at all, with the next word as its value, and
// plain is the statement without both: the Windows PowerShell reader skips
// such a parameter and reads its value as an operand, so mv -t <folder>
// <file> moved the folder (rel-1-0-10:GAP-1209). A word spelled with its
// value (-T:x) drops as one word.
//
// plain is the statement that stands for form, form itself unless a word
// was dropped; readings are the others, none for a statement whose
// parameters all bind as written. bounded reports too many to read.
func psParameterReadings(form string) (readings []string, plain string, bounded bool) {
	budget := &psBudget{}
	words := psWords(form, budget)
	if budget.over {
		return nil, form, true
	}
	if len(words) < 2 {
		return nil, form, false
	}
	params, mutator := psMutatorParameters[strings.ToLower(words[0].text)]
	if !mutator {
		return nil, form, false
	}
	texts := make([]string, len(words))
	// dropped marks the words plain leaves out (a value-only word and its
	// value); unknown, the words read both ways; joined, words that carry
	// their value (-Name:value).
	dropped := make([]bool, len(words))
	joined := make([]bool, len(words))
	var unknown []int
	changed := false
	for k, word := range words {
		texts[k] = word.text
		if k == 0 || dropped[k] || word.quoted || len(word.text) < 2 || word.text[0] != '-' {
			continue
		}
		c := word.text[1]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			continue
		}
		name, value, hasValue := strings.Cut(word.text[1:], ":")
		joined[k] = hasValue
		matches := psMatchParameters(params, name)
		if len(matches) == 1 {
			full := matches[0].name
			switch {
			case hasValue:
				// -Name:value binds as -Name value, and a switch bound to
				// anything but $true is off; the readers know only the
				// spaced form, so the colon form dropped the proof (checker
				// it16 RV16-1).
				texts[k] = "-" + full
				if matches[0].isSwitch {
					if !strings.EqualFold(value, "$true") && value != "1" {
						texts[k] = ""
					}
				} else if value != "" {
					texts[k] += " " + value
				}
				changed = true
			case !strings.EqualFold(full, name):
				texts[k] = "-" + full
				changed = true
			}
			continue
		}
		if len(matches) == 0 {
			matches = psMatchParameters(psAnyMutatorParameters, name)
		}
		if len(matches) == 0 || slices.ContainsFunc(matches, func(param psParameter) bool {
			return param.isSwitch || param.path
		}) {
			unknown = append(unknown, k)
			continue
		}
		dropped[k] = true
		if !hasValue && k+1 < len(words) {
			dropped[k+1] = true
		}
	}
	const maxUnknown = 8
	if len(unknown) > maxUnknown {
		return nil, form, true
	}
	without := func(skip, count int) string {
		parts := make([]string, 0, len(texts))
		for k, text := range texts {
			if text != "" && !dropped[k] && (k < skip || k >= skip+count) {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, " ")
	}
	plain = form
	if slices.Contains(dropped, true) {
		plain = without(len(texts), 0)
	} else if changed {
		readings = append(readings, without(len(texts), 0))
	}
	for _, k := range unknown {
		readings = append(readings, without(k, 1))
		if !joined[k] && k+1 < len(texts) && !dropped[k+1] {
			readings = append(readings, without(k, 2))
		}
	}
	return readings, plain, false
}

// psStateScanMaxRunes bounds the text the PowerShell reading copies into
// pieces and argument lists; psNestedShellDepth bounds powershell -Command
// bodies read inside each other. Ordinary commands stay far below both; a
// crafted command past one is judged the write (RV14-2).
const (
	psStateScanMaxRunes = 1 << 20
	psStateScanMaxSteps = 1 << 22
	psNestedShellDepth  = 3
)

// psBudget is the one copy and work budget of a whole reading: the
// command, every word split, every unquote and every nested shell body
// share it, so balanced nesting cannot multiply the work (checker it15
// RV15-1). Past it the reading is bounded.
type psBudget struct {
	copied, steps int
	over          bool
}

func (b *psBudget) step() bool {
	b.steps++
	if b.steps > psStateScanMaxSteps {
		b.over = true
	}
	return !b.over
}

func newPSScan(runes []rune, budget *psBudget) *psStateScan {
	if budget == nil {
		budget = &psBudget{}
	}
	return &psStateScan{runes: runes, budget: budget}
}

// powerShellStateWriteForms returns the PowerShell twins of command that
// name DefenseClaw (see provenPowerShellStateWrite), deduplicated. A
// powershell or pwsh -Command body is read as PowerShell too. bounded
// reports a command past the reading bounds. ok is false when PowerShell
// cannot parse the command: a < that starts a token is a parse error there
// (a Git Bash here-document or input redirect), so nothing runs in that
// reading. mentions, when not nil, also places text in the state (psMerger).
// unknown are the twins of the files a .NET open may write, by a mode or a
// path known only at run time: such a twin that proves the write is the
// unknown tier, not the write (rel-1-0-10:GAP-1138); so are the twins of the
// protected files a wildcard path of a write cmdlet may match
// (rel-1-0-10:GAP-1272). placed are the files of those twins the hook client
// placed, with the paths it placed them at (psWildcardElementTwins).
func powerShellStateWriteForms(command, home, cwd string, targets map[string]string, mentions func(string) bool, protected psProtectedPaths) (forms, unknown []string, placed map[string]string, bounded, ok bool) {
	seen := map[string]bool{}
	budget := &psBudget{}
	merge := newPSMerger(home, cwd, targets)
	merge.mentions = mentions
	placed = map[string]string{}
	reading := psReading{merge: merge, unknown: &unknown, protected: protected, targets: targets, placed: placed}
	bounded, ok = reading.collect(command, 0, true, seen, &forms, budget)
	return forms, unknown, placed, bounded, ok
}

// psReading is the user home, working directory and known links a command
// is read in, where it adds the twins of the files a .NET open may write, and
// the protected files a wildcard path may match, with the hook client's
// resolved targets and the twin files placed from them.
type psReading struct {
	merge     psMerger
	unknown   *[]string
	protected psProtectedPaths
	targets   map[string]string
	placed    map[string]string
}

// addUnknown adds the twin of a file a .NET open may write, once.
func (reading psReading) addUnknown(form string, seen map[string]bool) {
	key := "\x00" + form
	if !seen[key] && reading.merge.namesState(form) {
		seen[key] = true
		*reading.unknown = append(*reading.unknown, form)
	}
}

// collect adds the state-naming twins of command to forms. A command with a
// variable bound to a string is also read with the value in place of each
// use (psBindStaticValues); bind is false for that reading, which has no
// use left to bind.
func (reading psReading) collect(command string, depth int, bind bool, seen map[string]bool, forms *[]string, budget *psBudget) (bool, bool) {
	scan := newPSScan([]rune(command), budget)
	scan.code(0, false)
	if scan.overBound() {
		return true, true
	}
	if scan.parseError {
		return false, false
	}
	add := func(form string) {
		form = strings.TrimSpace(form)
		if form == "" || seen[form] || psOutputOnly(form) || !reading.merge.namesState(form) {
			return
		}
		seen[form] = true
		*forms = append(*forms, form)
	}
	if bind {
		readings := psBindStaticValues(command, reading.merge, budget)
		if budget.over {
			return true, true
		}
		for _, bound := range readings {
			if bounded, _ := reading.collect(bound, depth, false, seen, forms, budget); bounded {
				return true, true
			}
		}
	}
	for _, piece := range scan.pieces {
		add(piece)
		// A write cmdlet writes every item its path pattern matches
		// (rel-1-0-10:GAP-1272).
		if reading.merge.namesState(piece) {
			for _, form := range psWildcardWriteTwins(piece, reading, budget) {
				reading.addUnknown(form, seen)
			}
		}
		for _, target := range psPatchRunTargets(piece, reading.merge, budget) {
			add("Set-Content -LiteralPath " + target + " -Value x")
		}
		body, nested := psNestedShellBody(piece, budget)
		if budget.over {
			return true, true
		}
		if !nested || !reading.merge.namesState(body) {
			continue
		}
		if depth >= psNestedShellDepth {
			return true, true
		}
		// A body PowerShell cannot parse runs nothing; only its bound counts.
		if bounded, _ := reading.collect(body, depth+1, true, seen, forms, budget); bounded {
			return true, true
		}
	}
	for _, body := range scan.bodies {
		if !reading.merge.namesState(body) {
			continue
		}
		if depth >= psNestedShellDepth {
			return true, true
		}
		if bounded, _ := reading.collect(body, depth+1, true, seen, forms, budget); bounded {
			return true, true
		}
	}
	for _, target := range scan.targets {
		add("Set-Content -LiteralPath " + target + " -Value x")
	}
	// A .NET open that writes is read as the write of its file; one whose
	// mode or path is known only at run time may write it (rel-1-0-10:GAP-1138).
	for _, open := range scan.opens {
		form := "Set-Content " + psHomeLiteralParam(open.param, reading.merge.home) + " -Value x"
		if !open.unknown {
			add(form)
		} else {
			reading.addUnknown(form, seen)
		}
		// A write of a folder's children (or a DirectoryInfo's) may write
		// every file it holds (rel-1-0-10:GAP-1257).
		if open.folder {
			if folder := psFolderTwin(open.param, reading.merge.home); folder != "" {
				reading.addUnknown(folder, seen)
			}
		}
	}
	for _, text := range scan.dynamicPaths {
		for _, form := range psDynamicPathReadings(text, reading.merge.home, budget) {
			reading.addUnknown(form, seen)
		}
	}
	if scan.unplaced {
		// A FileInfo or System.IO write the reader cannot place may write
		// any file the command spells (rel-1-0-10:GAP-1230), or any file a
		// folder it spells holds (Get-ChildItem -Recurse f | ForEach-Object
		// { $_.Delete() }, rel-1-0-10:GAP-1257).
		for _, form := range psDynamicPathReadings(command, reading.merge.home, budget) {
			reading.addUnknown(form, seen)
			if param, ok := strings.CutPrefix(strings.TrimSuffix(form, " -Value x"), "Set-Content "); ok {
				if folder := psFolderTwin(param, reading.merge.home); folder != "" {
					reading.addUnknown(folder, seen)
				}
			}
		}
	}
	if budget.over {
		return true, true
	}
	return false, true
}

// psOutputOnly reports a statement whose command only writes to the output
// streams (Write-Host "defenseclaw step 3"); its own reading cannot mutate
// state, and a redirect of it is judged as its own target, so it is not a
// twin and does not count toward the bound (checker it14 B40).
func psOutputOnly(form string) bool {
	word := form
	if index := strings.IndexAny(form, " \t\r\n"); index >= 0 {
		word = form[:index]
	}
	switch strings.ToLower(word) {
	case "write-host", "write-output", "echo", "write", "write-verbose",
		"write-debug", "write-warning", "write-information", "write-error":
		return true
	}
	return false
}

// psWord is one whitespace-separated word of a PowerShell statement.
type psWord struct {
	start  int // rune index in the statement
	text   string
	quoted bool
}

// psWords splits a statement into words at blanks outside quotes.
func psWords(statement string, budget *psBudget) []psWord {
	r := []rune(statement)
	scan := newPSScan(r, budget)
	var words []psWord
	for i := 0; i < len(r) && scan.budget.step(); {
		if r[i] == ' ' || r[i] == '\t' || r[i] == '\r' || r[i] == '\n' {
			i++
			continue
		}
		start := i
		for i < len(r) && r[i] != ' ' && r[i] != '\t' && r[i] != '\r' && r[i] != '\n' && scan.budget.step() {
			switch {
			case r[i] == '`':
				i += 2
			case psSingleQuote(r[i]):
				i = scan.singleQuoted(i)
			case psDoubleQuote(r[i]):
				i = scan.doubleQuoted(i)
			default:
				i++
			}
		}
		if i > len(r) {
			i = len(r)
		}
		words = append(words, psWord{start: start, text: string(r[start:i]),
			quoted: psSingleQuote(r[start]) || psDoubleQuote(r[start])})
	}
	return words
}

// psUnquote removes the outer quotes of one quoted word as PowerShell does
// when it passes it to a program: a doubled quote and a backtick escape
// become the character.
func psUnquote(word string, budget *psBudget) string {
	r := []rune(word)
	if len(r) < 2 || !psQuotedWord(word, budget) {
		return word
	}
	single := psSingleQuote(r[0])
	var out []rune
	for i := 1; i < len(r)-1; i++ {
		switch {
		case single && psSingleQuote(r[i]) && i+1 < len(r)-1 && psSingleQuote(r[i+1]):
			out = append(out, r[i])
			i++
		case !single && r[i] == '`' && i+1 < len(r)-1:
			out = append(out, r[i+1])
			i++
		case !single && psDoubleQuote(r[i]) && i+1 < len(r)-1 && psDoubleQuote(r[i+1]):
			out = append(out, r[i])
			i++
		default:
			out = append(out, r[i])
		}
	}
	return string(out)
}

// psNestedShellBody returns the script a powershell or pwsh call in
// statement runs with -Command (or as its first positional argument), after
// the outer shell's quote removal: powershell -Command "Set-Content STATE x"
// writes state as the inner Set-Content does (checker it14, GAP-2414).
func psNestedShellBody(statement string, budget *psBudget) (string, bool) {
	// Only a statement that names a shell or a string runner is split into
	// words (checker it15 RV15-1: every piece was tokenized).
	lower := strings.ToLower(statement)
	if !strings.Contains(lower, "powershell") && !strings.Contains(lower, "pwsh") &&
		!strings.Contains(lower, "iex") && !strings.Contains(lower, "invoke-expression") {
		return "", false
	}
	words := psWords(statement, budget)
	if len(words) == 0 || budget.over {
		return "", false
	}
	body := func(rest []psWord) string {
		if len(rest) == 1 {
			return psUnquote(rest[0].text, budget)
		}
		parts := make([]string, 0, len(rest))
		for _, word := range rest {
			parts = append(parts, psUnquote(word.text, budget))
		}
		return strings.Join(parts, " ")
	}
	program := psProgramName(psUnquote(words[0].text, budget))
	switch program {
	case "iex", "invoke-expression":
		// Invoke-Expression runs its string in this session as a -Command
		// body (checker it15 RV15-2).
		for k := 1; k < len(words); k++ {
			name, value, _ := strings.Cut(words[k].text, ":")
			name = strings.ToLower(name)
			if !words[k].quoted && strings.HasPrefix(name, "-") {
				if len(name) >= 2 && strings.HasPrefix("-command", name) {
					// -Command:'...' binds the string in the same word
					// (checker it16 RV16-2).
					if value != "" {
						return body([]psWord{{text: value}}), true
					}
					if k+1 < len(words) {
						return body(words[k+1 : k+2]), true
					}
				}
				continue
			}
			return body(words[k : k+1]), true
		}
		return "", false
	case "start-process", "saps", "start":
		return psStartProcessShellBody(words, budget)
	case "powershell", "pwsh":
	default:
		return "", false
	}
	return psShellArgumentsBody(words, body)
}

// psProgramName is the lower-case command name of a program word, without
// its directory and .exe.
func psProgramName(word string) string {
	program := strings.ToLower(word)
	if index := strings.LastIndexAny(program, `\/`); index >= 0 {
		program = program[index+1:]
	}
	return strings.TrimSuffix(program, ".exe")
}

// psPipedInvokeBody returns the string a pipeline element runs when it is
// Invoke-Expression (iex) and the element before it is one string:
// 'Clear-Content STATE' | iex runs Clear-Content (checker it16 RV16-2).
func psPipedInvokeBody(from, element string, budget *psBudget) (string, bool) {
	word := strings.TrimSpace(element)
	if index := strings.IndexAny(word, " \t\r\n"); index >= 0 {
		word = word[:index]
	}
	if program := psProgramName(word); program != "iex" && program != "invoke-expression" {
		return "", false
	}
	from = strings.TrimSpace(from)
	if !psQuotedWord(from, budget) {
		return "", false
	}
	return psUnquote(from, budget), true
}

// psStartProcessStatement reports a statement (so far) whose command is
// Start-Process or one of its aliases; only its first word is read.
func psStartProcessStatement(cur []rune) bool {
	k := 0
	for k < len(cur) && (cur[k] == ' ' || cur[k] == '\t' || cur[k] == '\r') {
		k++
	}
	end := k
	for end < len(cur) && end-k <= len("start-process") && cur[end] != ' ' && cur[end] != '\t' {
		end++
	}
	switch strings.ToLower(string(cur[k:end])) {
	case "start-process", "saps", "start":
		return true
	}
	return false
}

// psJoinListWords joins the words of a comma list written with blanks
// ('-c', 'x' or "-c" ,"x") and of a (...) or @(...) array into one word, as
// PowerShell binds them to one parameter (checker it16 RV16-2).
func psJoinListWords(words []psWord, budget *psBudget) []psWord {
	out := make([]psWord, 0, len(words))
	for k := 0; k < len(words); k++ {
		word := words[k]
		depth := psParenDelta(word.text, budget)
		for k+1 < len(words) && budget.step() &&
			(strings.HasSuffix(word.text, ",") || strings.HasPrefix(words[k+1].text, ",") || depth > 0) {
			k++
			word.text += " " + words[k].text
			depth += psParenDelta(words[k].text, budget)
		}
		out = append(out, word)
	}
	return out
}

// psParenDelta is the count of ( minus ) of word outside its strings.
func psParenDelta(word string, budget *psBudget) int {
	r := []rune(word)
	scan := newPSScan(r, budget)
	delta := 0
	for i := 0; i < len(r) && budget.step(); i++ {
		switch {
		case r[i] == '`':
			i++
		case psSingleQuote(r[i]):
			i = scan.singleQuoted(i) - 1
		case psDoubleQuote(r[i]):
			i = scan.doubleQuoted(i) - 1
		case r[i] == '(':
			delta++
		case r[i] == ')':
			delta--
		}
	}
	return delta
}

// psArrayBody returns the elements of a (...) or @(...) array literal, or
// text itself.
func psArrayBody(text string) string {
	t := strings.TrimPrefix(strings.TrimSpace(text), "@")
	if len(t) >= 2 && t[0] == '(' && t[len(t)-1] == ')' {
		return t[1 : len(t)-1]
	}
	return text
}

// psStartProcessShellBody returns the script a Start-Process of powershell
// or pwsh runs: its -ArgumentList (a string or a comma list, joined with
// spaces as Start-Process does) is the shell's argument line (checker it15
// RV15-2).
func psStartProcessShellBody(words []psWord, budget *psBudget) (string, bool) {
	file, arguments, _ := psStartProcessParts(psJoinListWords(words, budget), budget)
	program := psProgramName(psUnquote(file, budget))
	if program != "powershell" && program != "pwsh" || arguments == "" {
		return "", false
	}
	var parts []string
	for _, part := range psSplitArguments(psArrayBody(arguments), budget) {
		if part == "" {
			return "", false
		}
		parts = append(parts, psUnquote(part, budget))
	}
	line := strings.Join(parts, " ")
	inner := psWords("powershell "+line, budget)
	return psShellArgumentsBody(inner, func(rest []psWord) string {
		texts := make([]string, 0, len(rest))
		for _, word := range rest {
			texts = append(texts, psUnquote(word.text, budget))
		}
		return strings.Join(texts, " ")
	})
}

// psStartProcessParts returns the program (-FilePath or the first positional
// word), the argument list (-ArgumentList or the second positional word) and
// the positional words left over of a Start-Process call whose words (the
// cmdlet first, comma lists joined) are words.
func psStartProcessParts(words []psWord, budget *psBudget) (file, arguments string, positional []string) {
	for k := 1; k < len(words); k++ {
		name, _, hasValue := strings.Cut(strings.ToLower(words[k].text), ":")
		if words[k].quoted || !strings.HasPrefix(name, "-") || len(name) < 2 {
			positional = append(positional, words[k].text)
			continue
		}
		if !hasValue && psStartProcessSwitch(name) {
			continue
		}
		var value string
		if !hasValue {
			if k+1 >= len(words) {
				break
			}
			k++
			value = words[k].text
		} else {
			value = words[k].text[len(name)+1:]
		}
		switch {
		case strings.HasPrefix("-filepath", name), name == "-pspath", name == "-path":
			file = value
		case len(name) >= 2 && strings.HasPrefix("-argumentlist", name), name == "-args":
			arguments = value
		}
	}
	if file == "" && len(positional) > 0 {
		file, positional = positional[0], positional[1:]
	}
	if arguments == "" && len(positional) > 0 {
		arguments, positional = positional[0], positional[1:]
	}
	return file, arguments, positional
}

// psStartProcessSwitch reports a Start-Process switch parameter (no value).
func psStartProcessSwitch(name string) bool {
	for _, full := range []string{"-wait", "-nonewwindow", "-passthru", "-usenewenvironment", "-loaduserprofile"} {
		if len(name) >= 3 && strings.HasPrefix(full, name) {
			return true
		}
	}
	return false
}

// psShellArgumentsBody returns the -Command body of a powershell or pwsh
// call whose words (program first) are words.
func psShellArgumentsBody(words []psWord, body func([]psWord) string) (string, bool) {
	for k := 1; k < len(words); k++ {
		lower := strings.ToLower(words[k].text)
		if words[k].quoted || !strings.HasPrefix(lower, "-") {
			return body(words[k:]), true
		}
		name, _, _ := strings.Cut(lower, ":")
		switch {
		case name == "-c" || len(name) >= 4 && strings.HasPrefix("-command", name):
			if k+1 >= len(words) {
				return "", false
			}
			return body(words[k+1:]), true
		case name == "-f" || len(name) >= 3 && strings.HasPrefix("-file", name),
			name == "-e" || name == "-ec" || len(name) >= 3 && strings.HasPrefix("-encodedcommand", name):
			return "", false
		case psShellValueOption(name):
			k++
		}
	}
	return "", false
}

// psShellValueOption reports a powershell/pwsh option that takes the next
// word as its value.
func psShellValueOption(name string) bool {
	switch name {
	case "-ep", "-ex", "-exec", "-if", "-inp", "-of", "-o", "-w", "-win",
		"-config", "-wd", "-settings", "-v", "-version", "-psconsolefile",
		"-custompipename", "-configurationname", "-settingsfile",
		"-workingdirectory", "-inputformat", "-outputformat":
		return true
	}
	return len(name) >= 5 && (strings.HasPrefix("-executionpolicy", name) ||
		strings.HasPrefix("-windowstyle", name))
}

// psStateScan reads a command in the PowerShell grammar: strings (also the
// typographic quotes PowerShell accepts), here-strings, comments, backtick
// escapes, the --% stop-parsing tail, $(...) inside double quotes and
// braced variable names.
type psStateScan struct {
	runes      []rune
	pieces     []string
	targets    []string
	bodies     []string // strings piped into Invoke-Expression
	parseError bool
	budget     *psBudget
	// The .NET file opens of the command (psDotNetCall): the twin
	// parameter of each file one writes, or may write (unknown), and the
	// text of each path argument known only at run time.
	opens        []psOpenTarget
	dynamicPaths []string
	// The placed bindings of the variables bound to a FileInfo, in
	// reading order, and the variables bound to a file stream (with the
	// twin parameter of the file), by lower-case name.
	fileInfos map[string][]psFileInfo
	streams   map[string]string
	// groupClose is the index after the ) of the last (...) group read: a
	// method called on it is called on what the group evaluates to.
	// groupCall reports that group as the argument list of a call
	// ([IO.FileInfo]::new(f).OpenWrite()), whose result is groupFile, the
	// FileInfo it returns (unplaced for none known).
	groupOpen, groupClose int
	groupCall             bool
	groupFile             psFileInfo
	// unplaced reports a FileInfo or System.IO write the reader cannot
	// place (psFileInfoMethod): every file the command spells may be the
	// one it writes, the unknown tier (rel-1-0-10:GAP-1230).
	unplaced bool
	// braces is the depth of the { blocks being read. item is where the
	// pipeline item ($_) of the ForEach-Object block at depth itemDepth
	// (0 for none), whose body starts at itemOpen, is placed; itemUses
	// counts the methods called on it (psStateScan.openBlock).
	braces, itemDepth, itemOpen, itemUses int
	item                                  psFileInfo
	// lower is the command in lower case, read once; uses caches
	// psVariableUses of it by variable; dynamic caches dynamicVariables
	// (0 not read, 1 no, 2 yes).
	lower   string
	uses    map[string]psVariableCount
	dynamic int
}

func (s *psStateScan) overBound() bool { return s.budget.over }

// account adds n copied runes and reports the reading still within bound.
func (s *psStateScan) account(n int) bool {
	s.budget.copied += n
	if s.budget.copied > psStateScanMaxRunes {
		s.budget.over = true
	}
	return !s.budget.over
}

func psSingleQuote(r rune) bool {
	return r == '\'' || r == '\u2018' || r == '\u2019' || r == '\u201a' || r == '\u201b'
}

func psDoubleQuote(r rune) bool {
	return r == '"' || r == '\u201c' || r == '\u201d' || r == '\u201e'
}

func psTokenBreak(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n' || strings.ContainsRune(";|&(){}", r)
}

// tokenStart reports whether index i starts a token.
func (s *psStateScan) tokenStart(i int) bool {
	return i == 0 || psTokenBreak(s.runes[i-1])
}

// code scans statements from i to the end, or to the ) that closes the
// enclosing ( when nested, and returns the index after it. Every statement
// and pipeline element becomes a piece; a nested (...), $(...) or @(...)
// body is a piece of its own.
func (s *psStateScan) code(i int, nested bool) int {
	r := s.runes
	var cur []rune
	var last, pipedFrom string
	// whole reports the pipeline element being read not cut by a group, a
	// block or a call since it started; lastWhole and pipedWhole are that of
	// last and pipedFrom, also fed by no pipeline (rel-1-0-10:GAP-1275).
	whole, lastWhole, pipedWhole := true, false, false
	// start is the rune index the statement in cur starts at.
	start := i
	var statementWordKnown, statementArgumentMode bool
	firstScanned := 0
	commentStarts := func(i int) bool {
		if !statementWordKnown {
			for firstScanned < len(cur) {
				first := cur[firstScanned]
				firstScanned++
				if !unicode.IsSpace(first) {
					statementArgumentMode = actionfacts.PowerShellStatementCommandWord(cur, firstScanned-1)
					statementWordKnown = true
					break
				}
			}
		}
		return actionfacts.PowerShellCommentStarts(r, i, !statementArgumentMode)
	}
	flush := func() {
		text := string(cur)
		if strings.TrimSpace(text) != "" && s.account(len(cur)) {
			s.pieces = append(s.pieces, text)
			// A statement read whole ends at a ; or a line, a block or group
			// close or the end of the code (copyFileInfo).
			s.dotNetStatement(text, start, i >= len(r) || strings.ContainsRune("\n;})", r[i]))
			if pipedFrom != "" {
				if body, ok := psPipedInvokeBody(pipedFrom, text, s.budget); ok {
					s.bodies = append(s.bodies, body)
				}
				// A program reads what is piped into it: an envelope piped
				// into apply_patch is the patch it applies, as when it is
				// the argument (GAP-1023 IB34). The run is read as a piece
				// with the piped text as its argument.
				if strings.Contains(pipedFrom, "*** ") && psRunsPatch(psWords(text, s.budget), s.budget) &&
					s.account(len(cur)+len(pipedFrom)+1) {
					s.pieces = append(s.pieces, strings.TrimSpace(text)+" "+strings.TrimSpace(pipedFrom))
				}
			}
		}
		last, lastWhole = text, whole && pipedFrom == ""
		pipedFrom, pipedWhole = "", false
		cur = cur[:0]
		statementWordKnown, statementArgumentMode = false, false
		firstScanned = 0
	}
	for i < len(r) && !s.parseError && s.budget.step() {
		if len(cur) == 0 {
			start = i
		}
		c := r[i]
		comment := (c == '#' || c == '<' && i+1 < len(r) && r[i+1] == '#') && commentStarts(i)
		switch {
		case c == '`':
			cur = append(cur, c)
			if i+1 < len(r) {
				cur = append(cur, r[i+1])
			}
			i += 2
		case c == '|':
			// A string piped into Invoke-Expression runs as its body
			// (checker it16 RV16-2).
			flush()
			whole = true
			if i+1 < len(r) && r[i+1] == '|' {
				i += 2
				continue
			}
			pipedFrom, pipedWhole = last, lastWhole
			i++
		case c == '{':
			// A ForEach-Object block places its pipeline item at what
			// feeds it (rel-1-0-10:GAP-1257).
			s.openBlock(string(cur), pipedFrom, pipedWhole, i)
			flush()
			whole = true
			i++
		case c == '}':
			flush()
			s.closeBlock(i)
			// What follows the block is still the element it is in.
			whole = false
			i++
		case c == '\n' || c == ';' || c == '&':
			flush()
			whole = true
			i++
		case c == ')':
			flush()
			if nested {
				return i + 1
			}
			whole = false
			i++
		case c == '(':
			tail := cur
			if len(tail) > 32 {
				tail = tail[len(tail)-32:]
			}
			method := strings.ToLower(strings.TrimRight(string(tail), " \t"))
			statement := string(cur)
			// A method called on the group just read (.AppendText() of
			// (Get-Item f)) is called on what the group evaluates to.
			onGroup := s.groupClose > 0 && s.groupClose < i && r[s.groupClose] == '.' &&
				strings.TrimSpace(statement) == string(r[s.groupClose:i])
			groupOpen, groupClose, groupCall, groupFile := s.groupOpen, s.groupClose, s.groupCall, s.groupFile
			// A ( glued to a name is the argument list of a call.
			call := i > 0 && r[i-1] < unicode.MaxASCII && psVariableNameByte(byte(r[i-1]))
			// A Start-Process statement keeps its (...) and @(...)
			// argument arrays, so the -ArgumentList it runs is read
			// (checker it16 RV16-2); the body is still scanned as a piece.
			keep := psStartProcessStatement(cur)
			if !keep {
				flush()
			}
			whole = false
			end := s.code(i+1, true)
			if s.overBound() {
				return len(r)
			}
			if keep && s.account(end-i) {
				cur = append(cur, r[i:end]...)
			}
			var receiver *psReceiver
			switch {
			case onGroup && groupCall:
				receiver = &psReceiver{file: groupFile, call: true}
			case onGroup && s.account(groupClose-groupOpen):
				receiver = &psReceiver{text: string(r[groupOpen+1 : groupClose-1])}
			}
			file := s.dotNetCall(method, statement, receiver, i, end)
			s.groupOpen, s.groupClose, s.groupCall, s.groupFile = i, end, call, file
			i = end
		case c == '#' && comment:
			for i < len(r) && r[i] != '\n' {
				i++
			}
		case c == '<' && i+1 < len(r) && r[i+1] == '#' && !comment:
			// Glued <#...#> stays inside the argument word. Read through
			// its closing marker so its > cannot become a redirect.
			j := i + 2
			for j+1 < len(r) && (r[j] != '#' || r[j+1] != '>') && s.budget.step() {
				j++
			}
			if j+1 < len(r) {
				j += 2
			} else {
				j = len(r)
			}
			cur = append(cur, r[i:j]...)
			i = j
		case c == '<' && i+1 < len(r) && r[i+1] == '#' && comment:
			// A block comment ends at the first #>; one pass over the
			// runes (RV14-2). An unterminated one runs to the end.
			j := i + 2
			for j+1 < len(r) && (r[j] != '#' || r[j+1] != '>') && s.budget.step() {
				j++
			}
			i = j + 2
			if i > len(r) {
				i = len(r)
			}
		case c == '<' && s.tokenStart(i):
			s.parseError = true
			return len(r)
		case c == '-' && s.tokenStart(i) && i+2 < len(r) && r[i+1] == '-' && r[i+2] == '%':
			for i < len(r) && r[i] != '\n' {
				cur = append(cur, r[i])
				i++
			}
		case c == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && s.hereStringOpen(i+2):
			end := s.hereString(i)
			if s.overBound() {
				return len(r)
			}
			cur = append(cur, r[i:end]...)
			i = end
		case psSingleQuote(c):
			end := s.singleQuoted(i)
			cur = append(cur, r[i:end]...)
			i = end
		case psDoubleQuote(c):
			end := s.doubleQuoted(i)
			if s.overBound() {
				return len(r)
			}
			cur = append(cur, r[i:end]...)
			i = end
		case c == '$' && i+1 < len(r) && r[i+1] == '{':
			end := i + 2
			for end < len(r) && r[end] != '}' {
				if r[end] == '`' {
					end++
				}
				end++
			}
			if end >= len(r) {
				cur = append(cur, r[i:]...)
				i = len(r)
				continue
			}
			name := string(r[i+2 : end])
			cur = append(cur, r[i:end+1]...)
			i = end + 1
			if target, ok := psProviderPathLiteral(name); ok && s.assignmentAt(i) {
				s.targets = append(s.targets, target)
			}
		case c == '>':
			// The redirect target is judged as its own write (below); the
			// piece keeps only the command, so a stream redirect such as
			// 2>$null or 2>&1 does not leave the cmdlet's own reading
			// partial (checker it14 class rows).
			if len(cur) > 0 && i > 0 && strings.ContainsRune("123456*", r[i-1]) && s.tokenStart(i-1) {
				cur = cur[:len(cur)-1]
			}
			i++
			if i < len(r) && r[i] == '>' {
				i++
			}
			if i < len(r) && r[i] == '&' {
				i++
				for i < len(r) && r[i] >= '0' && r[i] <= '9' {
					i++
				}
				continue
			}
			for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
				i++
			}
			start := i
			switch {
			case i < len(r) && psSingleQuote(r[i]):
				i = s.singleQuoted(i)
			case i < len(r) && psDoubleQuote(r[i]):
				i = s.doubleQuoted(i)
				if s.overBound() {
					return len(r)
				}
			default:
				for i < len(r) && !psTokenBreak(r[i]) && r[i] != '<' && r[i] != '>' {
					if r[i] == '`' {
						i++
					}
					i++
				}
				if i > len(r) {
					i = len(r)
				}
			}
			if i > start {
				if target := string(r[start:i]); !strings.EqualFold(target, "$null") {
					s.targets = append(s.targets, target)
				}
			}
		default:
			cur = append(cur, c)
			i++
		}
	}
	flush()
	return len(r)
}

// assignmentAt reports an assignment or increment operator after optional
// blanks at i: = (not ==), +=, -=, *=, /=, %=, ??=, ++ or --.
func (s *psStateScan) assignmentAt(i int) bool {
	r := s.runes
	for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
		i++
	}
	// Compare runes in place: converting the rest of the command for every
	// braced variable made the reading quadratic (RV14-2).
	at := func(op string) bool {
		k := i
		for _, c := range op {
			if k >= len(r) || r[k] != c {
				return false
			}
			k++
		}
		return true
	}
	for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "??=", "++", "--"} {
		if at(op) {
			return true
		}
	}
	return at("=") && !at("==")
}

// hereStringOpen reports that only blanks follow @' or @" to the end of the
// line, as a here-string header requires.
func (s *psStateScan) hereStringOpen(i int) bool {
	for ; i < len(s.runes); i++ {
		switch s.runes[i] {
		case ' ', '\t', '\r':
		case '\n':
			return true
		default:
			return false
		}
	}
	return false
}

// hereString returns the index after the here-string that starts at i (@'
// or @"): its body ends at a line that starts with the closing quote and @.
// An expandable body runs its $(...) subexpressions.
func (s *psStateScan) hereString(i int) int {
	r := s.runes
	expandable := psDoubleQuote(r[i+1])
	j := i + 2
	for j < len(r) && r[j] != '\n' {
		j++
	}
	lineStart := true
	for j < len(r) && s.budget.step() {
		if lineStart && j+1 < len(r) && r[j+1] == '@' &&
			(expandable && psDoubleQuote(r[j]) || !expandable && psSingleQuote(r[j])) {
			return j + 2
		}
		lineStart = r[j] == '\n'
		if expandable && r[j] == '`' {
			j += 2
			continue
		}
		if expandable && r[j] == '$' && j+1 < len(r) && r[j+1] == '(' {
			j = s.code(j+2, true)
			if s.overBound() {
				return len(r)
			}
			lineStart = false
			continue
		}
		j++
	}
	return len(r)
}

// singleQuoted returns the index after the single-quoted string at i; a
// doubled quote is an escaped one.
func (s *psStateScan) singleQuoted(i int) int {
	r := s.runes
	for j := i + 1; j < len(r) && s.budget.step(); j++ {
		if psSingleQuote(r[j]) {
			if j+1 < len(r) && psSingleQuote(r[j+1]) {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(r)
}

// doubleQuoted returns the index after the double-quoted string at i. A
// backtick or a doubled quote escapes; a $(...) subexpression runs.
func (s *psStateScan) doubleQuoted(i int) int {
	r := s.runes
	for j := i + 1; j < len(r) && s.budget.step(); j++ {
		switch {
		case r[j] == '`':
			j++
		case r[j] == '$' && j+1 < len(r) && r[j+1] == '(':
			j = s.code(j+2, true) - 1
			if s.overBound() {
				return len(r)
			}
		case psDoubleQuote(r[j]):
			if j+1 < len(r) && psDoubleQuote(r[j+1]) {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(r)
}

// psFileWriteMethod returns the argument positions a .NET file call writes,
// replaces or removes when prefix (lower case) ends with its name.
func psFileWriteMethod(prefix string) []int {
	for _, method := range []struct {
		name string
		args []int
	}{
		{"::writealltext", []int{0}}, {"::writeallbytes", []int{0}}, {"::writealllines", []int{0}},
		{"::appendalltext", []int{0}}, {"::appendalllines", []int{0}}, {"::appendtext", []int{0}},
		{"::createtext", []int{0}}, {"::create", []int{0}}, {"::openwrite", []int{0}},
		{"::delete", []int{0}}, {"::move", []int{0, 1}}, {"::copy", []int{1}},
		{"::replace", []int{0, 1, 2}},
	} {
		if strings.HasSuffix(prefix, method.name) {
			return method.args
		}
	}
	return nil
}

// psSplitArguments splits a .NET argument list at its top-level commas; an
// argument that is not one string or bare word is returned empty.
func psSplitArguments(text string, budget *psBudget) []string {
	args := psSplitArgumentTexts(text, budget)
	for k, arg := range args {
		if !psLiteralArgument(arg, budget) {
			args[k] = ""
		}
	}
	return args
}

// psLiteralArgument reports a .NET argument that is one string or bare word.
func psLiteralArgument(arg string, budget *psBudget) bool {
	return !strings.ContainsAny(arg, "()[]{} \t\r\n") || psQuotedWord(arg, budget)
}

// psSplitArgumentTexts splits a .NET argument list at its top-level commas
// and returns each argument's text, trimmed.
func psSplitArgumentTexts(text string, budget *psBudget) []string {
	r := []rune(text)
	scan := newPSScan(r, budget)
	var args []string
	depth, start := 0, 0
	for i := 0; i <= len(r); i++ {
		if i < len(r) {
			switch {
			case psSingleQuote(r[i]):
				i = scan.singleQuoted(i) - 1
				continue
			case psDoubleQuote(r[i]):
				i = scan.doubleQuoted(i) - 1
				continue
			case r[i] == '(' || r[i] == '[' || r[i] == '{':
				depth++
				continue
			case r[i] == ')' || r[i] == ']' || r[i] == '}':
				depth--
				continue
			case r[i] != ',' || depth != 0:
				continue
			}
		}
		args = append(args, strings.TrimSpace(string(r[start:i])))
		start = i + 1
	}
	return args
}

func psQuotedWord(arg string, budget *psBudget) bool {
	r := []rune(arg)
	if len(r) < 2 {
		return false
	}
	scan := newPSScan(r, budget)
	switch {
	case psSingleQuote(r[0]):
		return scan.singleQuoted(0) == len(r)
	case psDoubleQuote(r[0]):
		return scan.doubleQuoted(0) == len(r)
	}
	return false
}

// psProviderPathLiteral returns a single-quoted PowerShell literal of the
// file a braced variable name names on a drive (${C:\f}, ${c:/f}): the env,
// variable, function and alias drives and the scope modifiers name none.
func psProviderPathLiteral(name string) (string, bool) {
	colon := strings.IndexByte(name, ':')
	if colon <= 0 || colon+1 >= len(name) {
		return "", false
	}
	switch strings.ToLower(name[:colon]) {
	case "global", "local", "script", "private", "using", "workflow",
		"env", "variable", "function", "alias":
		return "", false
	}
	path := strings.ReplaceAll(strings.ReplaceAll(name, "``", "\x00"), "`", "")
	path = strings.ReplaceAll(path, "\x00", "`")
	if strings.ContainsAny(path, "\r\n") {
		return "", false
	}
	return "'" + strings.ReplaceAll(path, "'", "''") + "'", true
}

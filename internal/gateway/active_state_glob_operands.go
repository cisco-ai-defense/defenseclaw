// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// activeStateTreeNames are the protected trees directly under the state
// root; every entry in one is protected state (matchesActiveDefenseClawState).
var activeStateTreeNames = []string{
	"cache", "hooks", "installer", "policies", "previous", "quarantine", "receipts", "registries",
}

// activeStateFileNames are the protected files directly under the state root.
var activeStateFileNames = []string{
	".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
	"device.key", "picked_connector", "custom-providers.json", "audit.db",
	"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal", "judge.db-shm",
	"judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm",
}

// maxStateBraceExpansions bounds the brace alternatives one operand expands to.
const maxStateBraceExpansions = 64

// globbedStateMutation proves a removal, move or overwrite of the active
// state through an operand the shell expands before the program runs: a
// pathname pattern (`rm -rf ~/.defenseclaw/*`, `~/.defenseclaw/instal*`,
// `~/.defenseclaw/hooks/*`), a brace list (`~/.defenseclaw/{installer,hooks}`),
// a pattern copied into the state root (`cp /tmp/x/* ~/.defenseclaw/`), an
// rsync into it, and a git clean of it (GAP-2047). ActionFacts keeps such a
// word only as its static spelling, so these calls had no path fact and ran
// in every mode. A pattern counts when it could match a protected name (the
// shell's own matching, a leading dot only by an explicit dot); log and
// temp cleanup such as `rm ~/.defenseclaw/*.log` or
// `rm ~/.defenseclaw/logs/*` matches none and stays allowed.
func globbedStateMutation(facts actionfacts.Facts) bool {
	home := strings.TrimRight(facts.ActiveHome, "/")
	if !strings.HasPrefix(home, "/") {
		return false
	}
	dirs := posixCommandDirectories(facts, home)
	for index, command := range facts.Commands {
		if command.Effect == actionfacts.EffectPreview || command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		words, ok := stateOperandWords(command)
		// `sudo rm -rf hooks/*`: a glob operand keeps the wrapper call
		// whole (no wrapped command fact), so judge the program it runs
		// (pod check28 N5, N10, N13, N19).
		program, programWords := unwrapStateWrapper(command, words)
		// A relative operand names a path in a directory the command may
		// run in, after any earlier cd (pod check26, check27).
		for _, dir := range dirs[index] {
			// An unquoted -name/-path glob leaves find with no facts (GAP-2498).
			if findGlobStateMutation(facts, command, dir) ||
				ok && globbedStateCommandMutates(program, programWords, home, dir) {
				return true
			}
		}
	}
	return false
}

// stateWrapperValueOptions are the transparent wrappers whose program word
// follows their options, and the options of each that take the next word.
var stateWrapperValueOptions = map[string]map[string]bool{
	"sudo": {"-u": true, "-g": true, "-U": true, "-C": true, "-D": true, "-h": true,
		"-p": true, "-r": true, "-t": true, "-T": true, "-R": true},
	"doas":    {"-u": true, "-C": true},
	"env":     {"-u": true, "-C": true},
	"nice":    {"-n": true},
	"timeout": {"-s": true, "-k": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"nohup":   {},
	"time":    {},
	"command": {},
	"exec":    {"-a": true},
}

// unwrapStateWrapper is the program a transparent wrapper call runs and its
// words (`sudo -u root rm -rf a/*` -> rm, [-rf a/*]); the command itself
// when it is no such wrapper or its program word is not static.
func unwrapStateWrapper(command actionfacts.CommandFact, words []string) (actionfacts.CommandFact, []string) {
	for depth := 0; depth < 4; depth++ {
		program := path.Base(command.Program)
		valueOptions, wrapper := stateWrapperValueOptions[program]
		if !wrapper {
			break
		}
		index := 0
		for index < len(words) {
			word := words[index]
			if word == "--" {
				index++
				break
			}
			if program == "env" && !strings.HasPrefix(word, "-") && strings.Contains(word, "=") {
				index++
				continue
			}
			if !strings.HasPrefix(word, "-") || word == "-" {
				break
			}
			if program == "env" && (word == "-S" || strings.HasPrefix(word, "--split-string")) {
				return command, words
			}
			index++
			if valueOptions[word] {
				index++
			}
		}
		if program == "timeout" {
			index++
		}
		if index >= len(words) || words[index] == "" {
			return command, words
		}
		inner := command
		inner.Program = path.Base(words[index])
		command, words = inner, words[index+1:]
	}
	return command, words
}

// stateOperandWords returns the static spelling of each argument after the
// program word ("" for a word with no static spelling).
func stateOperandWords(command actionfacts.CommandFact) ([]string, bool) {
	if len(command.Arguments) == 0 || len(command.Arguments) != len(command.Argv) {
		return nil, false
	}
	words := make([]string, 0, len(command.Arguments)-1)
	for _, argument := range command.Arguments[1:] {
		value := argument.Value
		if value == "" {
			value = argument.StaticGlob
		}
		if value == "" {
			// `$HOME/.defenseclaw`, `--work-tree="$HOME"` (pod check27).
			value = argument.HomeSpelling()
		}
		words = append(words, value)
	}
	return words, true
}

func globbedStateCommandMutates(command actionfacts.CommandFact, words []string, home, cwd string) bool {
	operands, options := splitStateOperands(words)
	expanded := func(word string) bool { return stateWordExpands(word) }
	switch strings.ToLower(command.Program) {
	case "rm", "unlink", "rmdir", "shred":
		// A word with no static spelling (`$X`) can expand to nothing, so a
		// static state operand beside it is removed whatever it expands to
		// (`rm -rf ~/.defenseclaw/hooks $X`, GAP-2484; BALANCED rule 2).
		dynamic := slices.Contains(words, "")
		for _, operand := range operands {
			if (expanded(operand) || dynamic) && statePatternReaches(operand, home, cwd) {
				return true
			}
		}
	case "mv", "cp":
		destination, sources := copyMoveStateOperands(operands, options)
		if command.Program == "mv" {
			for _, source := range sources {
				if expanded(source) && statePatternReaches(source, home, cwd) {
					return true
				}
			}
		}
		if destination == "" {
			return false
		}
		for _, source := range sources {
			if expanded(source) && stateLandingReached(destination, path.Base(source), home, cwd) {
				return true
			}
			// `cp -r /tmp/x/. ~/.defenseclaw/`: the entries of x land in
			// the destination by their own names.
			if sourceNamesItsEntries(source) {
				if tree, root := stateDirectoryOf(destination, home, cwd); tree || root {
					return true
				}
			}
		}
		if expanded(destination) {
			for _, source := range sources {
				if stateLandingReached(destination, path.Base(strings.TrimRight(source, "/")), home, cwd) {
					return true
				}
			}
		}
	case "rsync":
		// An option value spelled as its own word (`--exclude cache/`) is
		// not a source.
		rsyncOperands, rsyncOptions := rsyncStateOperands(words)
		if len(rsyncOperands) < 2 {
			return false
		}
		destination := rsyncOperands[len(rsyncOperands)-1]
		if strings.Contains(destination, ":") {
			return false
		}
		deletes := slices.ContainsFunc(rsyncOptions, rsyncDeletes)
		tree, root := stateDirectoryOf(destination, home, cwd)
		if tree || root && deletes {
			return true
		}
		if !root {
			return false
		}
		// Into the root itself, each source lands by its name, and the
		// entries of a `dir/` or `dir/.` source by theirs, which can be
		// config.yaml or hooks/ (`rsync -a /tmp/x/ ~/.defenseclaw/`).
		for _, source := range rsyncOperands[:len(rsyncOperands)-1] {
			if strings.HasSuffix(source, "/") || sourceNamesItsEntries(source) ||
				stateLandingReached(destination, path.Base(source), home, cwd) {
				return true
			}
		}
	case "install":
		return installStateTarget(words, home, cwd)
	case "sort":
		return sortStateOutput(words, home, cwd)
	case "git":
		// A work tree on the state rewritten by another subcommand, or the
		// home work tree losing its untracked files (GAP-2485).
		if gitWorkTreeStateWrite(words, home, cwd) {
			return true
		}
		index := slices.Index(operands, "clean")
		if index < 0 || !slices.ContainsFunc(options, gitCleanForces) ||
			slices.ContainsFunc(options, gitCleanDryRun) {
			return false
		}
		// `git -C DIR clean` cleans from DIR, and its paths are under DIR.
		base, ok := gitCleanDirectory(words, home, cwd)
		if !ok {
			return false
		}
		paths := gitCleanPathspecs(words)
		if len(paths) == 0 {
			tree, root := stateDirectoryOf(base, home, cwd)
			return tree || root
		}
		for _, operand := range paths {
			if tree, root := stateDirectoryOf(operand, home, base); tree || root ||
				statePatternReaches(operand, home, base) {
				return true
			}
		}
	}
	return false
}

// rsyncValueOptions are the rsync long options whose value can be the
// next word.
var rsyncValueOptions = map[string]bool{
	"--exclude": true, "--include": true, "--filter": true, "--exclude-from": true,
	"--include-from": true, "--files-from": true, "--link-dest": true, "--compare-dest": true,
	"--copy-dest": true, "--backup-dir": true, "--partial-dir": true, "--temp-dir": true,
	"--suffix": true, "--rsh": true, "--rsync-path": true, "--chmod": true, "--chown": true,
	"--usermap": true, "--groupmap": true, "--max-size": true, "--min-size": true,
	"--max-delete": true, "--max-alloc": true, "--timeout": true, "--contimeout": true,
	"--bwlimit": true, "--log-file": true, "--log-file-format": true, "--out-format": true,
	"--password-file": true, "--port": true, "--sockopts": true, "--modify-window": true,
	"--block-size": true, "--checksum-choice": true, "--compress-choice": true,
	"--compress-level": true, "--skip-compress": true, "--iconv": true, "--info": true,
	"--debug": true, "--stop-after": true, "--stop-at": true, "--remote-option": true,
	"--checksum-seed": true, "--address": true, "--write-batch": true,
	"--only-write-batch": true, "--read-batch": true, "--early-input": true,
}

// rsyncStateOperands splits rsync words like splitStateOperands and skips
// the separately spelled value of an option that takes one (`--exclude
// cache/`, `-e ssh`, `-f "- x/"`, `-T /tmp`, `-B 1024`, `-M --x`).
func rsyncStateOperands(words []string) (operands, options []string) {
	optionsDone := false
	for index := 0; index < len(words); index++ {
		word := words[index]
		switch {
		case optionsDone:
			operands = append(operands, word)
		case word == "--":
			optionsDone = true
		case strings.HasPrefix(word, "--"):
			options = append(options, word)
			if !strings.Contains(word, "=") && rsyncValueOptions[word] {
				index++
			}
		case strings.HasPrefix(word, "-") && word != "-":
			options = append(options, word)
			if rsyncShortValueIsNextWord(word) {
				index++
			}
		default:
			operands = append(operands, word)
		}
	}
	return operands, options
}

// rsyncShortValueIsNextWord reads a short option cluster left to right:
// at its first letter that takes a value (e f T B M @) the rest of the word
// is that value (`-T/tmp/te`, `-aT/tmp/te`, `-essh-te`), and only when the
// letter ends the word is the value the next word (`-e ssh`, `-aT /tmp`).
// Reading only the last character made an attached value that happens to
// end in one of those letters swallow the real source (pod check18).
func rsyncShortValueIsNextWord(word string) bool {
	for index := 1; index < len(word); index++ {
		if strings.IndexByte("efTBM@", word[index]) >= 0 {
			return index == len(word)-1
		}
	}
	return false
}

// rsyncDeletes reports an rsync option that removes files: --del, --delete,
// --delete-* and --remove-source-files (not --delay-updates).
func rsyncDeletes(option string) bool {
	option, _, _ = strings.Cut(option, "=")
	return option == "--del" || option == "--delete" || strings.HasPrefix(option, "--delete-") ||
		option == "--remove-source-files"
}

// sourceNamesItsEntries reports a copy source spelled `dir/.`: its entries
// are copied, not the directory.
func sourceNamesItsEntries(source string) bool {
	source = strings.TrimRight(source, "/")
	return source == "." || strings.HasSuffix(source, "/.")
}

// gitCleanDirectory returns the directory a git clean starts from: the
// working directory, or the -C directories before the subcommand, each
// relative to the one before. A --work-tree DIR (or =DIR) names the tree a
// clean removes from; git keeps that value as written and resolves a
// relative one against the directory it ends in after every -C, wherever
// the option stands (`git --work-tree=. -C ~/.defenseclaw clean`, pod
// check18). ok is false for a value it cannot place.
func gitCleanDirectory(words []string, home, cwd string) (string, bool) {
	base := cwd
	workTree, hasWorkTree := "", false
	for index := 0; index < len(words) && words[index] != "clean"; index++ {
		word := words[index]
		if value, ok := strings.CutPrefix(word, "--work-tree="); ok {
			workTree, hasWorkTree = value, true
			continue
		}
		if word != "-C" && word != "--work-tree" || index+1 >= len(words) {
			continue
		}
		index++
		if word == "--work-tree" {
			workTree, hasWorkTree = words[index], true
			continue
		}
		next, ok := stateHomePath(words[index], home, base)
		if !ok {
			return "", false
		}
		base = path.Clean(next)
	}
	if hasWorkTree {
		next, ok := stateHomePath(workTree, home, base)
		if !ok {
			return "", false
		}
		return path.Clean(next), true
	}
	return base, true
}

// gitCleanPathspecs returns the static pathspecs after the clean
// subcommand. The value of -e/--exclude (also `-fdxe keep`) is a pattern
// git keeps, not a path it removes, so `clean -fdx -e keep` cleans the
// whole tree (GAP-2047); a word with no static spelling can expand to
// nothing (`clean -fdx $X`, GAP-2484). Neither narrows the clean.
func gitCleanPathspecs(words []string) []string {
	index := slices.Index(words, "clean")
	if index < 0 {
		return nil
	}
	var paths []string
	optionsDone := false
	for next := index + 1; next < len(words); next++ {
		word := words[next]
		switch {
		case word == "":
		case optionsDone:
			paths = append(paths, word)
		case word == "--":
			optionsDone = true
		case word == "--exclude":
			next++
		case len(word) > 1 && word[0] == '-' && word[1] != '-':
			// A short cluster ending in e takes the next word as its value;
			// an e inside the cluster takes the rest of it.
			if strings.IndexByte(word[1:], 'e') == len(word)-2 {
				next++
			}
		case strings.HasPrefix(word, "-"):
		default:
			paths = append(paths, word)
		}
	}
	return paths
}

func gitCleanForces(option string) bool {
	return option == "--force" || len(option) > 1 && option[0] == '-' && option[1] != '-' && strings.ContainsRune(option, 'f')
}

func gitCleanDryRun(option string) bool {
	return option == "--dry-run" || len(option) > 1 && option[0] == '-' && option[1] != '-' && strings.ContainsRune(option, 'n')
}

// splitStateOperands separates option words from operands; "--" ends the
// options. An option's value is not told apart from an operand, which only
// widens the words a pattern check reads.
func splitStateOperands(words []string) (operands, options []string) {
	optionsDone := false
	for _, word := range words {
		switch {
		case optionsDone:
			operands = append(operands, word)
		case word == "--":
			optionsDone = true
		case strings.HasPrefix(word, "-") && word != "-":
			options = append(options, word)
		default:
			operands = append(operands, word)
		}
	}
	return operands, options
}

// copyMoveStateOperands returns the destination and the sources of a cp or
// mv: the -t/--target-directory value, else the last operand.
func copyMoveStateOperands(operands, options []string) (string, []string) {
	for _, option := range options {
		if value, ok := strings.CutPrefix(option, "--target-directory="); ok {
			return value, operands
		}
		if value, ok := strings.CutPrefix(option, "-t"); ok && value != "" {
			return value, operands
		}
	}
	if len(operands) < 2 {
		return "", nil
	}
	return operands[len(operands)-1], operands[:len(operands)-1]
}

// stateWordExpands reports a word with a pathname pattern or a brace list.
func stateWordExpands(word string) bool {
	return strings.ContainsAny(word, "*?[") || len(expandStateBraces(word)) > 1
}

// stateHomePath places a word: a leading ~ is the active home, a relative
// word is under cwd. ok is false for a word with no static spelling.
func stateHomePath(word, home, cwd string) (string, bool) {
	switch {
	case word == "":
		return "", false
	case word == "~":
		return home, true
	case strings.HasPrefix(word, "~/"):
		return home + word[1:], true
	case strings.HasPrefix(word, "~"):
		return "", false
	case strings.HasPrefix(word, "/"):
		return word, true
	case strings.HasPrefix(cwd, "/"):
		return strings.TrimRight(cwd, "/") + "/" + word, true
	}
	return "", false
}

// stateRelativeComponents returns the path components of word under the
// state root (".defenseclaw" first), one entry per expanded brace form.
func stateRelativeComponents(word, home, cwd string) [][]string {
	var out [][]string
	for _, form := range expandStateBraces(word) {
		full, ok := stateHomePath(form, home, cwd)
		if !ok {
			continue
		}
		full = path.Clean(full)
		relative, within := strings.CutPrefix(full, home+"/")
		if !within || relative == "" {
			continue
		}
		out = append(out, strings.Split(relative, "/"))
	}
	return out
}

// statePatternReaches reports a (possibly globbed) operand that can name
// the state root, a protected tree or anything in one, or a protected file.
func statePatternReaches(word, home, cwd string) bool {
	for _, components := range stateRelativeComponents(word, home, cwd) {
		if !shellComponentMatches(components[0], ".defenseclaw") {
			continue
		}
		if len(components) == 1 {
			return true
		}
		for _, name := range activeStateTreeNames {
			if shellComponentMatches(components[1], name) {
				return true
			}
		}
		if len(components) == 2 {
			for _, name := range activeStateFileNames {
				if shellComponentMatches(components[1], name) {
					return true
				}
			}
		}
	}
	return false
}

// stateDirectoryOf reports whether a directory operand is (in) a protected
// tree, or is the state root itself.
func stateDirectoryOf(word, home, cwd string) (tree, root bool) {
	for _, components := range stateRelativeComponents(word, home, cwd) {
		if !shellComponentMatches(components[0], ".defenseclaw") {
			continue
		}
		if len(components) == 1 {
			root = true
			continue
		}
		for _, name := range activeStateTreeNames {
			if shellComponentMatches(components[1], name) {
				tree = true
			}
		}
	}
	return tree, root
}

// stateLandingReached reports a copy or move of a source named like base
// into destination that lands on protected state: anything into a
// protected tree, or a name into the root that can be a protected one.
func stateLandingReached(destination, base, home, cwd string) bool {
	tree, root := stateDirectoryOf(destination, home, cwd)
	if tree {
		return true
	}
	if !root {
		return false
	}
	for _, form := range expandStateBraces(base) {
		for _, name := range append(slices.Clone(activeStateTreeNames), activeStateFileNames...) {
			if shellComponentMatches(form, name) {
				return true
			}
		}
	}
	return false
}

// shellComponentMatches matches one path component as the shell expands a
// pattern: a leading dot of a name matches only an explicit dot. A
// malformed pattern counts as a match.
func shellComponentMatches(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") {
		return false
	}
	matched, err := path.Match(pattern, name)
	return matched || err != nil
}

// expandStateBraces expands bash brace lists ({a,b}, nested) of a word; a
// word with none, or more than maxStateBraceExpansions forms, is returned
// unchanged.
func expandStateBraces(word string) []string {
	forms := []string{word}
	for range maxStateBraceExpansions {
		changed := false
		var next []string
		for _, form := range forms {
			prefix, alternatives, suffix, ok := firstBraceList(form)
			if !ok {
				next = append(next, form)
				continue
			}
			changed = true
			for _, alternative := range alternatives {
				next = append(next, prefix+alternative+suffix)
			}
		}
		if !changed {
			return forms
		}
		if len(next) > maxStateBraceExpansions {
			return []string{word}
		}
		forms = next
	}
	return forms
}

// firstBraceList finds the first {x,y,...} group with a top-level comma.
func firstBraceList(word string) (prefix string, alternatives []string, suffix string, ok bool) {
	for start := 0; start < len(word); start++ {
		if word[start] != '{' {
			continue
		}
		depth, last := 0, start+1
		var parts []string
		for end := start; end < len(word); end++ {
			switch word[end] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					if len(parts) == 0 {
						end = len(word)
						break
					}
					parts = append(parts, word[last:end])
					return word[:start], parts, word[end+1:], true
				}
			case ',':
				if depth == 1 {
					parts = append(parts, word[last:end])
					last = end + 1
				}
			}
		}
	}
	return "", nil, "", false
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// The analysis of a POSIX call stops at a word over maxScalarBytes (4 KiB)
// with no command: the call is TRUNCATED in the sense of the bound rule
// (ShellInputPastByteBound). That is right for a word the local shell runs as
// code, and wrong for a word it only passes on: a big quoted script handed to
// a program that runs it somewhere else (dcx, ssh, docker exec, a
// deployment tool) is DATA to the local shell, whose hook never sees what it
// runs there. SplitOverLimitWords tells the two apart by position in the
// grammar of the call (rel-1-0-10:GAP-0382, the second round):
//
//   - CODE position, which stays truncated: the command name; the operand of
//     a shell, of eval, source or ., of a wrapper that starts the next word as
//     a command (the transparent wrappers, sudo, xargs, find, watch, ...);
//     the code operand of an interpreter, read from the interpreter's own
//     option table (inlineCapabilityTable) and, for an interpreter the table
//     lacks, every operand; a word before the destination of a remote
//     program (an ssh option such as ProxyCommand runs locally); and any word
//     that is not the plain operand of a simple command (a redirect target, a
//     here-document body, a loop or case word, an expansion default).
//   - DATA position, the plain operand of any other program, which includes a
//     word after the destination of ssh: classifySSH reads the options and
//     the destination of ssh and never the remote command, so there is no
//     remote-exec reading of the text to defer to, and the local analysis
//     treats it as the operand it is.
//
// No program is named for being data: a program is data unless the analysis
// or one of its readers already reads its operands as code (posixShellProgram,
// the wrappers of the layout reading, simpleShellTextRunner, the inline
// interpreter table). A call whose every over-limit word is data is judged as
// its twin: the same call with each such word replaced by a short stand-in of
// the same quoting, so every other statement is read in full; the dispatcher
// adds a detection-only record of the unread word.

// stubKeepBytes is the length up to which a part of an over-limit word is
// kept as it is in the twin (a quoted prefix such as --data= stays).
const stubKeepBytes = 64

// OverLimitWordSplit is the reading of a POSIX call whose analysis stops at
// a word over the string bound. Twin is the call with each DATA word
// shortened; Data and Code count the over-limit words in each position.
type OverLimitWordSplit struct {
	Twin string
	Data int
	Code int
	// Query counts the over-limit inline queries of a SQL client (psql -c,
	// mysql -e): code to the server, so the call is recorded truncated, but
	// the twin keeps the query with its long literals shortened, cut after
	// its last statement within the bound (sqlQueryWordChunks), and the cut by
	// itself raises nothing (DET111 ruling on FIX-T20B).
	Query int
	// QueryUnreadDanger counts the over-limit queries with a statement past
	// the cut that holds a modeled danger keyword and could not be read alone
	// (sqlQueryWordChunks): the call then takes the truncated row, not the
	// record (DET111 ruling on T23 review P3-1).
	QueryUnreadDanger int
	// QueryChunks are the further readings of the call when a query is
	// past the bound even shortened: the twin with each such query replaced
	// by its next chunk of whole statements (x when it has no more), so the
	// statements past the first cut are read too, at most maxSQLQueryChunks
	// readings in all (DET111 ruling B on GAP-1926).
	QueryChunks []string
	// Why is the reason the text could not be split, "" when it could.
	Why string
}

// SplitOverLimitWords reads a POSIX command text that is within the text
// bound and holds over-limit words. false when the text cannot be read with
// certainty (it does not parse, a word part has a shape the twin cannot
// shorten, or the twin is itself over a bound): the caller then keeps the
// call truncated.
func SplitOverLimitWords(command string) (OverLimitWordSplit, bool) {
	return splitOverLimitWords(command, false)
}

// SplitOverLimitWordsOfArgv is SplitOverLimitWords for the text of a call
// whose command is an array of words (the Codex shell tool): the script
// word of a shell -c is shell text to the reading of that array, so the
// over-limit words inside it that are plain data (ssh host '...') leave the
// call as its twin, as the same words typed as an argv are not code. A call
// written as text keeps the stricter reading (a script handed to the local
// shell is code, rel-1-0-10:GAP-0382, GAP-0689).
func SplitOverLimitWordsOfArgv(command string) (OverLimitWordSplit, bool) {
	return splitOverLimitWords(command, true)
}

func splitOverLimitWords(command string, nestedBodies bool) (OverLimitWordSplit, bool) {
	if len(command) > maxCommandBytes {
		return OverLimitWordSplit{Why: "text over the bound"}, false
	}
	file, ok := shellparse.Parse(command)
	if !ok {
		return OverLimitWordSplit{Why: "does not parse"}, false
	}
	dataWords := map[*syntax.Word]bool{}
	bodyWords := map[*syntax.Word]bool{}
	queryWords := map[*syntax.Word]sqlQueryWord{}
	bindings := literalBindings(file)
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, isCall := node.(*syntax.CallExpr); isCall {
			markDataWords(call, bindings, dataWords, bodyWords, queryWords)
		}
		return true
	})
	var split OverLimitWordSplit
	type replacement = overLimitReplacement
	var replacements []replacement
	// queryChunks holds, for each over-limit query, the index of its
	// replacement and its chunks past the first.
	type queryChunk struct {
		index  int
		chunks []string
	}
	var queryChunks []queryChunk
	valid := true
	syntax.Walk(file, func(node syntax.Node) bool {
		word, isWord := node.(*syntax.Word)
		if !isWord || !valid {
			return valid
		}
		if !overLimitWord(word) {
			return true
		}
		if query, isQuery := queryWords[word]; isQuery {
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < 0 || end > len(command) || start >= end {
				valid = false
				return false
			}
			chunks, danger := sqlQueryWordChunks(query, projectPOSIXWord(word).Value)
			if danger {
				split.QueryUnreadDanger++
			}
			if len(chunks) > 1 {
				queryChunks = append(queryChunks, queryChunk{len(replacements), chunks[1:]})
			}
			replacements = append(replacements, replacement{start, end, chunks[0]})
			split.Query++
			return false
		}
		if !dataWords[word] {
			// The script word of a shell -c is code to the local shell, but
			// what the script does with an over-limit word of its own is
			// decided by the grammar of the script: a body whose every
			// over-limit word is data (ssh host '<script>' inside bash -lc)
			// is read as its twin, the rest of the body kept
			// (rel-1-0-10:GAP-0689, the argv form of the Codex shell tool).
			if nestedBodies && bodyWords[word] {
				if text, nested, ok := nestedBodyTwin(word); ok {
					start, end := int(word.Pos().Offset()), int(word.End().Offset())
					if start >= 0 && end <= len(command) && start < end {
						if len(nested.QueryChunks) != 0 {
							chunks := make([]string, len(nested.QueryChunks))
							for i, chunk := range nested.QueryChunks {
								chunks[i] = posixSingleQuoted(chunk)
							}
							queryChunks = append(queryChunks, queryChunk{len(replacements), chunks})
						}
						replacements = append(replacements, replacement{start, end, text})
						split.Data += nested.Data
						split.Query += nested.Query
						split.QueryUnreadDanger += nested.QueryUnreadDanger
						return false
					}
				}
			}
			split.Code++
			return true
		}
		split.Data++
		for _, part := range word.Parts {
			start, end := int(part.Pos().Offset()), int(part.End().Offset())
			if end-start <= stubKeepBytes {
				continue
			}
			text, shortened := shortenedWordPart(part)
			if !shortened || start < 0 || end > len(command) || start >= end {
				valid = false
				return false
			}
			replacements = append(replacements, replacement{start, end, text})
		}
		return true
	})
	if !valid {
		split.Why = "a word part cannot be shortened"
		return split, false
	}
	if split.Data+split.Query == 0 {
		split.Why = "no data word"
		return split, false
	}
	twin, ok := overLimitTwinText(command, replacements)
	if !ok {
		split.Why = "overlapping parts"
		return split, false
	}
	split.Twin = twin
	for k := 0; len(queryChunks) != 0 && len(split.QueryChunks) < maxSQLQueryChunks+maxSQLDangerReadings-1; k++ {
		more := false
		chunked := slices.Clone(replacements)
		for _, query := range queryChunks {
			chunked[query.index].text = posixSingleQuoted("x")
			if k < len(query.chunks) {
				chunked[query.index].text, more = query.chunks[k], true
			}
		}
		if !more {
			break
		}
		text, _ := overLimitTwinText(command, chunked)
		split.QueryChunks = append(split.QueryChunks, text)
	}
	return split, true
}

// overLimitReplacement is the text that stands in for command[start:end]
// in a twin.
type overLimitReplacement struct {
	start, end int
	text       string
}

// overLimitTwinText is command with each replacement made, false when two
// overlap.
func overLimitTwinText(command string, replacements []overLimitReplacement) (string, bool) {
	sorted := slices.Clone(replacements)
	slices.SortFunc(sorted, func(a, b overLimitReplacement) int { return a.start - b.start })
	var twin strings.Builder
	last := 0
	for _, r := range sorted {
		if r.start < last {
			return "", false
		}
		twin.WriteString(command[last:r.start])
		twin.WriteString(r.text)
		last = r.end
	}
	twin.WriteString(command[last:])
	return twin.String(), true
}

// OverLimitTwinWithinBounds reports a twin of SplitOverLimitWords that the
// analysis reads to the end: its own analysis is not limit-exceeded.
func OverLimitTwinWithinBounds(input Input, twin string) bool {
	probe := input
	probe.Command, probe.Args, probe.Argv = twin, nil, nil
	return Analyze(probe).Parse.Status != StatusLimitExceeded
}

// overLimitWord reports a word the analysis refuses: a literal over the
// string bound that holds no expansion (as projectPOSIXStatement counts it).
func overLimitWord(word *syntax.Word) bool {
	value := projectPOSIXWord(word)
	return !value.Expands && len(value.Value) > maxScalarBytes
}

// shortenedWordPart is the stand-in of one part of an over-limit word, with
// the quoting of the part: a literal stays a bare literal, a single or double
// quoted string stays quoted. false for a part with an expansion.
func shortenedWordPart(part syntax.WordPart) (string, bool) {
	switch part := part.(type) {
	case *syntax.Lit:
		return "x", true
	case *syntax.SglQuoted:
		if part.Dollar {
			return "$'x'", true
		}
		return "'x'", true
	case *syntax.DblQuoted:
		for _, nested := range part.Parts {
			if _, literal := nested.(*syntax.Lit); !literal {
				return "", false
			}
		}
		if part.Dollar {
			return `$"x"`, true
		}
		return `"x"`, true
	}
	return "", false
}

// markDataWords records, in dataWords, each over-limit operand of call that
// is in DATA position, and in queryWords each that is the inline query of a
// SQL client.
func markDataWords(call *syntax.CallExpr, bindings map[string]string, dataWords, bodyWords map[*syntax.Word]bool,
	queryWords map[*syntax.Word]sqlQueryWord) {
	if len(call.Args) < 2 {
		return
	}
	argv := make([]string, len(call.Args))
	big := make([]bool, len(call.Args))
	any := false
	for index, word := range call.Args {
		value := projectPOSIXWord(word)
		switch {
		case value.Expands:
			argv[index] = staticWordTailName(word)
			if argv[index] == "" {
				argv[index] = boundVariableValue(word, bindings, call.Pos().Offset())
			}
		case len(value.Value) > maxScalarBytes:
			// A stand-in with no dash and no space: it is an operand, never an
			// option, wherever the grammar of the program puts it. A glued
			// long option (--command=<text>) keeps its name after the mark,
			// so the grammar of the program still sees which option the word
			// sets (overLimitSQLQueryOperand).
			argv[index] = "\x01"
			if name, _, glued := strings.Cut(value.Value, "="); glued &&
				strings.HasPrefix(name, "--") && len(name) <= stubKeepBytes {
				argv[index] = "\x01" + name + "="
			}
			big[index] = true
			any = true
		default:
			argv[index] = value.Value
		}
	}
	if !any {
		return
	}
	for index, isBig := range big {
		if !isBig {
			continue
		}
		position, query := overLimitOperandPosition(argv, index)
		switch {
		case position == overLimitData:
			dataWords[call.Args[index]] = true
		case position == overLimitSQLQuery:
			queryWords[call.Args[index]] = query
		case overLimitShellBodyAt(argv, index):
			bodyWords[call.Args[index]] = true
		}
	}
}

// nestedBodyTwin reads the script word of a shell -c as shell text: when its
// over-limit words are all DATA the word becomes its twin, requoted, and the
// nested split is returned. false for a word that is not one static literal
// or a script with a code word, an unreadable text or no data word.
func nestedBodyTwin(word *syntax.Word) (string, OverLimitWordSplit, bool) {
	value := projectPOSIXWord(word)
	if value.Expands || len(value.Value) <= maxScalarBytes {
		return "", OverLimitWordSplit{}, false
	}
	nested, ok := SplitOverLimitWordsOfArgv(value.Value)
	if !ok || nested.Code > 0 || nested.Data+nested.Query == 0 || len(nested.Twin) >= len(value.Value) {
		return "", OverLimitWordSplit{}, false
	}
	return posixSingleQuoted(nested.Twin), nested, true
}

// overLimitShellBodyAt reports argv[at] as the script a POSIX shell takes
// with -c, directly or behind transparent wrappers.
func overLimitShellBodyAt(argv []string, at int) bool {
	start := 0
	for range maxWrapperDepth + 1 {
		if at <= start || argv[start] == "" || strings.HasPrefix(argv[start], "\x01") {
			return false
		}
		program := overLimitProgram(argv[start])
		switch {
		case overLimitTransparentWrapper(program):
			rest := transparentWrapperTarget(argv[start:])
			next := len(argv) - len(rest)
			if len(rest) == 0 || next <= start || at < next {
				return false
			}
			start = next
		case posixShellProgram(program):
			index, ok := shellCommandBodyIndex(argv[start:])
			return ok && start+index == at
		default:
			return false
		}
	}
	return false
}

// shellCommandBodyIndex is the index of the script word of a POSIX shell
// call (bash -c BODY, sh -lc BODY), skipping the options that take a value;
// it reads the options only, not the whole invocation.
func shellCommandBodyIndex(argv []string) (int, bool) {
	for j := 1; j+1 < len(argv); j++ {
		option := argv[j]
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return 0, false
		}
		switch option {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			j++
			continue
		}
		if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
			!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
			return j + 1, true
		}
	}
	return 0, false
}

// overLimitPosition is the place of an over-limit word in the grammar of
// its call (overLimitOperandPosition).
type overLimitPosition uint8

const (
	// overLimitCode: code to the local shell or a program it starts.
	overLimitCode overLimitPosition = iota
	// overLimitData: the plain operand of a program that does not run it.
	overLimitData
	// overLimitSQLQuery: the inline query of a SQL client.
	overLimitSQLQuery
)

// overLimitOperandPosition reads the place of the over-limit word argv[at]:
// the plain operand of a program that does not run it as local code (data),
// the inline query of a SQL client (with its engine), or code. argv holds ""
// for an expansion and "\x01" for an over-limit word.
func overLimitOperandPosition(argv []string, at int) (overLimitPosition, sqlQueryWord) {
	start := 0
	for range maxWrapperDepth + 1 {
		if at <= start || argv[start] == "" || strings.HasPrefix(argv[start], "\x01") {
			return overLimitCode, sqlQueryWord{}
		}
		program := overLimitProgram(argv[start])
		if program == "kubectl" || program == "oc" || program == "k" {
			parsed, ok := parseKubectlArgv(argv[start:])
			if ok && !parsed.unknown && parsed.subcommand == "exec" && len(parsed.command) > 0 {
				childStart := len(argv) - len(parsed.command)
				if at > childStart {
					if engine, isSQL := sqlMutationEngine(overLimitProgram(parsed.command[0])); isSQL {
						if glued, query := overLimitSQLQueryOperand(engine, argv[at-1], argv[at]); query {
							return overLimitSQLQuery, sqlQueryWord{engine: engine, glued: glued}
						}
					}
				}
			}
		}
		switch {
		case overLimitRemoteProgram(program):
			// classifySSH reads the options and the destination; the words
			// after the destination are the command the remote host runs.
			return overLimitDataIf(overLimitAfterDestination(argv[start:], at-start, program))
		case overLimitTransparentWrapper(program):
			rest := transparentWrapperTarget(argv[start:])
			next := len(argv) - len(rest)
			if len(rest) == 0 || next <= start || at < next {
				return overLimitCode, sqlQueryWord{}
			}
			start = next
		case overLimitInterpreterRow(program) != nil:
			return overLimitDataIf(overLimitInterpreterOperandIsData(argv, start, at))
		case overLimitCodeProgram(program):
			return overLimitCode, sqlQueryWord{}
		case overLimitRunsOperand(program, argv, start, at):
			return overLimitCode, sqlQueryWord{}
		default:
			if engine, ok := sqlMutationEngine(program); ok {
				if glued, query := overLimitSQLQueryOperand(engine, argv[at-1], argv[at]); query {
					return overLimitSQLQuery, sqlQueryWord{engine: engine, glued: glued}
				}
			}
			return overLimitData, sqlQueryWord{}
		}
	}
	return overLimitCode, sqlQueryWord{}
}

func overLimitDataIf(data bool) (overLimitPosition, sqlQueryWord) {
	if data {
		return overLimitData, sqlQueryWord{}
	}
	return overLimitCode, sqlQueryWord{}
}

// overLimitRunsOperand reports a program that runs the over-limit operand
// argv[at] as code in its own grammar, though no shell reads it: a sed script
// (its e and w commands run a program and write a file), a make assignment or
// target (the recipes read it), a tar option value (--checkpoint-action,
// --to-command, -I), an rsync remote shell (-e, --rsh) and the value of a
// git -c setting (an alias that starts with ! is a shell command). A word
// these take that is past the string bound is no plain data, as the argument
// of a program that passes it on (rel-1-0-10:GAP-0761); a commit message of
// git, the destination of a copy and the like stay DATA. The inline query of
// a SQL client has its own place (overLimitSQLQueryOperand).
func overLimitRunsOperand(program string, argv []string, start, at int) bool {
	switch program {
	case "sed", "gsed", "make", "gmake", "gnumake", "tar", "gtar", "bsdtar", "rsync":
		return true
	case "git":
		return at-1 > start && argv[at-1] == "-c"
	}
	return false
}

// overLimitSQLQueryOperand reports the over-limit word of a SQL client of
// engine that is its inline query: the value of its query option as the next
// word (psql -c, mysql -e, sqlcmd -Q, snowsql -q), or glued to it
// (--command=<SQL>, kept by markDataWords as the mark and the option name).
// The query is no plain data (the server runs it, and COPY ... PROGRAM
// starts a program there) and no local code: the SQL readers read it
// (sqlQueryWordTwin). The database operand of psql stays DATA.
func overLimitSQLQueryOperand(engine, previous, word string) (glued, query bool) {
	if key, _, consumesNext, _, ok := exactSQLCLIOption(engine, previous); ok && key == "query" && consumesNext {
		return false, true
	}
	if name, marked := strings.CutPrefix(word, "\x01"); marked && name != "" {
		key, _, _, _, ok := exactSQLCLIOption(engine, name+"x")
		return true, ok && key == "query"
	}
	return false, false
}

// overLimitProgram is the lower-case base name of a program word, with a
// .exe suffix removed. It does not ask for a trusted path (commandProgram
// does): a shell at an unusual path is still a shell here.
func overLimitProgram(word string) string {
	if strings.TrimSpace(word) == "" {
		return ""
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(word, `\`, "/")))
	return strings.TrimSuffix(base, ".exe")
}

// overLimitRemoteProgram is the family classifySSH reads (ssh, autossh,
// sftp): the program starts a session on another host.
func overLimitRemoteProgram(program string) bool {
	return program == "ssh" || program == "autossh" || program == "sftp"
}

// overLimitTransparentWrapper is a program that starts a following word as
// the command and changes nothing about it (transparentWrapperTarget).
func overLimitTransparentWrapper(program string) bool {
	if program == "env" || program == "command" {
		return true
	}
	_, ok := transparentWrappers[program]
	return ok
}

// overLimitCodeProgram is a program whose operands the analysis or one of its
// readers already reads as code the local machine runs: the shells, eval,
// source and the dot, the wrappers of the layout reading, the programs that
// run argument words as shell text, and find.
func overLimitCodeProgram(program string) bool {
	return posixShellProgram(program) || layoutShells[program] || layoutWrappers[program] ||
		layoutInShell[program] || simpleShellTextRunner(program) || program == "find" ||
		program == "powershell" || program == "pwsh" || program == "cmd" || program == "nsenter"
}

// overLimitInterpreterRow is the row of the inline interpreter table for a
// program, nil when the program is not in it.
func overLimitInterpreterRow(program string) *inlineCapabilityRow {
	_, row, ok := inlineInterpreterRow(program)
	if !ok {
		return nil
	}
	return &row
}

// overLimitInterpreterOperandIsData reports an over-limit operand of an
// interpreter of the table that is neither its code (the word after a dash
// option, which may be the code option or take it) nor its script (the first
// operand): an argument of the script.
func overLimitInterpreterOperandIsData(argv []string, start, at int) bool {
	return at-1 > start && !strings.HasPrefix(argv[at-1], "-")
}

// overLimitAfterDestination reports whether argv[at] lies after the
// destination of a remote program called with argv.
//
// An -o option the egress reading does not model (BatchMode=yes) makes its
// scan invalid; here that only means the destination is unknown. A connection
// setting that runs nothing locally and names no path is dropped before the
// scan, so the remote command after the destination stays DATA (ssh -o
// BatchMode=yes host '<script>': the lead ruling on GAP-0382 and GAP-0760 for
// TestWindowsLauncherSpellingsPastTheBoundAreNeverACleanAllow). Any other -o
// (ProxyCommand, LocalCommand, KnownHostsCommand, Match, a path) keeps the
// scan invalid, and the word is CODE.
func overLimitAfterDestination(argv []string, at int, program string) bool {
	kept := make([]string, 0, len(argv))
	keptAt := -1
	for i := 0; i < len(argv); i++ {
		if i > 0 && i < at {
			if argv[i] == "-o" && i+1 < at && overLimitInertSSHOption(argv[i+1]) {
				i++
				continue
			}
			if len(argv[i]) > 2 && strings.HasPrefix(argv[i], "-o") && overLimitInertSSHOption(argv[i][2:]) {
				continue
			}
		}
		if i == at {
			keptAt = len(kept)
		}
		kept = append(kept, argv[i])
	}
	out := newParseOutput(DialectPOSIX, 1)
	command := CommandFact{ID: 1, Argv: kept}
	scan := classifySSHOptionPaths(&out, &command, program)
	return keptAt >= 0 && scan.valid && scan.destinationIndex > 0 && keptAt > scan.destinationIndex
}

// overLimitInertSSHOption reports an ssh -o setting that runs no local
// command and names no local path: a connection, keep-alive, host-key check
// or authentication-method setting with a plain value.
func overLimitInertSSHOption(value string) bool {
	key, optionValue, ok := splitSSHConfigOption(value)
	if !ok || strings.ContainsAny(optionValue, "\x00\x01/\\%$`;|&<>(){} \t") {
		return false
	}
	switch strings.ToLower(key) {
	case "batchmode", "connecttimeout", "connectionattempts", "stricthostkeychecking",
		"serveraliveinterval", "serveralivecountmax", "tcpkeepalive", "loglevel",
		"compression", "port", "user", "identitiesonly", "requesttty", "addressfamily",
		"checkhostip", "preferredauthentications", "passwordauthentication",
		"pubkeyauthentication", "kbdinteractiveauthentication", "numberofpasswordprompts":
		return true
	}
	return false
}

// staticWordTailName is the file name a word ends with when the word is a
// path whose directory expands ($K/dcx, "$HOME"/bin/ssh) and whose last
// component is literal: the program is named by that last component wherever
// the directory is, so it is read as that name (a shell called through a
// variable directory is still a shell here). "" for a word with no literal
// last component ($CMD, $K/$NAME), whose program is unknown.
func staticWordTailName(word *syntax.Word) string {
	var leaves []syntax.WordPart
	for _, part := range word.Parts {
		if quoted, ok := part.(*syntax.DblQuoted); ok {
			leaves = append(leaves, quoted.Parts...)
			continue
		}
		leaves = append(leaves, part)
	}
	tail := ""
	for index := len(leaves) - 1; index >= 0; index-- {
		value, _, expands := projectPOSIXWordPart(leaves[index])
		if expands {
			break
		}
		tail = value + tail
	}
	slash := strings.LastIndexByte(tail, '/')
	if slash < 0 || slash == len(tail)-1 {
		return ""
	}
	return tail[slash+1:]
}

// literalBindings are the variables the text sets once, at the top level, to
// a literal (K=/path/dcx; "$K" ...): name to value. A name that is set
// anywhere else (a second assignment, a prefix assignment, a declaration, a
// loop variable, an assigning expansion) is left out, and so is every name
// when the text holds a builtin that binds a name from data or code (read,
// eval, source, ...), which could rebind any of them.
func literalBindings(file *syntax.File) map[string]string {
	count := map[string]int{}
	rebinds := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Assign:
			count[node.Name.Value]++
		case *syntax.ForClause:
			if loop, ok := node.Loop.(*syntax.WordIter); ok {
				count[loop.Name.Value] += 2
			} else {
				rebinds = true
			}
		case *syntax.ParamExp:
			if node.Exp != nil && (node.Exp.Op == syntax.AssignUnset || node.Exp.Op == syntax.AssignUnsetOrNull) {
				rebinds = true
			}
		case *syntax.CallExpr:
			if len(node.Args) > 0 && bindsFromCommand(node.Args) {
				rebinds = true
			}
		case *syntax.ArithmCmd, *syntax.ArithmExp, *syntax.LetClause, *syntax.CoprocClause:
			rebinds = true
		}
		return !rebinds
	})
	if rebinds {
		return nil
	}
	bindings := map[string]string{}
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 0 {
			continue
		}
		for _, assign := range call.Assigns {
			if assign.Append || assign.Array != nil || assign.Index != nil || assign.Value == nil || count[assign.Name.Value] != 1 {
				continue
			}
			if value := projectPOSIXWord(assign.Value); !value.Expands && value.Value != "" {
				bindings[assign.Name.Value] = value.Value
			}
		}
	}
	return bindings
}

// bindsFromCommand is a call to a builtin that gives a name a value from data
// or code the text does not show: read, getopts, mapfile, readarray, eval,
// source, the dot, and printf -v.
func bindsFromCommand(args []*syntax.Word) bool {
	switch overLimitProgram(projectPOSIXWord(args[0]).Value) {
	case "read", "getopts", "mapfile", "readarray", "eval", "source", ".":
		return true
	case "printf":
		return len(args) > 1 && projectPOSIXWord(args[1]).Value == "-v"
	}
	return false
}

// boundVariableValue is the literal value of a word that is one plain
// variable ($D, "$D", ${D}) set once to a literal before the call at offset
// (see literalBindings); "" for any other word.
func boundVariableValue(word *syntax.Word, bindings map[string]string, offset uint) string {
	if len(bindings) == 0 || len(word.Parts) != 1 {
		return ""
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok && len(quoted.Parts) == 1 {
		part = quoted.Parts[0]
	}
	expansion, ok := part.(*syntax.ParamExp)
	if !ok || expansion.Param == nil || expansion.Exp != nil || expansion.Slice != nil || expansion.Repl != nil ||
		expansion.Index != nil || expansion.Length || expansion.Width || expansion.IsSet || expansion.Excl || expansion.Names != 0 {
		return ""
	}
	return bindings[expansion.Param.Value]
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"mvdan.cc/sh/v3/syntax"
)

// The private record of the secret-read chain (substrate-1:GAP-0341): the
// credentials files one POSIX call reads that the ordinary path projection
// does not hold (an operand of a stream editor, pager, decompressor, JSON
// tool or interpreter; a glob or a variable naming one; the input redirect
// of a loop; the source of a link or move the call made before it reads the
// new name; a credentials file under the folder of a recursive search).
//
// Only reads count (rel-1-0-10:GAP-1030). A word is a candidate only where
// its command reads the file it names (credentialReaderFormOf and its operand
// grammar), in an input redirect, or as the value of a variable that such a
// position expands. Writes, removes, listings, mode changes, key use, commit
// messages and other mentions never count. A glob wildcard never matches a
// leading dot (as in the shell), and a glob counts only when the segments it
// is compared on hold a literal byte: a bare * names no credentials file.
//
// The resolve is bounded by the one bound rule (rel-1-0-10:GAP-1029): the
// candidates it checks (bounded.Items), its work units (bounded.Time: the
// bytes the shape match reads and the probe comparisons) and the folders its
// recursive searches name (bounded.Paths; the walk under each has its own
// bounds, credentialPathWalk) are capped. A cap hit stops the resolve, keeps what
// was read before it and is TRUNCATED in the record's CapSet, which the
// gateway judges at the unknown tier of the pack (withBoundedTruncation). A
// glob is compared with each probe on the probe's own trailing segments
// only, so a word's segment count costs nothing past the deepest probe.
//
// Only resolveCredentialPathReads makes a record, from the parse of the call.
// The field is unexported, never serialized and printed as a pointer: no word
// of a call and no caller can set it, and nothing reads it but the accessors
// below.
type credentialPathRecord struct {
	reads []PathFact
	caps  bounded.CapSet
}

// The caps of the resolve. Every input under the analysis bounds of an
// ordinary call stays far below them; they stop a crafted word, not work.
const (
	maxCredentialPathCandidates = 4096
	maxCredentialPathWork       = 1 << 20
	maxCredentialPathLookups    = 1024
)

// The bounds of a recursive search's walk (substrate-1:GAP-0344): the
// folders it reads, the entries it reads in them (in batches, so one huge
// folder costs no more than its share) and the files it looks up. A walk
// cut at a bound is not a cap of the resolve, so it is no verdict on the
// search: the walk adds the chain's file-unknown read (Value ""), the
// unknown tier of the secret-read chain only (a later upload joins it), and
// what it found before the cut still counts. Exact numbers are kept in
// TestGAP0344WalkCut.
const (
	maxCredentialPathWalkFolders = 4096
	maxCredentialPathWalkEntries = 1 << 16
	maxCredentialPathWalkLookups = 1024
	credentialPathWalkBatch      = 512
	// The analyses of one hook evaluation (the call, its twins and its
	// result event) reuse a walk of the same folder made within
	// credentialPathWalkReuse: one walk per call. A later call walks again.
	credentialPathWalkReuse   = time.Second
	maxCredentialPathWalkMemo = 64
)

// MaxCredentialPathCandidates is the candidate cap of the resolve
// (bounded.Items), for the gateway's bound-rule lane test.
const MaxCredentialPathCandidates = maxCredentialPathCandidates

type credentialPathLimits struct {
	candidates, work, lookups int
}

var defaultCredentialPathLimits = credentialPathLimits{
	candidates: maxCredentialPathCandidates,
	work:       maxCredentialPathWork,
	lookups:    maxCredentialPathLookups,
}

// CredentialPathReads is a copy of the private record: the credentials files
// the call reads that Paths does not hold. A Value of "" is a read of a
// credentials file the call does not name exactly (the chain's file-unknown
// marker). Only the secret-read chain uses it, never path policy.
func (f Facts) CredentialPathReads() []PathFact {
	if f.credentialPaths == nil {
		return nil
	}
	return slices.Clone(f.credentialPaths.reads)
}

// HasCredentialPathReads reports a read in the private record.
func (f Facts) HasCredentialPathReads() bool {
	return f.credentialPaths != nil && len(f.credentialPaths.reads) != 0
}

// CredentialPathReadCaps is the caps the resolve hit: TRUNCATED, the one
// bound rule.
func (f Facts) CredentialPathReadCaps() bounded.CapSet {
	if f.credentialPaths == nil {
		return bounded.CapSet{}
	}
	return f.credentialPaths.caps
}

// PlaceCredentialPathReads is facts with each relative read of the private
// record placed under reported, the directory the hook reports, by the
// lexical rule the gateway places ordinary reads with. It adds no read and
// leaves the facts it was called on as they are.
func (f Facts) PlaceCredentialPathReads(reported string) Facts {
	if f.credentialPaths == nil || len(f.credentialPaths.reads) == 0 {
		return f
	}
	placed := &credentialPathRecord{reads: slices.Clone(f.credentialPaths.reads), caps: f.credentialPaths.caps}
	for i, candidate := range placed.reads {
		value := candidate.Value
		if candidate.Absolute || candidate.Resolved != "" || candidate.Flavor == PathFlavorWindows ||
			value == "" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") ||
			strings.ContainsAny(value, "\\$*?[]{}`\x00") {
			continue
		}
		placed.reads[i].Resolved = path.Join(reported, value)
	}
	f.credentialPaths = placed
	return f
}

// credentialPathWord is parse evidence the commands do not keep: an input
// redirect's word, a variable's value, or a variable a word expands (argIndex
// is the word's index in its simple command, -1 in an input redirect).
type credentialPathWord struct {
	commandID int64
	role      credentialPathWordRole
	name      string
	argIndex  int
	argument  ArgumentFact
}

type credentialPathWordRole uint8

const (
	credentialWordInputRedirect credentialPathWordRole = iota + 1
	credentialWordAssignment
	credentialWordReference
)

// captureCredentialPathWord records the evidence of one node of the POSIX
// walk. stack is the node's ancestors.
func captureCredentialPathWord(
	out *parseOutput,
	node syntax.Node,
	stack []syntax.Node,
	statementIDs map[*syntax.Stmt]int64,
	argIndexes *map[*syntax.CallExpr]map[*syntax.Word]int,
) {
	switch typed := node.(type) {
	case *syntax.Redirect:
		if typed.Word == nil || typed.Op != syntax.RdrIn && typed.Op != syntax.RdrInOut {
			return
		}
		out.credentialWords = append(out.credentialWords, credentialPathWord{
			commandID: nearestPOSIXStatementID(stack, statementIDs),
			role:      credentialWordInputRedirect,
			argIndex:  -1,
			argument:  projectPOSIXWord(typed.Word),
		})
	case *syntax.Assign:
		if typed.Name == nil || typed.Value == nil || typed.Append || typed.Naked {
			return
		}
		out.credentialWords = append(out.credentialWords, credentialPathWord{
			commandID: nearestPOSIXStatementID(stack, statementIDs),
			role:      credentialWordAssignment,
			name:      typed.Name.Value,
			argument:  projectPOSIXWord(typed.Value),
		})
	case *syntax.WordIter:
		// for NAME in WORDS: each word is a value of NAME, as an assignment
		// is (substrate-1:GAP-0349).
		if typed.Name == nil {
			return
		}
		for _, item := range typed.Items {
			out.credentialWords = append(out.credentialWords, credentialPathWord{
				commandID: nearestPOSIXStatementID(stack, statementIDs),
				role:      credentialWordAssignment,
				name:      typed.Name.Value,
				argument:  projectPOSIXWord(item),
			})
		}
	case *syntax.ParamExp:
		if typed.Param == nil {
			return
		}
		index, ok := posixReadPositionOfExpansion(stack, argIndexes)
		if !ok {
			return
		}
		out.credentialWords = append(out.credentialWords, credentialPathWord{
			commandID: nearestPOSIXStatementID(stack, statementIDs),
			role:      credentialWordReference,
			name:      typed.Param.Value,
			argIndex:  index,
		})
	}
}

func nearestPOSIXStatementID(stack []syntax.Node, statementIDs map[*syntax.Stmt]int64) int64 {
	for i := len(stack) - 1; i >= 0; i-- {
		if stmt, ok := stack[i].(*syntax.Stmt); ok && statementIDs[stmt] != 0 {
			return statementIDs[stmt]
		}
	}
	return 0
}

// posixReadPositionOfExpansion is the position of the word an expansion is in
// when that word may name a file read: an argument of a simple command (its
// index) or an input redirect (-1). Any other place (an assignment, an
// output redirect, a here-document) is not one.
func posixReadPositionOfExpansion(
	stack []syntax.Node,
	argIndexes *map[*syntax.CallExpr]map[*syntax.Word]int,
) (int, bool) {
	for i := len(stack) - 1; i > 0; i-- {
		word, ok := stack[i].(*syntax.Word)
		if !ok {
			continue
		}
		switch parent := stack[i-1].(type) {
		case *syntax.CallExpr:
			if *argIndexes == nil {
				*argIndexes = make(map[*syntax.CallExpr]map[*syntax.Word]int)
			}
			indexes, ok := (*argIndexes)[parent]
			if !ok {
				indexes = make(map[*syntax.Word]int, len(parent.Args))
				for index, arg := range parent.Args {
					indexes[arg] = index
				}
				(*argIndexes)[parent] = indexes
			}
			index, ok := indexes[word]
			return index, ok
		case *syntax.Redirect:
			return -1, parent.Word == word && (parent.Op == syntax.RdrIn || parent.Op == syntax.RdrInOut)
		}
		return 0, false
	}
	return 0, false
}

// credentialReaderForm is the operand grammar of a command that reads the
// files its words name.
type credentialReaderForm uint8

const (
	// Every operand is a file the command reads.
	credentialReadsOperands credentialReaderForm = iota + 1
	// awk and sed: operands are files or program text; program text is read
	// for path words. An in-place edit (-i) writes the file instead of
	// printing it.
	credentialReadsProgram
	// Interpreters: the inline program (-c, -e, -r, eval) is read for path
	// words; the input file operands of perl and ruby -n or -p, and the
	// operands after inline code that reads its arguments (perl <>, ruby
	// ARGF, python sys.argv), are reads (substrate-1:GAP-0349). A script's
	// own arguments are not reads (rel-1-0-10:GAP-1030).
	credentialReadsInterpreter
	// grep and rg: the first operand is the pattern unless an option gives it.
	credentialReadsSearch
	// cp and rsync: every operand but the destination is a source.
	credentialReadsSources
	// dd if=FILE, openssl -in FILE.
	credentialReadsOptionValue
	// jq: the first operand is the filter unless -f gives it.
	credentialReadsJSON
)

func credentialReaderFormOf(program string) credentialReaderForm {
	switch program {
	case "cat", "tac", "nl", "head", "tail", "less", "more", "most", "bat", "batcat",
		"base64", "base32", "basenc", "xxd", "od", "hexdump", "hd", "strings",
		"sort", "cut", "paste", "fold", "fmt", "column", "rev", "pr", "expand", "unexpand",
		"diff", "cmp", "comm", "iconv",
		"gzip", "gunzip", "zcat", "bzip2", "bunzip2", "bzcat", "xz", "unxz", "xzcat",
		"lzma", "unlzma", "zstd", "unzstd", "zstdcat", "lz4", "lz4cat", "brotli",
		"source", ".":
		return credentialReadsOperands
	case "awk", "gawk", "mawk", "nawk", "sed", "gsed":
		return credentialReadsProgram
	case "perl", "ruby", "php", "node", "nodejs", "deno", "bun", "python", "python2", "python3":
		return credentialReadsInterpreter
	case "grep", "egrep", "fgrep", "rg", "ripgrep":
		return credentialReadsSearch
	case "cp", "rsync":
		return credentialReadsSources
	case "dd", "openssl":
		return credentialReadsOptionValue
	case "jq":
		return credentialReadsJSON
	}
	if strings.HasPrefix(program, "python3.") || strings.HasPrefix(program, "python2.") {
		return credentialReadsInterpreter
	}
	return 0
}

// credentialOptionValues are the options of a reader that take the next word
// as their value (a count, a field, an output file), so that word is no
// operand.
var credentialOptionValues = map[string][]string{
	"head":    {"-n", "-c", "--lines", "--bytes"},
	"tail":    {"-n", "-c", "--lines", "--bytes", "-s", "--sleep-interval", "--pid"},
	"sort":    {"-o", "--output", "-T", "--temporary-directory", "-k", "--key", "-t", "--field-separator", "-S", "--buffer-size"},
	"cut":     {"-d", "-f", "-b", "-c", "--delimiter", "--fields", "--bytes", "--characters"},
	"xxd":     {"-c", "-g", "-l", "-s", "-o", "-n"},
	"od":      {"-A", "-j", "-N", "-t", "-w"},
	"hexdump": {"-e", "-f", "-n", "-s"},
	"base64":  {"-w", "--wrap"},
	"base32":  {"-w", "--wrap"},
	"basenc":  {"-w", "--wrap"},
	"fold":    {"-w", "--width"},
	"fmt":     {"-w", "--width", "-p", "--prefix"},
	"strings": {"-n", "-t", "-e", "--bytes", "--radix", "--encoding"},
	"nl":      {"-b", "-d", "-f", "-h", "-i", "-l", "-n", "-s", "-v", "-w"},
	"diff":    {"-L", "--label", "-x", "--exclude", "-I", "--ignore-matching-lines"},
	"iconv":   {"-f", "-t", "-o", "--output", "--from-code", "--to-code"},
	"column":  {"-s", "-t", "-c", "-o", "--separator", "--output-separator"},
	"pr":      {"-o", "-w", "-l", "-h"},
	"less":    {"-o", "-O", "-p", "-t", "-x", "-y", "-z", "-h", "-j", "-b"},
	"bat":     {"-l", "--language", "-r", "--line-range", "-H", "--highlight-line", "--file-name", "--style", "--theme", "-m", "--map-syntax", "--tabs", "--wrap", "--terminal-width", "--color", "--decorations", "--paging", "--pager"},
	"zstd":    {"-o", "-D"},
	"lz4":     {"-o"},
	"gzip":    {"-S", "--suffix"},
	"xz":      {"-S", "--suffix", "-T", "--threads"},
	"cp":      {"-t", "--target-directory", "-S", "--suffix"},
	"ln":      {"-t", "--target-directory", "-S", "--suffix"},
	"mv":      {"-t", "--target-directory", "-S", "--suffix"},
	"rsync": {"-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from", "--exclude-from",
		"--include-from", "-T", "--temp-dir", "--log-file", "--backup-dir", "--compare-dest", "--link-dest",
		"--copy-dest", "--partial-dir", "--chmod", "--chown", "-M", "--remote-option", "--port", "--timeout",
		"--bwlimit", "--info", "--debug", "--password-file", "--rsync-path", "--suffix"},
}

var credentialOptionValueSets = sync.OnceValue(func() map[string]map[string]struct{} {
	sets := make(map[string]map[string]struct{}, len(credentialOptionValues))
	for program, options := range credentialOptionValues {
		set := make(map[string]struct{}, len(options))
		for _, option := range options {
			set[option] = struct{}{}
		}
		sets[program] = set
	}
	sets["batcat"] = sets["bat"]
	sets["more"] = sets["less"]
	sets["most"] = sets["less"]
	sets["link"] = sets["ln"]
	return sets
})

// credentialOperandIndexes is the argv indexes of a command's operands: words
// after the options (and the values of options in consumes), "-" (stdin) and
// "--" excluded.
func credentialOperandIndexes(argv []string, consumes map[string]struct{}) []int {
	var operands []int
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if arg == "-" {
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if _, ok := consumes[arg]; ok && i+1 < len(argv) {
				i++
			}
			continue
		}
		operands = append(operands, i)
	}
	return operands
}

// credentialProbe is one probe path of the credentials table, lowercase, in
// segments.
type credentialProbe struct {
	value    string
	segments []string
}

var credentialProbes = sync.OnceValue(func() []credentialProbe {
	var probes []credentialProbe
	for _, probe := range CredentialFileShapeProbePaths() {
		probe = strings.Trim(strings.ToLower(probe), "/")
		if probe == "" {
			continue
		}
		probes = append(probes, credentialProbe{value: probe, segments: strings.Split(probe, "/")})
	}
	return probes
})

// credentialProbeFirstSegments groups the probes by their first segment, so a
// recursive search looks up each first segment once under a folder.
var credentialProbeFirstSegments = sync.OnceValue(func() map[string][]credentialProbe {
	groups := make(map[string][]credentialProbe)
	for _, probe := range credentialProbes() {
		groups[probe.segments[0]] = append(groups[probe.segments[0]], probe)
	}
	return groups
})

var credentialProbeDepth = sync.OnceValue(func() int {
	depth := 0
	for _, probe := range credentialProbes() {
		depth = max(depth, len(probe.segments))
	}
	return depth
})

// credentialPathLink is a link, copy or move from src to dst the call makes:
// a later read of dst in the call reads src.
type credentialPathLink struct {
	commandID int64
	src, dst  string
}

type credentialPathResolver struct {
	trunc      bounded.Truncated
	candidates bounded.Counter
	work       bounded.Counter
	lookups    bounded.Counter
	cwd, home  string
	commands   []CommandFact
	held       map[credentialHeldRead]bool
	links      []credentialPathLink
	seen       map[PathFact]bool
	reads      []PathFact
}

// resolveCredentialPathReads makes the private record of one call (nil when
// the call reads no credentials file the record adds and no cap was hit).
func resolveCredentialPathReads(words []credentialPathWord, cwd, home string, commands []CommandFact, paths []PathFact) *credentialPathRecord {
	return resolveCredentialPathReadsWithin(defaultCredentialPathLimits, words, cwd, home, commands, paths)
}

// credentialHeldRead is a read the ordinary path projection already holds
// and the chain already counts there (its command runs and has a read, search
// or copy operation); the record does not repeat it. A path whose command has
// no such operation (awk, openssl -in) is not one.
type credentialHeldRead struct {
	commandID int64
	value     string
}

func resolveCredentialPathReadsWithin(
	limits credentialPathLimits,
	words []credentialPathWord,
	cwd, home string,
	commands []CommandFact,
	paths []PathFact,
) *credentialPathRecord {
	if !credentialPathResolveNeeded(words, commands) {
		return nil
	}
	r := &credentialPathResolver{cwd: cwd, home: home, commands: commands}
	counted := make(map[int64]bool)
	for _, command := range commands {
		if command.Effect == EffectExecute && slices.ContainsFunc(command.Operations, func(op OperationKind) bool {
			return op == OperationRead || op == OperationSearch || op == OperationCopy
		}) {
			counted[command.ID] = true
		}
	}
	for _, held := range paths {
		if held.Access == PathAccessRead && counted[held.CommandID] {
			if r.held == nil {
				r.held = make(map[credentialHeldRead]bool)
			}
			r.held[credentialHeldRead{held.CommandID, held.Value}] = true
		}
	}
	r.candidates = bounded.NewCounter(&r.trunc, bounded.Items, limits.candidates)
	r.work = bounded.NewCounter(&r.trunc, bounded.Time, limits.work)
	r.lookups = bounded.NewCounter(&r.trunc, bounded.Paths, limits.lookups)
	r.resolve(words)
	caps := r.trunc.Set(&r.candidates, &r.work, &r.lookups)
	if len(r.reads) == 0 && !caps.Any() {
		return nil
	}
	return &credentialPathRecord{reads: r.reads, caps: caps}
}

// credentialPathResolveNeeded: no reader and no input redirect, nothing to
// resolve (the common call pays one pass over its programs).
func credentialPathResolveNeeded(words []credentialPathWord, commands []CommandFact) bool {
	for _, word := range words {
		if word.role == credentialWordInputRedirect {
			return true
		}
	}
	for _, command := range commands {
		if command.Dialect == DialectPOSIX && (credentialReaderFormOf(command.Program) != 0 || command.Program == "find") {
			return true
		}
	}
	return false
}

func (r *credentialPathResolver) stopped() bool { return r.trunc.Any() }

func (r *credentialPathResolver) resolve(words []credentialPathWord) {
	sets := credentialOptionValueSets()
	for _, command := range r.commands {
		if !credentialPathCommandReadable(command) {
			continue
		}
		switch command.Program {
		case "ln", "link", "mv":
			operands := credentialOperandIndexes(command.Argv, sets[command.Program])
			if len(operands) == 2 && !credentialOptionPresent(command.Argv, "-t", "--target-directory") {
				src, dst := command.Arguments[operands[0]], command.Arguments[operands[1]]
				if !src.Expands && !dst.Expands && src.Value != "" && dst.Value != "" {
					r.links = append(r.links, credentialPathLink{command.ID, src.Value, path.Clean(dst.Value)})
				}
			}
		}
	}
	// Readers, with the operand positions a variable may be read through.
	readOperands := make(map[int64]map[int]bool)
	readerParents := make(map[int64]bool)
	for _, command := range r.commands {
		if r.stopped() {
			return
		}
		if !credentialPathCommandReadable(command) {
			continue
		}
		form := credentialReaderFormOf(command.Program)
		if form == 0 {
			continue
		}
		operands := r.readCommand(command, form, sets)
		positions := make(map[int]bool, len(operands))
		for _, index := range operands {
			positions[index] = true
		}
		readOperands[command.ID] = positions
		if command.ParentCommandID != 0 {
			readerParents[command.ParentCommandID] = true
		}
	}
	// A reader's operand built by a substitution (cat "$(echo .env)") reads
	// what the substituted echo or printf prints, and a find whose -exec runs
	// a reader reads the files its name tests match: which file, the call
	// does not say.
	for _, command := range r.commands {
		if r.stopped() {
			return
		}
		if !credentialPathCommandReadable(command) {
			continue
		}
		switch {
		case (command.Program == "echo" || command.Program == "printf") && readOperands[command.ParentCommandID] != nil:
			operands := credentialOperandIndexes(command.Argv, nil)
			if command.Program == "printf" && len(operands) > 0 {
				operands = operands[1:] // the format
			}
			for _, index := range operands {
				r.argument(command.ID, command.Arguments[index], true)
			}
		case command.Program == "find" && credentialFindExecReads(command.Argv):
			for i := 1; i+1 < len(command.Argv); i++ {
				switch command.Argv[i] {
				case "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename":
					option := command.Argv[i]
					i++
					value := command.Arguments[i]
					switch {
					case value.Expands:
					case (option == "-name" || option == "-iname") && strings.ContainsAny(value.Value, "*?["):
						// find matches a name test against dotfiles too
						// (fnmatch without the shell's leading-dot rule):
						// -name '*.env' finds .env (substrate-1:GAP-0349).
						if !r.stopped() && r.candidates.Take() && r.work.TakeN(len(value.Value)) && r.globNamesCredentialFileDots(value.Value, true) {
							r.add(command.ID, "", true)
						}
					default:
						r.candidate(command.ID, value.Value, strings.ContainsAny(value.Value, "*?["), true)
					}
				}
			}
		}
	}
	// Input redirects read their file, whatever the command.
	referenced := make(map[string]bool)
	for _, word := range words {
		if r.stopped() {
			return
		}
		switch word.role {
		case credentialWordInputRedirect:
			r.argument(word.commandID, word.argument, false)
		case credentialWordReference:
			// A variable counts when a read position expands it: an input
			// redirect, a reader's operand, or any word of a wrapper whose
			// unwrapped command reads (sudo cat "$F").
			if word.argIndex == -1 || readOperands[word.commandID][word.argIndex] || readerParents[word.commandID] {
				referenced[word.name] = true
			}
		}
	}
	if len(referenced) == 0 {
		return
	}
	for _, word := range words {
		if r.stopped() {
			return
		}
		if word.role == credentialWordAssignment && referenced[word.name] {
			// The read is through the variable: its exact identity is not
			// the word's, so the read is file-unknown.
			r.argument(word.commandID, word.argument, true)
		}
	}
}

// credentialFindExecReads reports a find whose -exec, -execdir, -ok or -okdir
// runs a reader on the files it finds.
func credentialFindExecReads(argv []string) bool {
	for i := 1; i+1 < len(argv); i++ {
		switch argv[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			if credentialReaderFormOf(path.Base(argv[i+1])) != 0 {
				return true
			}
		}
	}
	return false
}

func credentialPathCommandReadable(command CommandFact) bool {
	return command.Dialect == DialectPOSIX && command.Effect != EffectPreview &&
		len(command.Arguments) == len(command.Argv)
}

func credentialOptionPresent(argv []string, options ...string) bool {
	for _, arg := range argv[1:] {
		if arg == "--" {
			return false
		}
		for _, option := range options {
			if arg == option || strings.HasPrefix(arg, option+"=") {
				return true
			}
		}
	}
	return false
}

// readCommand resolves the read operands of one reader and returns their
// argv indexes.
func (r *credentialPathResolver) readCommand(command CommandFact, form credentialReaderForm, sets map[string]map[string]struct{}) []int {
	argv := command.Argv
	var operands []int
	switch form {
	case credentialReadsOperands:
		operands = credentialOperandIndexes(argv, sets[command.Program])
	case credentialReadsProgram:
		if credentialProgramEditsInPlace(command.Program, argv) {
			return nil
		}
		for index := 1; index < len(command.Arguments); index++ {
			r.programWord(command.ID, command.Arguments[index])
			operands = append(operands, index)
		}
		return operands
	case credentialReadsInterpreter:
		if credentialProgramEditsInPlace(command.Program, argv) {
			return nil
		}
		code, inputs := credentialInterpreterWords(command.Program, argv)
		for _, index := range code {
			r.programWord(command.ID, command.Arguments[index])
		}
		for _, index := range inputs {
			r.argument(command.ID, command.Arguments[index], false)
		}
		return append(code, inputs...)
	case credentialReadsSearch:
		program := command.Program
		switch program {
		case "egrep", "fgrep":
			program = "grep"
		case "ripgrep":
			program = "rg"
		}
		fromOption, patternFiles := searchPatternOptions(argv)
		for _, file := range patternFiles {
			r.candidate(command.ID, file, false, false)
		}
		operands = searchOperandIndexes(argv, program)
		if !fromOption && len(operands) > 0 {
			operands = operands[1:]
		}
		recursive := credentialSearchRecursive(argv, program)
		// grep -r reads every file under the folder; ripgrep skips hidden
		// (dot-named) files and folders unless told otherwise
		// (substrate-1:GAP-0344).
		hidden := program != "rg" || rgSearchesHidden(argv)
		for _, index := range operands {
			argument := command.Arguments[index]
			r.argument(command.ID, argument, false)
			if recursive && !argument.Expands && argument.Value != "" {
				r.searchFolder(command.ID, argument.Value, hidden)
			}
		}
		if recursive && len(operands) == 0 && !(program == "rg" && r.pipedStdin(command)) {
			// No folder operand: grep -r and rg search the working folder
			// (an rg fed by a pipe searches its input instead,
			// substrate-1:GAP-0344).
			r.searchFolder(command.ID, ".", hidden)
		}
		return operands
	case credentialReadsSources:
		operands = credentialOperandIndexes(argv, sets[command.Program])
		if !credentialOptionPresent(argv, "-t", "--target-directory") && len(operands) > 0 {
			operands = operands[:len(operands)-1]
		}
	case credentialReadsOptionValue:
		for index := 1; index < len(argv); index++ {
			argument := command.Arguments[index]
			switch {
			case command.Program == "dd" && strings.HasPrefix(argument.Value, "if="):
				if !argument.Expands {
					r.candidate(command.ID, strings.TrimPrefix(argument.Value, "if="), false, false)
					operands = append(operands, index)
				}
			case command.Program == "openssl" && (argv[index] == "-in" || argv[index] == "-inkey") && index+1 < len(argv):
				index++
				r.argument(command.ID, command.Arguments[index], false)
				operands = append(operands, index)
			}
		}
		return operands
	case credentialReadsJSON:
		operands = r.jsonOperands(command)
	}
	for _, index := range operands {
		r.argument(command.ID, command.Arguments[index], false)
	}
	return operands
}

// jsonOperands is jq's input files: the operands after the filter (none when
// -f gives the filter), and the files --slurpfile and --rawfile read.
func (r *credentialPathResolver) jsonOperands(command CommandFact) []int {
	argv := command.Argv
	var operands []int
	filter := true
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case options && arg == "--":
			options = false
		case options && (arg == "--args" || arg == "--jsonargs"):
			// The rest are values, not files.
			return operands
		case options && (arg == "--arg" || arg == "--argjson"):
			i += 2
		case options && (arg == "--slurpfile" || arg == "--rawfile"):
			if i+2 < len(argv) {
				operands = append(operands, i+2)
			}
			i += 2
		case options && (arg == "-f" || arg == "--from-file"):
			if i+1 < len(argv) {
				operands = append(operands, i+1)
			}
			i++
			filter = false
		case options && (arg == "--indent" || arg == "-L"):
			i++
		case options && strings.HasPrefix(arg, "-") && arg != "-":
		case filter:
			filter = false
		default:
			operands = append(operands, i)
		}
	}
	return operands
}

// credentialInterpreterWords is the argv indexes of an interpreter's inline
// program (python -c, node -e/-p, perl and ruby -e/-E, php -r, deno eval,
// bun -e); of the files it reads as input: for perl and ruby with -n or -p,
// and after inline code that reads its arguments (credentialCodeReadsArgs,
// substrate-1:GAP-0349). Words after a script or module name are its
// arguments: no reads (rel-1-0-10:GAP-1030). A python -W or -X takes the
// next word as its value.
func credentialInterpreterWords(program string, argv []string) (code, inputs []int) {
	codeLetters, loopLetters, valued := "c", "", ""
	python := strings.HasPrefix(program, "python")
	switch program {
	case "node", "nodejs", "bun":
		codeLetters = "ep"
	case "perl", "ruby":
		codeLetters, loopLetters = "eE", "np"
	case "php":
		codeLetters = "r"
	case "deno":
		for i := 1; i+1 < len(argv); i++ {
			if argv[i] == "eval" {
				return []int{i + 1}, nil
			}
		}
		return nil, nil
	}
	if python {
		valued = "WX"
	}
	rest := func(from int) []int {
		var out []int
		for j := from; j < len(argv); j++ {
			out = append(out, j)
		}
		return out
	}
	loop := false
	readsArgs := func() bool {
		for _, index := range code {
			if credentialCodeReadsArgs(program, argv[index]) {
				return true
			}
		}
		return false
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			if loop || readsArgs() {
				inputs = append(inputs, rest(i+1)...)
			}
			return code, inputs
		case arg == "--eval" || arg == "--print":
			if i+1 < len(argv) {
				code = append(code, i+1)
			}
			i++
			if program != "node" && program != "nodejs" && program != "bun" {
				return code, inputs
			}
		case len(arg) == 2 && arg[0] == '-' && strings.IndexByte(valued, arg[1]) >= 0:
			i++ // python -W ignore, -X dev: the option's value
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1:
			takesCode := false
			for j, letter := range arg[1:] {
				if strings.ContainsRune(loopLetters, letter) {
					loop = true
				}
				if strings.ContainsRune(codeLetters, letter) {
					takesCode = j == len(arg)-2 // the code is the next word
					break
				}
				if letter == 'm' && python {
					return code, inputs // a module: the rest are its arguments
				}
			}
			if takesCode && i+1 < len(argv) {
				code = append(code, i+1)
				i++
				if python || program == "php" {
					// The rest are the program's arguments: files it reads
					// when its code reads them.
					if readsArgs() {
						inputs = append(inputs, rest(i+1)...)
					}
					return code, inputs
				}
			}
		case strings.HasPrefix(arg, "--"):
		default:
			if len(code) == 0 {
				return code, inputs // a script: the rest are its arguments
			}
			if loop || readsArgs() {
				inputs = append(inputs, i)
			}
		}
	}
	return code, inputs
}

// credentialCodeReadsArgs reports inline code that reads the files named by
// its arguments: perl's <> or <<>> and @ARGV, ruby's ARGF and ARGV, python's
// sys.argv (substrate-1:GAP-0349).
func credentialCodeReadsArgs(program, code string) bool {
	switch {
	case program == "perl":
		return strings.Contains(code, "<>") || strings.Contains(code, "ARGV")
	case program == "ruby":
		return strings.Contains(code, "ARGF") || strings.Contains(code, "ARGV")
	case strings.HasPrefix(program, "python"):
		return strings.Contains(code, "sys.argv")
	}
	return false
}

// credentialProgramEditsInPlace: sed -i, perl -i and ruby -i write the file
// they read instead of printing it.
func credentialProgramEditsInPlace(program string, argv []string) bool {
	var rest string // option letters that take the rest of the word as a value
	switch program {
	case "sed", "gsed":
		rest = "efl"
	case "perl":
		rest = "eEMmIlx0CdDF"
	case "ruby":
		rest = "eEIrCFxK"
	default:
		return false
	}
	for _, arg := range argv[1:] {
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--in-place") {
			return true
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		for _, letter := range arg[1:] {
			if letter == 'i' {
				return true
			}
			if strings.ContainsRune(rest, letter) {
				break
			}
		}
	}
	return false
}

// credentialSearchRecursive reports a grep that reads folders recursively
// (-r, -R, --recursive, --dereference-recursive, -d recurse) or an rg, which
// always does. A letter of a short-option word after one that takes the rest
// as its value (-e, -f, -m, ...) is that value, not an option.
func credentialSearchRecursive(argv []string, program string) bool {
	if program == "rg" {
		return true
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return false
		}
		switch arg {
		case "--recursive", "--dereference-recursive", "--directories=recurse":
			return true
		case "-d", "--directories":
			if i+1 < len(argv) && argv[i+1] == "recurse" {
				return true
			}
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		for _, letter := range arg[1:] {
			if letter == 'r' || letter == 'R' {
				return true
			}
			if strings.ContainsRune("ABCDdefm", letter) {
				break
			}
		}
		if searchOptionConsumesValue(program, arg) {
			i++ // the option's value
		}
	}
	return false
}

// programWord reads one word of an interpreter, stream editor or awk call:
// the whole word (a file operand) and the path words of its program text.
func (r *credentialPathResolver) programWord(id int64, argument ArgumentFact) {
	if argument.Expands {
		r.argument(id, argument, false)
		return
	}
	value := argument.Value
	if value == "" || !r.work.TakeN(len(value)) {
		return
	}
	if !strings.HasPrefix(value, "-") {
		r.candidate(id, value, false, false)
	}
	if !strings.ContainsFunc(value, credentialProgramSeparator) {
		return
	}
	for _, token := range strings.FieldsFunc(value, credentialProgramSeparator) {
		if r.stopped() {
			return
		}
		if strings.HasPrefix(token, "-") {
			continue
		}
		r.candidate(id, token, false, false)
	}
}

func credentialProgramSeparator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("'\"(){};,=", r)
}

// argument reads one read-position word: its static value, its glob, its
// $HOME spelling, or the literal text after its last expansion.
func (r *credentialPathResolver) argument(id int64, argument ArgumentFact, unknown bool) {
	switch {
	case argument.StaticGlob != "":
		r.candidate(id, argument.StaticGlob, true, true)
	case !argument.Expands:
		r.candidate(id, argument.Value, false, unknown)
	case argument.homeSpelling != "":
		r.candidate(id, argument.homeSpelling, false, unknown)
	case argument.holeText != "":
		// "$DIR/.env": the file is a credentials file, which one the call
		// does not say.
		tail := argument.holeText
		if index := strings.LastIndex(tail, awkprog.Hole); index >= 0 {
			tail = tail[index+len(awkprog.Hole):]
		}
		if strings.HasPrefix(tail, "/") {
			r.candidate(id, tail, false, true)
		}
	}
}

// candidate checks one word. A glob or an unknown read is file-unknown; an
// exact read keeps its value, and a read of a name the call linked, copied or
// moved a file to before it also reads that file.
func (r *credentialPathResolver) candidate(id int64, value string, glob, unknown bool) {
	if value == "" || strings.Contains(value, "://") || !strings.ContainsAny(value, "./_") || r.stopped() {
		return
	}
	if !r.candidates.Take() || !r.work.TakeN(len(value)) {
		return
	}
	if glob {
		if r.globNamesCredentialFile(value) {
			r.add(id, "", true)
		}
		return
	}
	if _, ok := MatchCredentialFileShape(value); ok {
		r.add(id, value, unknown)
	}
	if unknown {
		return
	}
	clean := path.Clean(value)
	for _, link := range r.links {
		if link.commandID < id && link.dst == clean {
			if !r.candidates.Take() || !r.work.TakeN(len(link.src)) {
				return
			}
			if _, ok := MatchCredentialFileShape(link.src); ok {
				r.add(link.commandID, link.src, false)
			}
		}
	}
}

// globNamesCredentialFile reports a glob that matches a probe of the
// credentials table on the probe's own trailing segments, a wildcard never
// matching a leading dot, with a literal byte in those segments.
func (r *credentialPathResolver) globNamesCredentialFile(glob string) bool {
	return r.globNamesCredentialFileDots(glob, false)
}

// globNamesCredentialFileDots is globNamesCredentialFile; with dots, a
// wildcard matches a leading dot too (find -name).
func (r *credentialPathResolver) globNamesCredentialFileDots(glob string, dots bool) bool {
	segments := trailingPathSegments(strings.ToLower(strings.TrimRight(glob, "/")), credentialProbeDepth())
	for _, probe := range credentialProbes() {
		if !r.work.Take() {
			return false
		}
		k := len(probe.segments)
		if len(segments) < k {
			continue
		}
		aligned := segments[len(segments)-k:]
		literal, match := false, true
		for i, pattern := range aligned {
			if !credentialGlobSegmentMatches(pattern, probe.segments[i], dots) {
				match = false
				break
			}
			literal = literal || credentialGlobHasLiteral(pattern)
		}
		if match && literal {
			return true
		}
	}
	return false
}

// trailingPathSegments is at most n trailing segments of value, in order,
// without splitting the rest of it.
func trailingPathSegments(value string, n int) []string {
	segments := make([]string, 0, n)
	for len(segments) < n {
		index := strings.LastIndexByte(value, '/')
		segments = append(segments, value[index+1:])
		if index < 0 {
			break
		}
		value = value[:index]
	}
	slices.Reverse(segments)
	return segments
}

func credentialGlobSegmentMatches(pattern, name string, dots bool) bool {
	if !dots && strings.HasPrefix(name, ".") && !strings.HasPrefix(pattern, ".") && !strings.HasPrefix(pattern, `\.`) {
		return false
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func credentialGlobHasLiteral(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*', '?':
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				return true
			}
			i += end + 1
		default:
			return true
		}
	}
	return false
}

// pipedStdin reports a command that reads a pipe: a later stage of its
// pipeline.
func (r *credentialPathResolver) pipedStdin(command CommandFact) bool {
	if command.PipelineID == 0 {
		return false
	}
	for _, other := range r.commands {
		if other.ID < command.ID && other.PipelineID == command.PipelineID && other.ParentCommandID == command.ParentCommandID {
			return true
		}
	}
	return false
}

// credentialWalkSkips are the folders a recursive search's walk does not
// enter: git's own store and the package trees whose files never start the
// chain (node_modules, site-packages, dist-packages).
var credentialWalkSkips = map[string]bool{
	".git": true, "node_modules": true, "site-packages": true, "dist-packages": true,
}

// searchFolder resolves the credentials files under the folder a recursive
// search reads, in it and in every folder below it (substrate-1:GAP-0344,
// credentialPathWalk); with hidden false (ripgrep's default), not in a
// dot-named file or folder. Only a regular file that is there counts (T6
// scope ruling: an ordinary repository search starts no chain). A walk cut
// at its bounds adds the file-unknown read: the chain's unknown tier, never
// a cap of the resolve, so the search itself is judged as it was before the
// walk (T6 ruling 2026-11-18).
func (r *credentialPathResolver) searchFolder(id int64, folder string, hidden bool) {
	dir := folder
	if strings.HasPrefix(dir, "~/") && r.home != "" {
		dir = filepath.Join(r.home, dir[2:])
	}
	if !filepath.IsAbs(dir) {
		if r.cwd == "" {
			return
		}
		dir = filepath.Join(r.cwd, dir)
	}
	if !r.lookups.Take() {
		return
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return
	}
	walk := credentialPathWalkOf(filepath.Clean(dir), hidden)
	for _, file := range walk.found {
		if r.stopped() {
			return
		}
		r.candidate(id, file, false, false)
	}
	if walk.cut {
		r.add(id, "", true)
	}
}

// credentialPathWalkResult is one walk: the credentials files it found and
// whether a bound cut it.
type credentialPathWalkResult struct {
	found []string
	cut   bool
	at    time.Time
}

type credentialPathWalkKey struct {
	dir    string
	hidden bool
}

// credentialPathWalks holds the walks of the last credentialPathWalkReuse
// (at most maxCredentialPathWalkMemo folders): every analysis of one hook
// call walks a folder once. A result is shared read-only.
var credentialPathWalks struct {
	sync.Mutex
	walks map[credentialPathWalkKey]credentialPathWalkResult
}

func credentialPathWalkOf(dir string, hidden bool) credentialPathWalkResult {
	key := credentialPathWalkKey{dir, hidden}
	now := time.Now()
	credentialPathWalks.Lock()
	walk, ok := credentialPathWalks.walks[key]
	credentialPathWalks.Unlock()
	if ok && !now.Before(walk.at) && now.Sub(walk.at) < credentialPathWalkReuse {
		return walk
	}
	walk = credentialPathWalk(dir, hidden)
	walk.at = now
	credentialPathWalks.Lock()
	defer credentialPathWalks.Unlock()
	if credentialPathWalks.walks == nil || len(credentialPathWalks.walks) >= maxCredentialPathWalkMemo {
		fresh := make(map[credentialPathWalkKey]credentialPathWalkResult)
		for other, kept := range credentialPathWalks.walks {
			if now.Sub(kept.at) < credentialPathWalkReuse && len(fresh) < maxCredentialPathWalkMemo/2 {
				fresh[other] = kept
			}
		}
		credentialPathWalks.walks = fresh
	}
	credentialPathWalks.walks[key] = walk
	return walk
}

// credentialPathWalk walks dir breadth first and reads each folder once,
// in batches of credentialPathWalkBatch entries; each entry named as the
// first segment of a credentials probe is looked up. It does not enter
// credentialWalkSkips or follow a symbolic link to a folder, as grep -r does
// not. With hidden false it neither counts nor enters a dot-named entry, and
// skips a probe with a dot-named segment, as ripgrep without --hidden. A
// bound (folders, entries, lookups) cuts it: what it found stays, and cut
// is set.
func credentialPathWalk(dir string, hidden bool) (walk credentialPathWalkResult) {
	groups := credentialProbeFirstSegments()
	folders, entries, lookups := 0, 0, 0
	// The folder searched may itself be the first segment of a probe
	// (rg KEY .aws, grep -r KEY ~/.aws): its own files are looked up
	// under it. It is read whatever its name, as the command names it.
	for _, probe := range groups[filepath.Base(dir)] {
		if len(probe.segments) < 2 {
			continue
		}
		rest := strings.Join(probe.segments[1:], "/")
		if !hidden && (strings.HasPrefix(rest, ".") || strings.Contains(rest, "/.")) {
			continue
		}
		if lookups == maxCredentialPathWalkLookups {
			walk.cut = true
			return walk
		}
		lookups++
		file := filepath.Join(dir, filepath.FromSlash(rest))
		if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
			walk.found = append(walk.found, file)
		}
	}
	queue := []string{dir}
	for len(queue) > 0 {
		if folders == maxCredentialPathWalkFolders {
			walk.cut = true
			return walk
		}
		folders++
		current := queue[0]
		queue = queue[1:]
		f, err := os.Open(current)
		if err != nil {
			continue
		}
		for {
			batch, err := f.ReadDir(credentialPathWalkBatch)
			for _, entry := range batch {
				if entries == maxCredentialPathWalkEntries {
					_ = f.Close()
					walk.cut = true
					return walk
				}
				entries++
				name := entry.Name()
				if !hidden && strings.HasPrefix(name, ".") {
					continue
				}
				for _, probe := range groups[name] {
					if !hidden && strings.Contains(probe.value, "/.") {
						continue
					}
					if lookups == maxCredentialPathWalkLookups {
						_ = f.Close()
						walk.cut = true
						return walk
					}
					lookups++
					file := filepath.Join(current, filepath.FromSlash(probe.value))
					if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
						walk.found = append(walk.found, file)
					}
				}
				if entry.IsDir() && !credentialWalkSkips[name] {
					queue = append(queue, filepath.Join(current, name))
				}
			}
			if err != nil {
				break // io.EOF, or a folder that cannot be read on
			}
		}
		_ = f.Close()
	}
	return walk
}

// rgSearchesHidden reports an rg that reads hidden (dot-named) files and
// folders. ripgrep's documented default skips them (and .gitignore'd
// paths, which are not modelled: a non-hidden file counts as read);
// --hidden (-.), --unrestricted twice (-uu, -uuu) and a --glob or --iglob
// override that may match a dot-named credentials file (globs override
// every other ignore rule) read them. --no-ignore-hidden counts as well;
// --no-hidden turns --hidden off again. A file or folder the command names
// is read whatever its name (credentialPathResolver.argument).
func rgSearchesHidden(argv []string) bool {
	hidden, unrestricted, glob := false, 0, false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		value := ""
		switch {
		case arg == "--":
			return hidden || unrestricted >= 2 || glob
		case arg == "--hidden" || arg == "--no-ignore-hidden":
			hidden = true
		case arg == "--no-hidden":
			hidden = false
		case arg == "--unrestricted":
			unrestricted++
		case arg == "--glob" || arg == "--iglob":
			if i+1 < len(argv) {
				i++
				value = argv[i]
			}
		case strings.HasPrefix(arg, "--glob=") || strings.HasPrefix(arg, "--iglob="):
			value = arg[strings.IndexByte(arg, '=')+1:]
		case strings.HasPrefix(arg, "--"):
			if searchOptionConsumesValue("rg", arg) {
				i++
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
		letters:
			for j, letter := range arg[1:] {
				switch {
				case letter == '.':
					hidden = true
				case letter == 'u':
					unrestricted++
				case strings.ContainsRune("ABCEefgjMmrtTd", letter):
					// The option's value is the rest of the word, or the next.
					rest := arg[2+j:]
					if rest == "" && i+1 < len(argv) {
						i++
						rest = argv[i]
					}
					if letter == 'g' {
						value = rest
					}
					break letters
				}
			}
		}
		if value != "" && rgGlobMayMatchHidden(value) {
			glob = true
		}
	}
	return hidden || unrestricted >= 2 || glob
}

// rgGlobMayMatchHidden reports an rg include glob that may match a
// dot-named segment of a credentials probe (an exclude glob, !..., never
// adds a read). A glob with alternation or classes path.Match does not
// read counts.
func rgGlobMayMatchHidden(glob string) bool {
	if strings.HasPrefix(glob, "!") {
		return false
	}
	glob = strings.ToLower(glob)
	if strings.ContainsAny(glob, "{}") {
		return true
	}
	last := glob[strings.LastIndexByte(glob, '/')+1:]
	for _, probe := range credentialProbes() {
		for _, segment := range probe.segments {
			if !strings.HasPrefix(segment, ".") {
				continue
			}
			if ok, err := path.Match(last, segment); ok || err != nil {
				return true
			}
		}
	}
	return false
}

func (r *credentialPathResolver) add(id int64, value string, unknown bool) {
	fact := PathFact{CommandID: id, Access: PathAccessRead, Flavor: PathFlavorPOSIX, Value: value}
	if unknown {
		fact.Value = ""
	} else {
		one := []PathFact{fact}
		normalizePathFactsForCommands(one, r.cwd, r.home, r.commands)
		fact = one[0]
		if r.held[credentialHeldRead{fact.CommandID, fact.Value}] {
			return
		}
	}
	if r.seen == nil {
		r.seen = make(map[PathFact]bool)
	}
	if !r.seen[fact] {
		r.seen[fact] = true
		r.reads = append(r.reads, fact)
	}
}

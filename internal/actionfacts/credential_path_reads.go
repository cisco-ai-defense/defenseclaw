// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// The bounds of the recursive searches' walks of one resolve, shared by
// every folder the call's searches name (substrate-1:GAP-0344, GAP-0672):
// the folders read, the entries read in them (in batches, so one huge
// folder costs no more than its share) and the files looked up. A walk
// cut at a bound is not a cap of the resolve, so it is no verdict on the
// search: the walk adds the chain's file-unknown read (Value ""), the
// unknown tier of the secret-read chain only (a later upload joins it), and
// what it found before the cut still counts. Exact numbers are kept in
// TestGAP0344WalkCut.
const (
	maxCredentialPathWalkFolders = 4096
	maxCredentialPathWalkEntries = 1 << 16
	maxCredentialPathWalkLookups = 1024
	credentialPathWalkWorkers    = 4
)

// credentialPathWalkSlots bounds the walks the process runs at once to
// max(2, GOMAXPROCS/4) (substrate-1:GAP-0674). The gateway answers many hook
// calls at once, up to a caller's 64 in flight, and each call that searches a
// folder recursively walks it. On Windows a walk of 2,047 folders under
// 2,000-character paths costs about 26 MB and 0.2 s of system calls, so 64
// of them at once held every walk's found paths and slowed one another: the
// gateway peaked at 1.3 to 2.3 GB on 2,048 such calls in a minute (1.0.10,
// which walks nothing: 0.45 to 0.6 GB). A walk waits for a slot before it
// reads anything, so a call that waits holds none of the walk's memory, and
// the walk's result is the one it would have had: nothing is cut or skipped.
var credentialPathWalkSlots = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)/4))

// HoldCredentialPathWalkSlotsForTest takes every walk slot, as walks of a slow
// folder hold them, and returns the function that gives them back. It is the
// seam of the gateway's hook-route test of the slot wait (substrate-1:GAP-1083);
// a slot that stays taken for 10 s reports ok false. Only _test.go files call
// it (TestGAP1083WalkSlotSeamsAreCalledOnlyByTests): a production caller that
// kept the slots would cut every walk to the unknown tier.
func HoldCredentialPathWalkSlotsForTest() (release func(), ok bool) {
	held := 0
	release = func() {
		for ; held > 0; held-- {
			<-credentialPathWalkSlots
		}
	}
	for range cap(credentialPathWalkSlots) {
		select {
		case credentialPathWalkSlots <- struct{}{}:
			held++
		case <-time.After(10 * time.Second):
			release()
			return func() {}, false
		}
	}
	return release, true
}

// credentialPathWalkSlotWaits counts the waits for a walk slot that began (a
// take that found every slot taken, its call with wait left and its context
// not done). A hook request waits once, whatever number of records and tool
// calls it resolves, so a test asserts the count of the request, not the time
// it took, which load moves (substrate-1:GAP-1083, RV-0674T F1).
var credentialPathWalkSlotWaits atomic.Int64

// CredentialWalkSlotWaitsForTest is the number of waits for a walk slot that
// began, in all. It is the seam of the gateway's hook-route test of the slot
// wait, beside HoldCredentialPathWalkSlotsForTest, and only _test.go files
// call it (TestGAP1083WalkSlotSeamsAreCalledOnlyByTests).
func CredentialWalkSlotWaitsForTest() int64 {
	return credentialPathWalkSlotWaits.Load()
}

// credentialPathWalkSlotWait is the longest one resolve waits for walk slots
// (substrate-1:GAP-1083). The slots are the gateway's, shared by every call:
// two walks of a slow folder (a home on an SMB share, sshfs or NFS) can hold
// them for seconds, and a call that waited for them without a limit answered
// past the hook's 3.5 s budget, where the client applies its fail mode. A walk
// that gets no slot in time is cut before it reads anything: probeUnder and
// the file-unknown read (searchFolder), as for a walk past its budget, the
// chain's unknown tier and no cap of the resolve.
const credentialPathWalkSlotWait = time.Second

// CredentialWalkBudget is what one hook call may still wait for walk slots,
// whatever number of records it resolves, and when the call is done. The
// dispatch makes one for the call and carries it on
// Input.CredentialWalkBudget, so the call's twins, statements and nested
// shells draw on the same wait: a wait per record answered a call with a
// wrapper or a second statement 1 s later for each, past the hook's budget
// (substrate-1:GAP-1083). It is safe for concurrent use; nil is no wait.
//
// It is a channel that holds its state (credentialWalkWait) between takes,
// and the state keeps the call's Done channel, never its context. Input and
// Facts carry the budget, and their readers walk them by reflection
// (mentionsString, the dispatch memos' reflect.DeepEqual), which never
// enters a channel: no reader reaches the time left or the call's context.
// A budget that held the context and a lock let mentionsString iterate the
// context's children while the rule evaluator cancelled one, a fatal
// concurrent map read (substrate-1:GAP-1110).
type CredentialWalkBudget chan credentialWalkWait

// credentialWalkWait is the state of a CredentialWalkBudget.
type credentialWalkWait struct {
	done <-chan struct{} // the call's Done (nil: the call is never done)
	left time.Duration
}

// NewCredentialWalkBudget is the wait of one hook call judged within ctx.
func NewCredentialWalkBudget(ctx context.Context) CredentialWalkBudget {
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}
	return newCredentialWalkBudget(done, credentialPathWalkSlotWait)
}

func newCredentialWalkBudget(done <-chan struct{}, left time.Duration) CredentialWalkBudget {
	w := make(CredentialWalkBudget, 1)
	w <- credentialWalkWait{done: done, left: left}
	return w
}

// take takes a walk slot: a free one at once, else the first one freed within
// what the call may still wait. A call whose context is done (its client has
// gone, its deadline has passed) waits for nothing, so it holds no place
// among the walks that wait; a slot that is free is still its own, as it was
// before the slots had a wait.
func (w CredentialWalkBudget) take() bool {
	select {
	case credentialPathWalkSlots <- struct{}{}:
		return true
	default:
	}
	if w == nil {
		return false
	}
	state := <-w
	w <- state
	select {
	case <-state.done:
		return false
	default:
	}
	if state.left <= 0 {
		return false
	}
	credentialPathWalkSlotWaits.Add(1)
	start := time.Now()
	timer := time.NewTimer(state.left)
	defer func() {
		timer.Stop()
		spent := <-w
		spent.left = max(0, spent.left-time.Since(start))
		w <- spent
	}()
	select {
	case credentialPathWalkSlots <- struct{}{}:
		return true
	case <-timer.C:
	case <-state.done:
	}
	return false
}

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
	record := f.credentialPaths.get()
	if record == nil {
		return nil
	}
	return slices.Clone(record.reads)
}

// HasCredentialPathReads reports a read in the private record.
func (f Facts) HasCredentialPathReads() bool {
	record := f.credentialPaths.get()
	return record != nil && len(record.reads) != 0
}

// CredentialPathReadCaps is the caps the resolve hit: TRUNCATED, the one
// bound rule.
//
// The dispatch reads them first, with the call's context: a resolve that
// waits for a walk slot stops waiting when the call is done
// (substrate-1:GAP-1083).
func (f Facts) CredentialPathReadCaps(ctx context.Context) bounded.CapSet {
	record := f.credentialPaths.getWithin(ctx)
	if record == nil {
		return bounded.CapSet{}
	}
	return record.caps
}

// PlaceCredentialPathReads is facts with each relative read of the private
// record placed under reported, the directory the hook reports, by the
// lexical rule the gateway places ordinary reads with. It adds no read and
// leaves the facts it was called on as they are.
func (f Facts) PlaceCredentialPathReads(reported string) Facts {
	record := f.credentialPaths.get()
	if record == nil || len(record.reads) == 0 {
		return f
	}
	placed := &credentialPathRecord{reads: slices.Clone(record.reads), caps: record.caps}
	for i, candidate := range placed.reads {
		if candidate.CredentialReadPlaceable() {
			placed.reads[i].Resolved = path.Join(reported, candidate.Value)
		}
	}
	f.credentialPaths = &credentialPathResult{record: placed}
	return f
}

// CredentialReadPlaceable reports a read of the private record that
// PlaceCredentialPathReads places under the directory the hook reports: a
// plain relative POSIX spelling the resolve could not place.
func (f PathFact) CredentialReadPlaceable() bool {
	value := f.Value
	return !f.Absolute && f.Resolved == "" && f.Flavor != PathFlavorWindows &&
		value != "" && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "~") &&
		!strings.ContainsAny(value, "\\$*?[]{}`\x00")
}

// ThinCredentialPathReads keeps, of a private record of more than whole
// reads, the reads keep marks (keep returns one mark per read, in order) and
// drops the others, for every copy of the facts (substrate-1:GAP-0674). The
// caps stay as they are, the kept reads keep their order and are not
// changed, and a record that had a read keeps at least one. A recursive
// search of a deep tree has hundreds of reads of paths thousands of bytes
// long, and the facts of the call are kept until its verdict is written,
// behind every check of the call that comes after the resolve. The caller
// marks the reads its checks can still tell apart; the record is never read
// in full after that. A mark list of another length changes nothing.
func (f Facts) ThinCredentialPathReads(whole int, keep func(reads []PathFact) []bool) {
	l := f.credentialPaths
	record := l.get()
	if record == nil || len(record.reads) <= whole {
		return
	}
	marks := keep(record.reads)
	if len(marks) != len(record.reads) {
		return
	}
	var reads []PathFact
	for i, kept := range marks {
		if kept {
			reads = append(reads, record.reads[i])
		}
	}
	if len(reads) == len(record.reads) {
		return
	}
	if len(reads) == 0 {
		reads = []PathFact{record.reads[0]}
	}
	thinned := &credentialPathRecord{reads: slices.Clip(reads), caps: record.caps}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.record == record {
		l.record = thinned
	}
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
	walkUsed   credentialPathWalkLimits // the walk budget the searches read
	wait       CredentialWalkBudget     // the wait for walk slots left, the call's
	// walkedBy holds the folders each command already searched, as named
	// and as resolved: a folder named again by the same command adds
	// nothing, so grep -r K . . . walks it once (rel-1-0-10:GAP-1668).
	walkedBy map[credentialWalkKey]bool
	// rgConfig: the call sets RIPGREP_CONFIG_PATH, so an rg may read
	// options (--hidden) from a file (substrate-1:GAP-0682).
	rgConfig bool
	seen     map[PathFact]bool
	reads    []PathFact
	// ignoreGlobs holds the whitelist globs of each ignore file the
	// resolve looked up (nil: none there), so the folders above many
	// searched folders are read once per call; ignoreChecks counts those
	// lookups, on their own bound (rgIgnoreFileChecks), never the lookups
	// budget (rel-1-0-10:GAP-1652).
	ignoreGlobs  map[string][]rgGlob
	ignoreChecks int
}

// credentialPathResult is the private record of one parse, made by the
// resolve the first time it is read (substrate-1:GAP-0709). The hook parses
// one call about fifteen times (the call, its twins, its rule packs) and
// reads the record of one of them, so the other parses no longer resolve,
// and a recursive search walks its folders once per call, from the
// filesystem as it is then: no walk is kept for a later resolve
// (rel-1-0-10:GAP-1045, substrate-1:GAP-0674). Copies of the Facts share
// it; it is safe for concurrent use.
type credentialPathResult struct {
	once sync.Once
	// mu guards record once resolved: ThinCredentialPathReads replaces it.
	mu      sync.Mutex
	record  *credentialPathRecord
	pending bool // the resolve has not run: the input below is its own
	// budget is the wait of the call the parse belongs to (nil: the resolve
	// has its own, within the context it is read with). A channel: no
	// reflection over Facts reaches its state (substrate-1:GAP-1110).
	budget CredentialWalkBudget
	// The resolve's input, a copy of the parse's, dropped once resolved.
	words    []credentialPathWord
	cwd      string
	home     string
	commands []CommandFact
	paths    []PathFact
}

// lazyCredentialPathReads is the private record of a parse, resolved when
// it is first read; nil when the call has nothing to resolve.
func lazyCredentialPathReads(words []credentialPathWord, cwd, home string, commands []CommandFact, paths []PathFact) *credentialPathResult {
	if !credentialPathResolveNeeded(words, commands) {
		return nil
	}
	return &credentialPathResult{
		pending: true,
		words:   cloneSlice(words), cwd: cwd, home: home,
		commands: cloneCommands(commands), paths: cloneSlice(paths),
	}
}

func (l *credentialPathResult) get() *credentialPathRecord {
	return l.getWithin(context.Background())
}

// getWithin is get, the resolve (when it runs now) within ctx.
func (l *credentialPathResult) getWithin(ctx context.Context) *credentialPathRecord {
	if l == nil {
		return nil
	}
	l.once.Do(func() {
		if l.pending {
			wait := l.budget
			if wait == nil {
				wait = NewCredentialWalkBudget(ctx)
			}
			l.record = resolveCredentialPathReads(wait, l.words, l.cwd, l.home, l.commands, l.paths)
		}
		l.pending, l.words, l.commands, l.paths = false, nil, nil, nil
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.record
}

// resolveCredentialPathReads makes the private record of one call (nil when
// the call reads no credentials file the record adds and no cap was hit).
func resolveCredentialPathReads(wait CredentialWalkBudget, words []credentialPathWord, cwd, home string, commands []CommandFact, paths []PathFact) *credentialPathRecord {
	return resolveCredentialPathReadsWithin(wait, defaultCredentialPathLimits, words, cwd, home, commands, paths)
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
	wait CredentialWalkBudget,
	limits credentialPathLimits,
	words []credentialPathWord,
	cwd, home string,
	commands []CommandFact,
	paths []PathFact,
) *credentialPathRecord {
	if !credentialPathResolveNeeded(words, commands) {
		return nil
	}
	r := &credentialPathResolver{cwd: cwd, home: home, commands: commands, wait: wait}
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
	r.rgConfig = slices.ContainsFunc(words, func(word credentialPathWord) bool {
		return word.role == credentialWordAssignment && word.name == "RIPGREP_CONFIG_PATH"
	}) || slices.ContainsFunc(r.commands, func(command CommandFact) bool {
		// export, declare, env ... RIPGREP_CONFIG_PATH=FILE
		return slices.ContainsFunc(command.Argv, func(word string) bool {
			return strings.HasPrefix(word, "RIPGREP_CONFIG_PATH=")
		})
	})
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
	// expandingRead: readers with a read operand that expands, the only
	// place a substitution's output is read (rel-1-0-10:GAP-1047).
	expandingRead := make(map[int64]bool)
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
			if index < len(command.Arguments) && command.Arguments[index].Expands {
				expandingRead[command.ID] = true
			}
		}
		readOperands[command.ID] = positions
		if command.ParentCommandID != 0 {
			readerParents[command.ParentCommandID] = true
		}
	}
	// An input redirect that expands reads what it expands to, whatever
	// the command: cat < "$(echo .env)" reads the echo's output.
	for _, word := range words {
		if word.role == credentialWordInputRedirect && word.argument.Expands {
			expandingRead[word.commandID] = true
		}
	}
	// A reader's operand or an input redirect built by a substitution
	// (cat "$(echo .env)", cat < "$(echo .env)") reads what the substituted
	// echo or printf prints, and a find whose -exec runs a reader reads the
	// files its name tests match: which file, the call does not say. A
	// substitution in a reader's other words (the pattern of
	// grep "$(echo .env)" .gitignore) reads nothing: the reader needs a read
	// operand or an input redirect that expands.
	for _, command := range r.commands {
		if r.stopped() {
			return
		}
		if !credentialPathCommandReadable(command) {
			continue
		}
		switch {
		case (command.Program == "echo" || command.Program == "printf") && expandingRead[command.ParentCommandID]:
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
		if program == "rg" {
			argv = rgArgvWords(command)
		}
		fromOption, patternFiles := searchPatternOptions(argv, program)
		for _, file := range patternFiles {
			r.candidate(command.ID, file, false, false)
		}
		operands = searchOperandIndexes(argv, program)
		if !fromOption && len(operands) > 0 {
			operands = operands[1:]
		}
		recursive := credentialSearchRecursive(argv, program)
		// grep -r reads every file under the folder that its --include,
		// --exclude and --exclude-dir globs admit (rel-1-0-10:GAP-1047);
		// ripgrep skips hidden (dot-named) files and folders unless told
		// otherwise (substrate-1:GAP-0344), and searches only what its
		// globs and types select (substrate-1:GAP-0683). A call that sets
		// RIPGREP_CONFIG_PATH may give rg any option from a file: every
		// file counts (substrate-1:GAP-0682).
		var filter credentialWalkFilter
		if recursive {
			switch {
			case program != "rg":
				filter.grep = credentialSearchFilterOf(command)
			case r.rgConfig:
				filter.rg = rgFilterAll
			default:
				filter.rg = rgSearchFilterOf(command, argv, r.rgWorkingFolder(command))
			}
		}
		bases, placed := r.searchWorkFolders(command, program != "rg")
		for _, index := range operands {
			argument := command.Arguments[index]
			r.argument(command.ID, argument, false)
			if folder := r.searchFolderWord(argument); recursive && folder != "" {
				for _, base := range bases {
					r.searchFolder(command.ID, folder, base, placed, filter)
				}
			}
		}
		if recursive && len(operands) == 0 && (program != "rg" || (!r.pipedStdin(command) && !parseRgCommandLine(argv).stdin)) {
			// No folder operand: grep -r and rg search the working folder
			// (an rg fed by a pipe, or given -, searches its input instead,
			// substrate-1:GAP-0344).
			for _, base := range bases {
				r.searchFolder(command.ID, ".", base, placed, filter)
			}
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
	for _, token := range credentialProgramReadTokens(value) {
		if r.stopped() {
			return
		}
		r.candidate(id, token, false, false)
	}
}

// credentialProgramReadTokens returns the words of program text the program
// may read: every word but an option and a word the program only prints or
// writes (rel-1-0-10:GAP-1047). Those are a word whose innermost call is a
// print, log or write call (print('copy .env.example to .env'),
// fs.writeFileSync('.env', ...), open('.env', 'w')), a word right after a
// bare print verb (puts ".env"), and the target of an awk output redirect or
// pipe (print > ".env"). A word inside a read call stays, however it is
// nested: print(open('.env').read()) reads .env. A print, log or write name
// the text binds itself (credentialProgramBoundNames: info=open, import
// open as log) may be any call, a read among them, so it is no print verb
// there (rel-1-0-10:GAP-1653).
func credentialProgramReadTokens(text string) []string {
	var tokens, calls []string
	var quote rune
	prev, start := "", -1
	var bound map[string]bool
	boundRead := false
	nonRead := func(name string) bool {
		if !boundRead {
			bound, boundRead = credentialProgramBoundNames(text), true
		}
		return !bound[name]
	}
	emit := func(end int) {
		if start < 0 {
			return
		}
		token := text[start:end]
		start = -1
		verb := strings.ToLower(prev)
		skip := strings.HasPrefix(token, "-") || prev == ">" || prev == ">>" || prev == "|" ||
			credentialProgramPrintVerbs[verb] && nonRead(verb)
		if !skip && len(calls) > 0 {
			skip = credentialProgramNonReadCall(calls[len(calls)-1], text[end:], nonRead)
		}
		prev = token
		if !skip {
			tokens = append(tokens, token)
		}
	}
	for i, c := range text {
		if !credentialProgramSeparator(c) {
			if start < 0 {
				start = i
			}
			continue
		}
		name := ""
		if start >= 0 {
			name = text[start:i]
		}
		emit(i)
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			calls = append(calls, name)
		case c == ')':
			if len(calls) > 0 {
				calls = calls[:len(calls)-1]
			}
		}
	}
	emit(len(text))
	return tokens
}

// credentialProgramPrintVerbs are calls and statements that print or log
// their arguments, by their last name segment, lower case.
var credentialProgramPrintVerbs = map[string]bool{
	"print": true, "println": true, "printf": true, "sprintf": true, "puts": true, "say": true,
	"echo": true, "warn": true, "log": true, "info": true, "debug": true, "error": true,
	"format": true, "write": true, "writeln": true, "writelines": true,
}

// credentialProgramWriteCalls write or create the file their first argument
// names, by their last name segment, lower case.
var credentialProgramWriteCalls = map[string]bool{
	"writefile": true, "writefilesync": true, "appendfile": true, "appendfilesync": true,
	"write_text": true, "write_bytes": true, "createwritestream": true,
	"mkdir": true, "mkdirsync": true, "makedirs": true, "touch": true,
}

// credentialProgramWriteMode matches the rest of an open call after its file
// argument when the call opens it to write only: , 'w' / , "a" / , mode="wb".
var credentialProgramWriteMode = regexp.MustCompile(`^['"]?\s*,\s*(?:mode\s*=\s*)?['"][wax][bt]?['"]`)

// credentialProgramNonReadCall reports a call that prints, logs or writes
// its arguments rather than reading a file they name. rest is the program
// text after the word; unbound reports a print or write name the text does
// not bind to something else.
func credentialProgramNonReadCall(call, rest string, unbound func(name string) bool) bool {
	name := strings.ToLower(call[strings.LastIndexAny(call, ".:$@")+1:])
	switch {
	case credentialProgramPrintVerbs[name], credentialProgramWriteCalls[name]:
		return unbound(name)
	case name == "open" || name == "opensync":
		return credentialProgramWriteMode.MatchString(rest)
	}
	return false
}

// credentialProgramBinding matches a name program text binds, by its last
// name segment: an assignment (info=open, $log = \&open, const debug =
// fs.readFileSync; not ==), an import alias (open as info) and a definition
// (def info, function log, sub say).
var credentialProgramBinding = regexp.MustCompile(`(?i)(?:([A-Za-z_][A-Za-z0-9_]*)\s*=(?:[^=~]|$)|\bas\s+([A-Za-z_][A-Za-z0-9_]*)|\b(?:def|function|sub)\s+([A-Za-z_][A-Za-z0-9_]*))`)

// credentialProgramBoundNames returns the names, lower case, program text
// binds (credentialProgramBinding): such a name may stand for a read call,
// so it does not only print or write (rel-1-0-10:GAP-1653).
func credentialProgramBoundNames(text string) map[string]bool {
	var names map[string]bool
	for _, match := range credentialProgramBinding.FindAllStringSubmatch(text, -1) {
		for _, name := range match[1:] {
			if name == "" {
				continue
			}
			if names == nil {
				names = make(map[string]bool)
			}
			names[strings.ToLower(name)] = true
		}
	}
	return names
}

// credentialSearchFilter keeps, of grep -r's credentials-file probes,
// those it opens (rel-1-0-10:GAP-1047): grep reads a name as its last
// matching --include or --exclude says, and never one in a folder its
// --exclude-dir globs match. The zero filter searches every probe. rg's
// filter is rgFilter.
type credentialSearchFilter struct {
	// names are grep's --include (include) and --exclude globs in command
	// order; excludeDir its --exclude-dir globs.
	names      []credentialSearchGlob
	excludeDir []string
}

type credentialSearchGlob struct {
	glob    string
	include bool
}

func credentialSearchFilterOf(command CommandFact) credentialSearchFilter {
	argv := command.Argv
	// spelled: the word is the literal argv text (no expansion, no glob).
	spelled := func(i int) bool {
		return i >= len(command.Arguments) || !command.Arguments[i].Expands && command.Arguments[i].StaticGlob == ""
	}
	var filter credentialSearchFilter
	// add records one option's glob. A glob the call does not spell is,
	// for --include, the unquoted glob itself (a file matching it can only
	// narrow it) or "*" (any name); for --exclude and --exclude-from (whose
	// patterns GNU grep adds to the same ordered list) an exclude that
	// matches no name, kept in its place so a later --include never becomes
	// the first option; for --exclude-dir nothing. Either way the filter
	// keeps every name the search might read.
	add := func(option, glob string, known bool) {
		switch option {
		case "--include":
			if !known {
				glob = "*"
			}
			filter.names = append(filter.names, credentialSearchGlob{glob, true})
		case "--exclude", "--exclude-from":
			if !known || option == "--exclude-from" {
				// path.Match("", name) is false for every file name.
				glob = ""
			}
			filter.names = append(filter.names, credentialSearchGlob{glob, false})
		case "--exclude-dir":
			if known {
				filter.excludeDir = append(filter.excludeDir, glob)
			}
		}
	}
	// abbreviated: grep's getopt_long takes any unambiguous prefix of a long
	// option (--incl, --exclude-f). Such a word switches the name filter off
	// (every name is read, as on rel) instead of guessing which option it is.
	abbreviated := false
	abbreviates := func(name string) bool {
		if len(name) <= 2 || !strings.HasPrefix(name, "--") || name == "--exclude" {
			return false
		}
		for _, option := range []string{"--include", "--exclude", "--exclude-dir", "--exclude-from"} {
			if len(name) < len(option) && strings.HasPrefix(option, name) {
				return true
			}
		}
		return false
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			break
		}
		if !spelled(i) {
			argument := command.Arguments[i]
			name, _, named := strings.Cut(argument.staticPrefix, "=")
			switch prefix := argument.staticPrefix; {
			case strings.HasPrefix(argument.StaticGlob, "--include="):
				add("--include", strings.TrimPrefix(argument.StaticGlob, "--include="), true)
			case named && abbreviates(name):
				// --incl="$X", --inc=$X, --exclude-f=$F: as a spelled
				// abbreviation (rel-1-0-10:GAP-1666).
				abbreviated = true
			case strings.HasPrefix(prefix, "--include"), strings.HasPrefix("--include=", prefix):
				// --include="$X", or a word that may expand to an --include
				// ("$X", -"$X", --"$X", --inc"$X"): an include of every name
				// from here on, so an earlier --exclude hides nothing grep
				// may read (rel-1-0-10:GAP-1666), as rg's unspelled word
				// turns hidden on.
				add("--include", "", false)
			case strings.HasPrefix(prefix, "--exclude-dir"):
				add("--exclude-dir", "", false)
			case strings.HasPrefix(prefix, "-"):
				// --exclude="$X", --exclude-from="$F", or a word that may
				// expand to either: an exclude grep may read in this place.
				add("--exclude", "", false)
			}
			continue
		}
		if name, _, _ := strings.Cut(arg, "="); abbreviates(name) {
			abbreviated = true
		}
		for _, option := range []string{"--include", "--exclude", "--exclude-dir", "--exclude-from"} {
			switch {
			case strings.HasPrefix(arg, option+"="):
				add(option, strings.TrimPrefix(arg, option+"="), true)
			case arg == option && i+1 < len(argv):
				i++
				if spelled(i) {
					add(option, argv[i], true)
				} else if glob := command.Arguments[i].StaticGlob; glob != "" && option == "--include" {
					add(option, glob, true)
				} else {
					add(option, "", false)
				}
			}
		}
	}
	if abbreviated {
		filter.names = nil
	}
	return filter
}

// searches reports whether grep opens the probe whose path under a folder it
// enters is segments.
func (f credentialSearchFilter) searches(segments []string) bool {
	base := segments[len(segments)-1]
	if len(f.names) > 0 {
		// GNU grep: the last --include or --exclude that matches the name
		// wins; a name none matches is read unless the first is --include.
		// An --include glob the matcher cannot read matches: the file is
		// read.
		read := !f.names[0].include
		for _, name := range f.names {
			if ok, valid := grepGlobMatch(name.glob, base); ok || !valid && name.include {
				read = name.include
			}
		}
		if !read {
			return false
		}
	}
	for _, dir := range segments[:len(segments)-1] {
		if !f.enters(dir) {
			return false
		}
	}
	return true
}

// enters reports a folder grep -r enters: none its --exclude-dir globs
// match.
// An --exclude-dir glob the matcher cannot read excludes nothing: the
// folder is read.
func (f credentialSearchFilter) enters(name string) bool {
	for _, glob := range f.excludeDir {
		if ok, _ := grepGlobMatch(glob, name); ok {
			return false
		}
	}
	return true
}

// credentialWalkFilter is what a recursive search's walk reads: rg's
// filter (its hidden rule, globs and types), or, with no rg filter, grep
// -r's --include, --exclude and --exclude-dir globs.
type credentialWalkFilter struct {
	rg   *rgFilter
	grep credentialSearchFilter
}

// admits reports a probe path under the folder rg names parent.
func (f credentialWalkFilter) admits(parent string, segments []string) bool {
	if f.rg != nil {
		return f.rg.admits(parent, segments)
	}
	return f.grep.searches(segments)
}

// enters reports a folder the search enters; shown is its path as rg names
// it (readsPath), name its own name.
func (f credentialWalkFilter) enters(shown, name string) bool {
	if f.rg != nil {
		return f.rg.enters(shown, name)
	}
	return f.grep.enters(name)
}

// readsPath reports a filter that reads the path as rg names it: an rg
// glob.
func (f credentialWalkFilter) readsPath() bool {
	return f.rg != nil && len(f.rg.globs) > 0
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

// credentialCandidateCounted reports a word candidate takes of the resolve's
// caps: one candidate and its length in work. Any other word (empty, a URL,
// without a dot, slash or underscore) takes nothing.
func credentialCandidateCounted(value string) bool {
	return value != "" && !strings.Contains(value, "://") && strings.ContainsAny(value, "./_")
}

// credentialWalkRoom is what the resolve can still take of the files a walk
// finds, in the order the walk finds them (the resolver reads them with
// candidate, which takes one candidate and the file's length in work). The
// first file past it trips the resolve's cap, which stops the resolve, so the
// files after that one are never read: the walk keeps none of them.
type credentialWalkRoom struct {
	candidates, work int
	over             bool
}

// admit reports whether the walk keeps file. The file that trips a cap is kept
// (the resolve trips on it as before, and records the cap); the files after it
// are not.
func (room *credentialWalkRoom) admit(file string) bool {
	if room.over {
		return false
	}
	if !credentialCandidateCounted(file) {
		return true
	}
	room.candidates--
	room.work -= len(file)
	room.over = room.candidates < 0 || room.work < 0
	return true
}

// walkRoom is the room the files of a walk of this resolve can take. A resolve
// that has stopped reads none: the first file found is kept so that the
// resolve sees a walk with files and stops, as it did with the whole list.
func (r *credentialPathResolver) walkRoom() credentialWalkRoom {
	if r.stopped() {
		return credentialWalkRoom{}
	}
	return credentialWalkRoom{candidates: r.candidates.Left(), work: r.work.Left()}
}

// credentialWalkRoomOf is the walk room of a resolve (walkRoom). The walk
// room differential swaps in a room that keeps every file, the resolve
// before substrate-1:GAP-0674, as its reference.
var credentialWalkRoomOf = (*credentialPathResolver).walkRoom

// candidate checks one word. A glob or an unknown read is file-unknown; an
// exact read keeps its value, and a read of a name the call linked, copied or
// moved a file to before it also reads that file.
func (r *credentialPathResolver) candidate(id int64, value string, glob, unknown bool) {
	if !credentialCandidateCounted(value) || r.stopped() {
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
			// path.Match scans the pattern: charge the bytes it reads
			// (rel-1-0-10:GAP-1046).
			if !r.work.TakeN(len(pattern)) {
				return false
			}
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

// searchWorkFolders are the folders a recursive search of command reads a
// relative folder operand in: the call's folder, or the ones the static cd
// steps before it reach. placed is false where a cd moved the search to a
// folder the walk cannot place (bases is then one ""). A relative folder was
// joined to the call's folder whatever cd came before, so cd ~/.config &&
// grep -r KEY gh read nothing (substrate-1 GAP-0925).
//
// A cd that may fail (cd P; grep -r KEY .) leaves the search in more than
// one folder. When every one of them is a static folder, a grep search
// (each) walks each, as the shell runs it in one of them; only an unresolved
// folder is the file-unknown read. GAP-0925 read every such call as unplaced,
// so an ordinary `cd /proj/docs; grep -rn TODO .` joined the chain's unknown
// tier, and a later upload or scp alerted where 1.0.10 allowed (DET111 bar
// p2hookc). rg (each false) keeps the unplaced reading: its globs match from
// one working folder (rgWorkingFolder).
func (r *credentialPathResolver) searchWorkFolders(command CommandFact, each bool) (bases []string, placed bool) {
	unplaced := []string{""}
	if command.Dialect != DialectPOSIX {
		return []string{r.cwd}, !windowsWorkFolders(r.commands)[command.ID].moved()
	}
	folders := command.workFolders
	if !folders.moved() {
		return []string{r.cwd}, r.outerCommandsStay(command)
	}
	if len(folders) == 1 {
		logical, ok := resolveWorkFolder(filepath.ToSlash(r.cwd), r.home, folders[0])
		return []string{filepath.FromSlash(logical)}, ok
	}
	if !each {
		return unplaced, false
	}
	for _, folder := range folders {
		logical, ok := resolveWorkFolder(filepath.ToSlash(r.cwd), r.home, folder)
		if !ok || logical != "" && !simplePathAbs(logical) {
			return unplaced, false
		}
		if logical == "" {
			// The hook folder when the hook gives none (its folder is not
			// there): read as a search that does not move is, no folder and
			// no walk, while the folder the cd reaches is still walked.
			continue
		}
		if base := filepath.FromSlash(logical); !slices.Contains(bases, base) {
			bases = append(bases, base)
		}
	}
	return bases, true
}

// searchFolderWord is the folder a recursive search's operand names: its
// static value, or the home folder an unquoted ~/ word names when the call
// does not rebind HOME (ArgumentFact.homeTilde). The trusted home rewrite
// places ~ in a lone command only, so in a list (a cd, a function call
// before the search) the folder was never walked: `f(){ test -d .git &&
// return; cd /; }; f && rg -g '/.env' KEY ~/proj` read proj/.env and
// started no chain (substrate-1:GAP-0689, live TST-6432).
func (r *credentialPathResolver) searchFolderWord(argument ArgumentFact) string {
	if !argument.Expands {
		return argument.Value
	}
	if r.home == "" {
		return ""
	}
	return argument.homeTilde
}

// searchFolder resolves the credentials files under the folder a recursive
// search reads, in it and in every folder below it (substrate-1:GAP-0344,
// credentialPathWalk); for ripgrep, only the files and folders its filter
// admits (rgFilter: its hidden rule, globs and types). Only a regular file that is there counts (T6
// scope ruling: an ordinary repository search starts no chain). Every walk
// of one resolve shares one walk budget (substrate-1:GAP-0672): a call
// naming many folders costs no more than one walk at the bound. A walk cut
// at the budget, and every folder named after it is spent, adds the
// file-unknown read: the chain's unknown tier, never a cap of the resolve,
// so the search itself is judged as it was before the walk (T6 ruling
// 2026-11-18).
func (r *credentialPathResolver) searchFolder(id int64, folder, base string, placed bool, filter credentialWalkFilter) {
	dir := folder
	if strings.HasPrefix(dir, "~/") && r.home != "" {
		dir = filepath.Join(r.home, dir[2:])
	} else if dir == "~" && r.home != "" {
		dir = r.home
	}
	if !filepath.IsAbs(dir) {
		if !placed {
			// A cd the walk cannot follow moved the search: the folder
			// may hold any file (substrate-1 GAP-0925).
			r.add(id, "", true)
			return
		}
		if base == "" {
			return
		}
		dir = filepath.Join(base, dir)
	}
	// The folder as rg names its paths: the shell expands ~/.
	shown := folder
	if (shown == "~" || strings.HasPrefix(shown, "~/")) && r.home != "" {
		shown = r.home + shown[1:]
	}
	key := credentialWalkKey{id: id, dir: filepath.Clean(dir), shown: shown}
	if r.walkedBy[key] {
		return
	}
	if r.walkedBy == nil {
		r.walkedBy = make(map[credentialWalkKey]bool)
	}
	r.walkedBy[key] = true
	if !r.lookups.Take() {
		return
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return
	}
	dir, shown = filepath.Clean(dir), filepath.ToSlash(shown)
	// rg reads the ignore files of the folder and of every folder above
	// it: a whitelist line there lifts its hidden rule for the names it
	// matches (rel-1-0-10:GAP-1652). Past the bound of those lookups the
	// hidden rule is off: count when unsure.
	read := map[string]bool{}
	if filter.rg.readsIgnoreFiles() {
		if globs, ok := r.ignoreWhitelistAbove(dir, read); ok {
			filter.rg = filter.rg.withWhitelist(globs)
		} else {
			filter.rg = filter.rg.withHidden()
		}
	}
	r.probeWithin(id, dir, shown, filter)
	left := credentialPathWalkBounds.minus(r.walkUsed)
	if left.spent() {
		r.probeUnder(id, dir, shown, filter)
		r.add(id, "", true)
		return
	}
	walk := credentialPathWalk(r.wait, dir, shown, filter, left, credentialWalkRoomOf(r))
	r.walkUsed = r.walkUsed.plus(walk.used)
	if filter.rg.readsIgnoreFiles() && !walk.cut {
		// An ignore file below the folder whitelists more names: walk again
		// with them, once (a whitelist line there is rare). Past the bound
		// of the ignore-file lookups, walk again with the hidden rule off.
		var globs []rgGlob
		unsure := false
		for _, file := range walk.ignores {
			if read[file] {
				continue
			}
			read[file] = true
			found, ok := r.ignoreFileWhitelist(file, true)
			if !ok {
				unsure = true
				break
			}
			globs = append(globs, found...)
		}
		if unsure || len(globs) > 0 {
			if unsure {
				filter.rg = filter.rg.withHidden()
			} else {
				filter.rg = filter.rg.withWhitelist(globs)
			}
			if left = credentialPathWalkBounds.minus(r.walkUsed); !left.spent() {
				again := credentialPathWalk(r.wait, dir, shown, filter, left, credentialWalkRoomOf(r))
				r.walkUsed = r.walkUsed.plus(again.used)
				// The second walk's filter admits all the first one did:
				// a file both found is judged once.
				first := make(map[string]bool, len(walk.found))
				for _, file := range walk.found {
					first[file] = true
				}
				for _, file := range again.found {
					if !first[file] {
						walk.found = append(walk.found, file)
					}
				}
				walk.cut = again.cut
			} else {
				walk.cut = true
			}
		}
	}
	for _, file := range walk.found {
		if r.stopped() {
			return
		}
		r.candidate(id, file, false, false)
	}
	if walk.cut {
		r.probeUnder(id, dir, shown, filter)
		r.add(id, "", true)
	}
}

// rgIgnoreFileChecks bounds the ignore files one resolve looks up for
// whitelist lines, each at most once (rel-1-0-10:GAP-1652): a folder and
// every folder above it, three names each, and the ignore files the walks
// meet. The bound is its own, not the lookups budget, so many searched
// folders never cut the resolve; past it, rg is taken to search hidden
// names (count when unsure).
const rgIgnoreFileChecks = 1024

// ignoreFileWhitelist returns the whitelist globs (rgIgnoreWhitelist) of
// the ignore file at file, looked up once per resolve; there reports a file
// the walk met (no stat needed). ok is false once the bound of lookups
// (rgIgnoreFileChecks) is spent: the answer is unknown.
func (r *credentialPathResolver) ignoreFileWhitelist(file string, there bool) ([]rgGlob, bool) {
	if globs, seen := r.ignoreGlobs[file]; seen {
		return globs, true
	}
	if r.ignoreChecks >= rgIgnoreFileChecks {
		return nil, false
	}
	r.ignoreChecks++
	if !there {
		info, err := os.Stat(file)
		there = err == nil && info.Mode().IsRegular()
	}
	var globs []rgGlob
	if there {
		globs = rgIgnoreWhitelist(file)
	}
	if r.ignoreGlobs == nil {
		r.ignoreGlobs = make(map[string][]rgGlob)
	}
	r.ignoreGlobs[file] = globs
	return globs, true
}

// ignoreWhitelistAbove returns the whitelist globs of the ignore files in
// dir and in every folder above it (ignoreFileWhitelist), and marks each
// file read. ok is false once the bound of those lookups is spent.
func (r *credentialPathResolver) ignoreWhitelistAbove(dir string, read map[string]bool) ([]rgGlob, bool) {
	var globs []rgGlob
	for folder := dir; ; {
		for _, name := range rgIgnoreFileNames {
			file := filepath.Join(folder, name)
			found, ok := r.ignoreFileWhitelist(file, false)
			if !ok {
				return globs, false
			}
			read[file] = true
			globs = append(globs, found...)
		}
		parent := filepath.Dir(folder)
		if parent == folder {
			return globs, true
		}
		folder = parent
	}
}

// probeUnder looks up every probe of the credentials table under the folder
// a recursive search names, as rel does, outside the shared walk budget
// (substrate-1:GAP-0911): a walk spent on a huge folder named before it
// (grep -r KEY /usr ~), or cut inside this one, would otherwise miss the
// exact ~/.aws/credentials read and record only the file-unknown read. A
// first segment that is not there costs no lookup (rel-1-0-10:GAP-1045);
// the probes run in table order, so the reads come in the same order every
// time.
func (r *credentialPathResolver) probeUnder(id int64, dir, shown string, filter credentialWalkFilter) {
	there := make(map[string]bool)
	for _, probe := range credentialProbes() {
		if r.stopped() {
			return
		}
		first := probe.segments[0]
		found, checked := there[first]
		if !checked {
			if !r.work.Take() {
				return
			}
			_, err := os.Lstat(filepath.Join(dir, first))
			if found = err == nil; found && !r.lookups.Take() {
				return
			}
			there[first] = found
		}
		if !found || !filter.admits(shown, probe.segments) {
			continue
		}
		if !r.lookups.Take() {
			return
		}
		file := filepath.Join(dir, filepath.FromSlash(probe.value))
		if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
			r.candidate(id, file, false, false)
		}
	}
}

// probeWithin looks up the files of the probes the folder a recursive
// search names sits inside: rg KEY .aws or grep -r KEY ~/.aws reads
// ~/.aws/credentials, and grep -r KEY ~/.config/gh reads
// ~/.config/gh/hosts.yml (substrate-1:GAP-0913; the walk looked only at a
// folder named as a probe's first segment, so a folder deeper in the probe
// read nothing). The folder's trailing segments must be the probe's leading
// folders; it is read whatever its name, as the command names it.
func (r *credentialPathResolver) probeWithin(id int64, dir, shown string, filter credentialWalkFilter) {
	for _, tail := range credentialProbeTails()[filepath.Base(dir)] {
		if r.stopped() || !r.work.Take() {
			return
		}
		if !credentialFolderEndsIn(dir, tail.probe.segments[:tail.depth]) {
			continue
		}
		rest := tail.probe.segments[tail.depth:]
		if !filter.admits(shown, rest) {
			continue
		}
		if !r.lookups.Take() {
			return
		}
		file := filepath.Join(dir, filepath.FromSlash(strings.Join(rest, "/")))
		if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
			r.candidate(id, file, false, false)
		}
	}
}

// credentialProbeTail is a probe whose first depth segments are folders a
// search may name: the folder named is segments[depth-1].
type credentialProbeTail struct {
	probe credentialProbe
	depth int
}

// credentialProbeTails indexes the probes by each of their folder segments.
var credentialProbeTails = sync.OnceValue(func() map[string][]credentialProbeTail {
	tails := make(map[string][]credentialProbeTail)
	for _, probe := range credentialProbes() {
		for depth := 1; depth < len(probe.segments); depth++ {
			name := probe.segments[depth-1]
			tails[name] = append(tails[name], credentialProbeTail{probe: probe, depth: depth})
		}
	}
	return tails
})

// credentialFolderEndsIn reports a folder whose trailing segments are
// segments.
func credentialFolderEndsIn(dir string, segments []string) bool {
	for i := len(segments) - 1; i >= 0; i-- {
		if filepath.Base(dir) != segments[i] {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir && i > 0 {
			return false
		}
		dir = parent
	}
	return true
}

// credentialWalkKey is one folder one command searched: its resolved path
// and its spelling, which the found files are named under.
type credentialWalkKey struct {
	id         int64
	dir, shown string
}

// credentialPathWalkLimits is what a walk reads: folders, entries, lookups.
type credentialPathWalkLimits struct {
	folders, entries, lookups int64
}

// credentialPathWalkBounds is the walk budget of one resolve.
var credentialPathWalkBounds = credentialPathWalkLimits{
	folders: maxCredentialPathWalkFolders,
	entries: maxCredentialPathWalkEntries,
	lookups: maxCredentialPathWalkLookups,
}

func (l credentialPathWalkLimits) minus(o credentialPathWalkLimits) credentialPathWalkLimits {
	return credentialPathWalkLimits{l.folders - o.folders, l.entries - o.entries, l.lookups - o.lookups}
}

func (l credentialPathWalkLimits) plus(o credentialPathWalkLimits) credentialPathWalkLimits {
	return credentialPathWalkLimits{l.folders + o.folders, l.entries + o.entries, l.lookups + o.lookups}
}

func (l credentialPathWalkLimits) spent() bool {
	return l.folders <= 0 || l.entries <= 0 || l.lookups <= 0
}

// credentialPathWalkResult is one walk: the credentials files it found,
// whether a bound cut it and what it read of its budget.
type credentialPathWalkResult struct {
	found []string
	cut   bool
	used  credentialPathWalkLimits
	// ignores are the ignore files the walk met (rgIgnoreFileNames), for an
	// rg filter whose hidden rule they can lift (rel-1-0-10:GAP-1652).
	ignores []string
}

// credentialPathWalk walks dir breadth first and reads each folder once, a
// huge one in pieces (readCredentialWalkFolder); each entry named as the
// first segment of a credentials probe is looked up. It does not enter
// credentialWalkSkips or follow a symbolic link to a folder, as grep -r does
// not. It counts and enters only what filter admits (rgFilter, ripgrep's
// hidden rule, globs and types, applied to each folder on the way to a
// probe and to the probe file; nil for grep -r, which admits all); shown
// is dir as rg names it. A limit (folders, entries, lookups) cuts it: what it found stays, and cut
// is set. A level of folders that does not fit in the folder bound is not
// read at all (substrate-1:GAP-0709): the walk is cut there and charged the
// whole folder bound, as a walk that read the level up to the bound was.
// Nothing found in that level could change what the chain reads of a cut
// walk: the cut adds the file-unknown read (searchFolder), with which no
// read of the call is exact and which joins any later upload, so a file
// found next to it adds nothing. Reading it was most of the walk's cost: on
// the hook-cost probe's tree (4,146 folders), 4,031 of the 4,096 folders
// read, about 7 ms on every grep -r or rg call there. A level's folders
// are named only once it is known to fit (credentialPathFolderScan keeps
// the names), so a level that does not fit costs no path either.
//
// room is what the resolve can still take of the files found (candidate takes
// one candidate and the file's length in work for each): the walk keeps the
// files in order up to the one that trips a cap, which the resolve then trips
// on as it did with every file kept, and no file after it, which the stopped
// resolve never read. The folders it reads, its cut and its budget are the
// same either way: a walk that stopped reading there would leave a later folder
// of the call a budget it did not have (substrate-1:GAP-0674).
//
// The walk runs in a walk slot (credentialPathWalkSlots), taken through wait.
// One it does not get in time is a walk cut before it read anything and
// charged all of limits, so every folder the call names after it is spent
// too and waits no more (substrate-1:GAP-1083).
func credentialPathWalk(wait CredentialWalkBudget, dir, shown string, filter credentialWalkFilter, limits credentialPathWalkLimits, room credentialWalkRoom) (walk credentialPathWalkResult) {
	if !wait.take() {
		return credentialPathWalkResult{cut: true, used: limits}
	}
	defer func() { <-credentialPathWalkSlots }()
	groups := credentialProbeFirstSegments()
	budget := credentialPathWalkBudget{limits: limits}
	folders := int64(0)
	defer func() {
		walk.cut = walk.cut || budget.stop.Load()
		walk.used = credentialPathWalkLimits{
			folders: folders,
			entries: min(budget.entries.Load(), limits.entries),
			lookups: min(budget.lookups.Load(), limits.lookups),
		}
	}()
	// Level by level: the folders of one level are read by up to
	// credentialPathWalkWorkers goroutines (the walk's cost is its system
	// calls), and merged in order, so an uncut walk finds the same files in
	// the same order every time.
	level := []credentialWalkFolder{{dir, shown}}
	for len(level) > 0 {
		folders += int64(len(level))
		scans := make([]credentialPathFolderScan, len(level))
		var next atomic.Int64
		work := func() {
			defer func() {
				if recover() != nil {
					budget.stop.Store(true) // a cut walk, never a crash
				}
			}()
			for {
				i := int(next.Add(1)) - 1
				if i >= len(level) || budget.stop.Load() {
					return
				}
				scans[i] = budget.scan(level[i], filter, groups)
			}
		}
		if workers := min(credentialPathWalkWorkers, len(level)); workers <= 1 {
			work()
		} else {
			var wg sync.WaitGroup
			for range workers {
				wg.Go(work)
			}
			wg.Wait()
		}
		count := 0
		for _, s := range scans {
			for _, file := range s.found {
				if room.admit(file) {
					walk.found = append(walk.found, file)
				}
			}
			walk.ignores = append(walk.ignores, s.ignores...)
			count += len(s.ends)
		}
		if budget.stop.Load() {
			break
		}
		if int64(count) > limits.folders-folders {
			folders = limits.folders
			walk.cut = true
			break
		}
		above := level
		level = make([]credentialWalkFolder, 0, count)
		for i, s := range scans {
			start := 0
			for j, end := range s.ends {
				next := credentialWalkFolder{dir: filepath.Join(above[i].dir, string(s.names[start:end]))}
				if s.shown != nil {
					next.shown = s.shown[j]
				}
				level = append(level, next)
				start = end
			}
		}
	}
	return walk
}

// credentialPathWalkBudget is the entries and lookups of one walk, shared
// by its workers, within limits; stop is set when one runs out.
type credentialPathWalkBudget struct {
	limits           credentialPathWalkLimits
	entries, lookups atomic.Int64
	stop             atomic.Bool
}

func (b *credentialPathWalkBudget) take(counter *atomic.Int64, limit int64) bool {
	if counter.Add(1) > limit {
		b.stop.Store(true)
		return false
	}
	return true
}

// credentialWalkSearchChecked: the system checks a folder's search (x)
// permission apart from its read permission. Windows does not: every user
// holds the bypass traverse checking privilege, and a folder that can be
// listed names files whose attributes can be read.
const credentialWalkSearchChecked = runtime.GOOS != "windows"

// credentialWalkWindowsPathBytes is the longest path, in bytes, of a file
// the walk finds that Windows surely can name: its paths end at 32,767
// UTF-16 units, the \\?\ prefix and the closing NUL among them, and a path
// has no more units than bytes. A longer one is looked up.
const credentialWalkWindowsPathBytes = 32_000

// credentialWalkPathTooLong reports a path the walk looks up before it
// counts the file, as one Windows may not name.
func credentialWalkPathTooLong(file string) bool {
	return runtime.GOOS == "windows" && len(file) > credentialWalkWindowsPathBytes
}

// credentialPathFolderScan is one folder of a walk: the credentials files
// found in it and the folders below it to read next, by name (names[e:f]
// for consecutive ends e, f, the first from 0) and, when rg globs read the
// path, as rg names them (shown).
type credentialPathFolderScan struct {
	found   []string
	names   []byte
	ends    []int
	shown   []string
	ignores []string // the ignore files in it, for an rg that reads them
}

// credentialWalkFolder is one folder of a walk and its path as rg names it.
type credentialWalkFolder struct {
	dir, shown string
}

// scan reads one folder (readCredentialWalkFolder).
//
// A file the folder read names is looked up by its path only where the lookup
// can fail when the read did not (substrate-1:GAP-0674, RV-T6C P4-1): the
// first of a folder on a system that checks a folder's search permission
// apart from its read permission (a folder of mode 0644 lists its files, but
// no file in it can be opened, by the walk or by the agent's grep), unless a
// check of the open folder (credentialWalkSearchable, Linux) shows it can be
// entered, and a path
// past what Windows can name (credentialWalkPathTooLong). The resolve then
// adds no read the agent cannot make, as before the lookups were skipped.
func (b *credentialPathWalkBudget) scan(folder credentialWalkFolder, filter credentialWalkFilter, groups map[string][]credentialProbe) (s credentialPathFolderScan) {
	entered, checked := !credentialWalkSearchChecked, false
	readCredentialWalkFolder(folder.dir, func(name []byte, isDir, regular bool, dirfd int) bool {
		if !b.take(&b.entries, b.limits.entries) {
			return false
		}
		if regular && filter.rg.readsIgnoreFiles() && slices.Contains(rgIgnoreFileNames, string(name)) {
			s.ignores = append(s.ignores, filepath.Join(folder.dir, string(name)))
		}
		for _, probe := range groups[string(name)] {
			if !filter.admits(folder.shown, probe.segments) {
				continue
			}
			if !b.take(&b.lookups, b.limits.lookups) {
				return false
			}
			file := filepath.Join(folder.dir, filepath.FromSlash(probe.value))
			named := regular && probe.value == string(name)
			if named && !entered && !checked {
				checked = true
				entered = dirfd >= 0 && credentialWalkSearchable(dirfd)
			}
			if named && entered && !credentialWalkPathTooLong(file) {
				// The entry is the probe's file, a regular file as the folder
				// read has it, in a folder a lookup has entered: no lookup of
				// it by its path (on Windows, a 2,000-character path costs a
				// 7 KB conversion and a system call for each of up to 1,024
				// files, substrate-1:GAP-0674).
				s.found = append(s.found, file)
			} else if info, err := os.Stat(file); err == nil && info.Mode().IsRegular() {
				s.found = append(s.found, file)
				entered = entered || named
			}
		}
		if !isDir || credentialWalkSkips[string(name)] {
			return true
		}
		shown := ""
		globs := filter.readsPath()
		if globs {
			shown = rgJoin(folder.shown, string(name))
		}
		if !filter.enters(shown, string(name)) {
			return true
		}
		if globs {
			s.shown = append(s.shown, shown)
		}
		s.names = append(s.names, name...)
		s.ends = append(s.ends, len(s.names))
		return true
	})
	return s
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
		fact.storeOnce()
		r.reads = append(r.reads, fact)
	}
}

// storeOnce makes the spellings of a read share the memory of the longest one
// where they are the same text or a part of it (a resolved path is the working
// folder, a slash and the value; a normalized one is the value). A walk of a
// deep tree names a file with a path of thousands of bytes, and the record of
// the call keeps each read for as long as the call is judged, so the
// spellings it kept as separate strings were two or three times the path
// (substrate-1:GAP-0674). The strings are equal, byte for byte, as they were.
func (f *PathFact) storeOnce() {
	host := f.Value
	for _, s := range []string{f.Normalized, f.Resolved} {
		if len(s) > len(host) {
			host = s
		}
	}
	f.Value, f.Normalized, f.Resolved = within(host, f.Value), within(host, f.Normalized), within(host, f.Resolved)
}

// within is s as a part of host (the same bytes, in host's memory) when host
// ends or begins with s, and s as it is otherwise.
func within(host, s string) string {
	switch {
	case s == "" || len(s) > len(host):
		return s
	case strings.HasSuffix(host, s):
		return host[len(host)-len(s):]
	case strings.HasPrefix(host, s):
		return host[:len(s)]
	}
	return s
}

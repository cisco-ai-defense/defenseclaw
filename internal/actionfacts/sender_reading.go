// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The shared sender reader answers one question for every consumer (the
// secret-read-then-egress chain, intent scope, the egress rules): does this
// call send data to a network sink, and where to. It reads the commands and
// network facts the projection made and, when the projection is not
// complete, the parts it did not project: a command part that cannot be
// projected never defaults to "no sender" (GAP-0597, GAP-0598, GAP-0599).
//
//   - A projected upload (a network fact of action upload) is a sender with
//     the destinations of its facts.
//   - A projected remote copy (scp, rsync or sftp) is a sender when its
//     destination operand is remote, with that host.
//   - A program that a find -exec/-execdir/-ok/-okdir or an xargs runs is
//     read as a command of its own (the wrapper walk of
//     classifyEmbeddedPrograms); an xargs program whose destination may come
//     from stdin has an unknown destination.
//   - A shell part the projection did not read (a function body, a trap or
//     eval string, a coprocess, the lines before a syntax error, a second
//     shell value) is read from the syntax tree: a known network sender
//     program there is a sender with an unknown destination.
//   - Whatever else of a call that is not complete stays unread (Unread),
//     never "no sender".
//
// An unknown destination is the unknown tier of the one bound rule: alert in
// the default and permissive packs, block in strict (bounded.Unknown). A
// sender whose destination the reader proved keeps the verdict its consumer
// gives that destination.

// SenderOrigin says how the sender reader found a sender.
type SenderOrigin string

const (
	// SenderProjected is a projected command with an upload network fact.
	SenderProjected SenderOrigin = "projected"
	// SenderRemoteCopy is a projected scp, rsync or sftp with a remote
	// destination operand.
	SenderRemoteCopy SenderOrigin = "remote_copy"
	// SenderEmbedded is a program a find -exec/-ok or an xargs runs.
	SenderEmbedded SenderOrigin = "embedded"
	// SenderUnprojected is a sender in a shell part the projection did not
	// read.
	SenderUnprojected SenderOrigin = "unprojected"
	// SenderInlineCode is an interpreter one-liner (python -c, node -e ...)
	// whose code asks for a network capability: the code is opaque to the
	// projection, so where it sends is not read (GAP-0595).
	SenderInlineCode SenderOrigin = "inline_code"
	// SenderNetworkRole and SenderUnprovenRole are read from the network
	// facts and the operand shape (sender_network_role.go).
)

// SenderFact is one command of a call that sends data to a network sink.
type SenderFact struct {
	// CommandID is the projected command (for an embedded program, the find
	// or xargs that runs it); 0 for a sender in an unprojected part.
	CommandID int64
	Program   string
	Origin    SenderOrigin
	// Hosts are the destinations read from static words, lower case.
	Hosts []string
	// Network holds the network facts of a projected or embedded upload.
	Network []NetworkFact
	// DestinationUnknown is set when where it sends could not be read in
	// full: a word the shell builds, stdin, an unprojected part.
	DestinationUnknown bool
	// Operands are the static operand words of the sender's command (what a
	// credential-file check reads); empty for an embedded program.
	Operands []string
	// FedText is the literal text fed to its standard input (a here-string
	// or here-document, or the file a redirect reads): an sftp or ftp batch
	// names the file it puts there (GAP-0775).
	FedText string
}

// SendReading is the shared sender reader's answer for one call.
type SendReading struct {
	Senders []SenderFact
	// Unread is set when the projection is not complete: a part of the call
	// was not read by it, so "no sender" is not proven even when Senders is
	// empty.
	Unread bool
	// Unreadable is set when the syntax reading of an unprojected part could
	// not finish either: a program word the shell builds, an evaluated
	// string it builds, a value the parser refuses or a reading cap.
	Unreadable bool
	// Capped is set when a value is past shellparse's reading bounds: a cap
	// hit of the one bound rule, never "no sender". Cap names the bound.
	Capped bool
	Cap    bounded.Cap
}

// Bound records the reading's cap hit in t (the one bound rule: a
// truncated reading is at least the unknown tier).
func (r SendReading) Bound(t *bounded.Truncated) {
	if r.Capped && t != nil {
		t.Hit(r.Cap)
	}
}

// UnknownTier reports a reading whose answer is the unknown tier of the one
// bound rule (bounded.Unknown: alert in default and permissive, block in
// strict): a sender whose destination is not read in full, or a cap hit.
func (r SendReading) UnknownTier() bool {
	return r.Capped || r.Unreadable || r.UnknownDestination()
}

// Sends reports a sender of any origin.
func (r SendReading) Sends() bool { return len(r.Senders) > 0 }

// UnknownDestination reports a sender whose destination is not read in full.
func (r SendReading) UnknownDestination() bool {
	for _, sender := range r.Senders {
		if sender.DestinationUnknown {
			return true
		}
	}
	return false
}

// UnprojectedSends reports a sender the projection's own network facts do
// not hold (a remote copy, an embedded program or an unprojected part):
// what a consumer that reads only the upload network facts misses.
func (r SendReading) UnprojectedSends() bool {
	for _, sender := range r.Senders {
		if sender.Origin != SenderProjected {
			return true
		}
	}
	return false
}

// sendSource is one shell value or argv of a call, kept on Facts only when
// the projection is not complete so the sender reader can read what the
// projection did not.
type sendSource struct {
	text string
	argv []string
	// dialect is the dialect of text: POSIX (or none), PowerShell or cmd.
	dialect Dialect
}

// NetworkRoleProgram reports a program name (any directory, any case, an
// .exe suffix) that the egress classifiers or the mail list know as a network
// program: the classifier publishes a network fact for it when it is given a
// remote operand.
func NetworkRoleProgram(word string) bool {
	name := senderProgramName(word)
	if name == "" || strings.ContainsAny(name, " \t\r\n\x00") {
		return false
	}
	if mailSenderPrograms[name] {
		return true
	}
	probe := Analyze(Input{Tool: "bash", Argv: []string{name, "user@probe.invalid:/x", "https://probe.invalid/x"}})
	return len(probe.Network) > 0
}

func senderProgramName(word string) string {
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(word, `\`, "/"))), ".exe")
}

const maxSenderDepth = 3

// ReadSenders is the shared sender reader (see the comment at the top of
// this file).
func ReadSenders(facts Facts) SendReading {
	var reading SendReading
	readProjectedSenders(facts, &reading, 0)
	readNetworkRoleSenders(facts, &reading, false)
	readInlineCodeSenders(facts, &reading)
	if facts.Parse.Status != StatusComplete && facts.Parse.Status != StatusNotApplicable {
		reading.Unread = true
		readUnprojectedSenders(facts, &reading)
	}
	for i := range reading.Senders {
		sender := &reading.Senders[i]
		if sender.Origin == SenderProjected {
			continue
		}
		// the hosts read from words, as network facts like the projection's
		sender.Network = nil
		for _, host := range sender.Hosts {
			normalized, scope, kind, prefix := deriveNetworkTarget(host)
			sender.Network = append(sender.Network, NetworkFact{
				CommandID: sender.CommandID, Action: NetworkUpload, Host: host,
				NormalizedHost: normalized, Scope: scope, TargetKind: kind, PrefixLength: prefix,
			})
		}
	}
	return reading
}

func readProjectedSenders(facts Facts, reading *SendReading, depth int) {
	uploads := map[int64][]NetworkFact{}
	for _, network := range facts.Network {
		if network.Action == NetworkUpload {
			uploads[network.CommandID] = append(uploads[network.CommandID], network)
		}
	}
	for _, command := range facts.Commands {
		if command.Kind == CommandKindShellRedirect || command.Effect == EffectPreview {
			continue
		}
		prog := senderProgramName(command.Program)
		args := commandWords(command)
		if network := uploads[command.ID]; len(network) > 0 {
			sender := SenderFact{CommandID: command.ID, Program: prog, Origin: SenderProjected, Network: network,
				Operands: senderOperandWords(prog, args), FedText: command.LiteralStdin}
			for _, n := range network {
				host := n.NormalizedHost
				if host == "" {
					host = n.Host
				}
				if host == "" || n.TargetKind == NetworkTargetUnknown || n.TargetKind == NetworkTargetGenerated {
					sender.DestinationUnknown = true
					continue
				}
				sender.Hosts = appendHost(sender.Hosts, host)
			}
			if !command.ArgvComplete {
				sender.DestinationUnknown = true
			}
			reading.Senders = append(reading.Senders, sender)
		} else if remoteCopyProgram(prog) {
			if sends, hosts, unknown := readRemoteCopyArgs(prog, args, nil); sends {
				reading.Senders = append(reading.Senders, SenderFact{
					CommandID: command.ID, Program: prog, Origin: SenderRemoteCopy,
					Hosts: hosts, DestinationUnknown: unknown || !command.ArgvComplete,
					Operands: senderOperandWords(prog, args), FedText: command.LiteralStdin,
				})
			}
		}
		if !command.ArgvComplete || command.Effect != EffectExecute {
			continue
		}
		switch prog {
		case "find", "xargs":
			readEmbeddedSenders(facts, command.ID, prog, command.Argv, reading, depth)
		}
	}
}

func commandArgs(command CommandFact) []string {
	if len(command.Argv) > 0 && senderProgramName(command.Argv[0]) == senderProgramName(command.Program) {
		return command.Argv[1:]
	}
	return command.Argv
}

// readEmbeddedSenders reads the programs a find -exec/-execdir/-ok/-okdir or
// an xargs runs (the same walk as classifyEmbeddedPrograms, with the words
// that hold a handed entry kept), each as a command of its own.
func readEmbeddedSenders(facts Facts, parentID int64, prog string, argv []string, reading *SendReading, depth int) {
	if depth >= maxSenderDepth {
		reading.Unreadable = true
		reading.Capped, reading.Cap = true, bounded.Depth
		return
	}
	var programs []embeddedProgram
	stdinDestination := false
	replace := ""
	switch prog {
	case "find":
		programs = findEmbeddedPrograms(argv)
	case "xargs":
		var known bool
		_, replace, known = XargsProgram(argv)
		if !known {
			// an xargs option it does not know may hide the program
			reading.Unreadable = true
			return
		}
		programs = xargsEmbeddedPrograms(argv)
		// xargs appends what it reads to the program words: a destination
		// may come from stdin. With -I the words holding its string do.
		stdinDestination = replace == ""
	}
	for _, program := range programs {
		if len(program.whole) == 0 {
			continue
		}
		if hasProjectedChildSender(facts, parentID, program.whole[0]) {
			continue
		}
		child := Analyze(Input{Tool: "bash", Argv: cloneSlice(program.whole)})
		var inner SendReading
		readProjectedSenders(child, &inner, depth+1)
		found := len(inner.Senders) > 0
		for _, sender := range inner.Senders {
			sender.CommandID = parentID
			sender.Origin = SenderEmbedded
			sender.DestinationUnknown = sender.DestinationUnknown || stdinDestination
			reading.Senders = append(reading.Senders, sender)
		}
		reading.Unreadable = reading.Unreadable || inner.Unreadable
		if inner.Capped && !reading.Capped {
			reading.Capped, reading.Cap = true, inner.Cap
		}
		if found {
			continue
		}
		// The program's own reading names no upload (its destination or its
		// body is a handed entry, so its grammar may not finish): read its
		// words as a sender's.
		var handed map[int]bool
		if replace != "" {
			for i, word := range program.whole {
				if strings.Contains(word, replace) {
					if handed == nil {
						handed = map[int]bool{}
					}
					handed[i] = true
				}
			}
		}
		name, args := unwrapSenderWords(program.whole, handed)
		if name == "" {
			reading.Unreadable = true
			continue
		}
		if sends, hosts, unknown := readWordSender(name, args, shiftDynamic(handed, len(program.whole)-len(args)), true, depth+1); sends {
			reading.Senders = append(reading.Senders, SenderFact{
				CommandID: parentID, Program: name, Origin: SenderEmbedded,
				Hosts: hosts, DestinationUnknown: unknown || stdinDestination || len(hosts) == 0,
			})
		}
	}
}

// hasProjectedChildSender reports that the projection already attached the
// program a find or xargs runs as its child command (classifyEmbeddedPrograms
// attaches only a complete reading), so it is read once.
func hasProjectedChildSender(facts Facts, parentID int64, word string) bool {
	name := senderProgramName(word)
	for _, command := range facts.Commands {
		if command.ParentCommandID == parentID && senderProgramName(command.Program) == name {
			return true
		}
	}
	return false
}

// readUnprojectedSenders reads, from the syntax tree, the shell values and
// argv of a call whose projection is not complete, and adds a sender for
// each sender command the projection does not account for.
func readUnprojectedSenders(facts Facts, reading *SendReading) {
	projected := map[string][][]string{}
	for _, command := range facts.Commands {
		name := senderProgramName(command.Program)
		projected[name] = append(projected[name], commandArgs(command))
	}
	match := func(name string, args []string) bool {
		list := projected[name]
		for i, candidate := range list {
			if equalStrings(candidate, args) {
				projected[name] = append(list[:i:i], list[i+1:]...)
				return true
			}
		}
		return false
	}
	var occurrences []senderOccurrence
	for _, source := range facts.sendSources {
		switch {
		case source.text != "" && source.dialect == DialectCMD:
			// no cmd reader reads the part the projection did not: unknown
			reading.Unreadable = true
		case source.text != "" && source.dialect == DialectPowerShell:
			res := readPowerShellSender(source.text)
			reading.Unreadable = reading.Unreadable || res.unknown
			if res.cap != 0 && !reading.Capped {
				reading.Capped, reading.Cap = true, res.cap
			}
			occurrences = append(occurrences, res.calls...)
		case source.text != "":
			if c := shellBoundCap(source.text); c != 0 {
				reading.Capped, reading.Cap = true, c
				continue
			}
			res := syntaxSenderRead(source.text, 0)
			reading.Unreadable = reading.Unreadable || res.unknown
			if res.cap != 0 && !reading.Capped {
				reading.Capped, reading.Cap = true, res.cap
			}
			occurrences = append(occurrences, res.calls...)
		case len(source.argv) > 0:
			name, args := unwrapSenderWords(source.argv, nil)
			if name == "" {
				if unknownProgramMaySend(source.argv, false) {
					reading.Unreadable = true
				}
				continue
			}
			occurrences = append(occurrences, senderOccurrence{name: name, args: args})
		}
	}
	// A call the projection holds with the same words is its own reading;
	// what is left is matched to any projected command of its program left
	// over (a word the shell builds, a wrapper the projection kept in argv),
	// and only what is left then is read here.
	var left []senderOccurrence
	for _, occurrence := range occurrences {
		if occurrence.dynamic == nil && match(occurrence.name, occurrence.args) {
			continue
		}
		left = append(left, occurrence)
	}
	for _, occurrence := range left {
		if list := projected[occurrence.name]; len(list) > 0 {
			projected[occurrence.name] = list[1:]
			continue
		}
		readOccurrence(occurrence, reading, 0)
	}
}

func readOccurrence(occurrence senderOccurrence, reading *SendReading, depth int) {
	switch occurrence.name {
	case "find", "xargs":
		if occurrence.dynamic != nil {
			if embeddedMaySend(occurrence.args) {
				reading.Unreadable = true
			}
			return
		}
		var inner SendReading
		readEmbeddedSenders(Facts{}, 0, occurrence.name, append([]string{occurrence.name}, occurrence.args...), &inner, depth)
		reading.Unreadable = reading.Unreadable || inner.Unreadable
		if inner.Capped && !reading.Capped {
			reading.Capped, reading.Cap = true, inner.Cap
		}
		for _, sender := range inner.Senders {
			sender.Origin = SenderUnprojected
			sender.DestinationUnknown = true
			reading.Senders = append(reading.Senders, sender)
		}
		return
	}
	if sends, hosts, _ := readWordSender(occurrence.name, occurrence.args, occurrence.dynamic, occurrence.fed, depth); sends {
		reading.Senders = append(reading.Senders, SenderFact{
			Program: occurrence.name, Origin: SenderUnprojected, Hosts: hosts,
			Operands: senderOperandWords(occurrence.name, occurrence.args),
			FedText:  occurrence.fedText,
			// a part the projection did not read: where it sends is not proven
			DestinationUnknown: true,
		})
	}
}

// unknownProgramMaySend reports whether a call whose program the reader
// cannot name may send data: a standard input fed to it, a word the shell
// builds (it may be the destination), or a static word that names a remote
// place (a URL, user@host, host:path, a dotted host). A call with none of
// these has no destination to send to: a read-only remote command through a
// program path the shell builds is not a sender (GAP-0774).
func unknownProgramMaySend(words []string, fed bool) bool {
	if fed {
		return true
	}
	for i, word := range words {
		if word == "" && i > 0 {
			return true
		}
		if unprovenRemoteOperand(word) || emailLikeOperand(word) || dottedHostPortOperand(word) || bareHostnameOperand(word) {
			return true
		}
	}
	return false
}

// embeddedMaySend reports a find or xargs whose words name a sender program.
func embeddedMaySend(args []string) bool {
	for _, word := range args {
		if NetworkRoleProgram(word) {
			return true
		}
	}
	return false
}

// senderOccurrence is one simple command the syntax reader found: its
// program (after wrappers) and its words; dynamic marks the words the shell
// builds (nil when there are none).
type senderOccurrence struct {
	name    string
	args    []string
	dynamic map[int]bool
	// fed is set when the call's standard input is fed: a pipe into it, a
	// file redirect or a here-document.
	fed bool
	// fedText is the literal text of a here-string or here-document fed to
	// it, or the file a redirect reads.
	fedText string
}

type syntaxSenderResult struct {
	calls   []senderOccurrence
	unknown bool
	// cap is the first reading cap the value hit (bounded.Cap), 0 for none.
	cap bounded.Cap
}

// maxSenderOccurrences bounds the calls of one value the unprojected reader
// classifies.
const maxSenderOccurrences = 256

const boundedItems = bounded.Items

// syntaxSenderRead reads the shell syntax tree of one value. A value that
// does not parse is read statement by statement up to the error: the shell
// runs the complete lines before a syntax error.
func syntaxSenderRead(command string, depth int) syntaxSenderResult {
	var res syntaxSenderResult
	if file, ok := shellparse.Parse(command); ok && file != nil {
		syntaxSenderNode(file, depth, &res)
		return res
	}
	stmts, unknown := statementsBeforeSyntaxError(command)
	res.unknown = unknown
	for _, st := range stmts {
		syntaxSenderNode(st, depth, &res)
	}
	return res
}

func statementsBeforeSyntaxError(command string) (stmts []*syntax.Stmt, unknown bool) {
	var all []*syntax.Stmt
	var err error
	for st, e := range syntax.NewParser(syntax.Variant(syntax.LangBash)).StmtsSeq(shellparse.Reader(command)) {
		if e != nil {
			err = e
			break
		}
		all = append(all, st)
	}
	var perr syntax.ParseError
	if !errors.As(err, &perr) {
		return nil, err != nil
	}
	for _, st := range all {
		if st.End().Line() < perr.Pos.Line() {
			stmts = append(stmts, st)
		}
	}
	return stmts, false
}

// syntaxSenderNode walks one syntax tree: functions, coprocesses and command
// substitutions are visited by the walk, and the strings a command hands to
// the shell (eval, trap, a shell's -c body) are read again as shell text.
func syntaxSenderNode(root syntax.Node, depth int, res *syntaxSenderResult) {
	fed := map[*syntax.CallExpr]bool{}
	fedText := map[*syntax.CallExpr]string{}
	syntax.Walk(root, func(n syntax.Node) bool {
		switch t := n.(type) {
		case *syntax.Stmt:
			// a call whose standard input is read from a file, a here-document
			// or a here-string
			if call, ok := t.Cmd.(*syntax.CallExpr); ok {
				for _, redirect := range t.Redirs {
					switch redirect.Op {
					case syntax.RdrIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc, syntax.RdrInOut:
						fed[call] = true
						body := redirect.Word
						if redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc {
							body = redirect.Hdoc
						}
						if body != nil {
							if text, ok := literalShellWord(body); ok {
								fedText[call] += text + "\n"
							}
						}
					}
				}
			}
		case *syntax.BinaryCmd:
			// the call on the right of a pipe reads its left side
			if t.Op == syntax.Pipe || t.Op == syntax.PipeAll {
				if call, ok := t.Y.Cmd.(*syntax.CallExpr); ok {
					fed[call] = true
				}
			}
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, 0, len(call.Args))
		dynamic := map[int]bool{}
		for i, w := range call.Args {
			if lit, ok := literalShellWord(w); ok {
				words = append(words, lit)
			} else {
				words = append(words, "")
				dynamic[i] = true
			}
		}
		name, args := unwrapSenderWords(words, dynamic)
		if name == "" {
			// the program is a word the shell builds: what runs is unknown.
			// It is the unknown tier only when the call may send: a fed
			// standard input, a word the shell builds, or a word that names
			// a remote place (GAP-0774).
			if unknownProgramMaySend(words, fed[call]) {
				res.unknown = true
			}
			return true
		}
		argDynamic := shiftDynamic(dynamic, len(words)-len(args))
		if body, ok, known := evaluatedShellString(name, args, argDynamic); !known {
			res.unknown = true
		} else if ok {
			if depth >= maxSenderDepth {
				res.unknown = true
				res.hitCap(bounded.Depth)
			} else if c := shellBoundCap(body); c != 0 {
				res.unknown = true
				res.hitCap(c)
			} else {
				inner := syntaxSenderRead(body, depth+1)
				res.unknown = res.unknown || inner.unknown
				res.hitCap(inner.cap)
				res.calls = append(res.calls, inner.calls...)
			}
		}
		if len(res.calls) >= maxSenderOccurrences {
			res.unknown = true
			res.hitCap(bounded.Items)
			return true
		}
		occurrence := senderOccurrence{name: name, args: args, fed: fed[call], fedText: fedText[call]}
		if len(argDynamic) > 0 {
			occurrence.dynamic = argDynamic
		}
		res.calls = append(res.calls, occurrence)
		return true
	})
}

// shellBoundCap is the cap a shell value past shellparse's reading bounds
// hit, or 0 for a value within them.
func shellBoundCap(command string) bounded.Cap {
	switch reason := shellparse.BudgetExceeded(command); reason {
	case "":
		if shellparse.NestedBodiesOverBudget(command) {
			return bounded.Bytes
		}
		return 0
	case shellparse.BudgetNesting, shellparse.BudgetDepth:
		return bounded.Depth
	case shellparse.BudgetBytes, shellparse.BudgetUnparsed:
		return bounded.Bytes
	case shellparse.BudgetNodes:
		return bounded.Nodes
	default:
		return bounded.Items
	}
}

func shiftDynamic(dynamic map[int]bool, drop int) map[int]bool {
	if len(dynamic) == 0 {
		return nil
	}
	out := map[int]bool{}
	for i := range dynamic {
		if i-drop >= 0 {
			out[i-drop] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// unwrapSenderWords returns the program a simple command runs and its
// arguments, past the wrappers that run the rest of their words (env,
// timeout, nohup, nice, ionice, stdbuf, setsid, time, command, exec,
// builtin, sudo). name is "" when the program is a word the shell builds or
// the wrappers nest too deep.
func unwrapSenderWords(words []string, dynamic map[int]bool) (string, []string) {
	offset := 0
	for depth := 0; ; depth++ {
		if offset >= len(words) || dynamic[offset] {
			return "", nil
		}
		name := senderProgramName(words[offset])
		inner := wrappedProgramIndex(name, words[offset+1:])
		if inner < 0 {
			return name, words[offset+1:]
		}
		if depth >= maxSenderDepth {
			return "", nil
		}
		offset += 1 + inner
	}
}

// wrappedProgramIndex is the index in args of the program a wrapper runs, or
// -1 when name is not a wrapper (or runs nothing).
func wrappedProgramIndex(name string, args []string) int {
	var valued map[string]bool
	switch name {
	case "env":
		valued = map[string]bool{"-u": true, "-C": true, "-S": true, "--unset": true, "--chdir": true}
	case "timeout":
		valued = map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true}
	case "nice":
		valued = map[string]bool{"-n": true, "--adjustment": true}
	case "ionice":
		valued = map[string]bool{"-c": true, "-n": true, "-p": true}
	case "sudo":
		valued = map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true}
	case "nohup", "stdbuf", "setsid", "time", "command", "exec", "builtin":
		valued = map[string]bool{}
	default:
		return -1
	}
	durationSeen := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return i + 1
			}
			return -1
		case valued[a]:
			i++
		case strings.HasPrefix(a, "-") && len(a) > 1:
		case name == "env" && strings.Contains(a, "="):
		case name == "timeout" && !durationSeen:
			durationSeen = true
		default:
			return i
		}
	}
	return -1
}

// evaluatedShellString returns the shell text a command hands to the shell
// to run: eval's words, a trap's action, the body of a shell's -c. ok
// reports that there is one; known is false when the shell builds it.
func evaluatedShellString(name string, args []string, dynamic map[int]bool) (body string, ok, known bool) {
	switch name {
	case "eval":
		if len(dynamic) > 0 {
			return "", false, false
		}
		return strings.Join(args, " "), len(args) > 0, true
	case "trap":
		i := 0
		if len(args) > 0 && args[0] == "--" {
			i = 1
		}
		if i >= len(args) || (strings.HasPrefix(args[i], "-") && len(args[i]) > 1) {
			return "", false, true // trap -l, trap -p: no action
		}
		if dynamic[i] {
			return "", false, false
		}
		return args[i], args[i] != "" && args[i] != "-", true
	case "bash", "sh", "zsh", "dash", "ksh":
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-o" || a == "-O" || a == "+o":
				i++
			case strings.HasPrefix(a, "--"):
			case len(a) > 1 && a[0] == '-' && shortFlagLetters(a):
				if strings.Contains(a, "c") {
					if i+1 >= len(args) || dynamic[i+1] {
						return "", false, false
					}
					return args[i+1], true, true
				}
			default:
				return "", false, true // a script or another operand: no -c body
			}
		}
	}
	return "", false, true
}

func shortFlagLetters(a string) bool {
	for _, c := range a[1:] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return len(a) > 1
}

// literalShellWord is the text of a word made only of literals and quoted
// text.
func literalShellWord(w *syntax.Word) (string, bool) {
	var b strings.Builder
	var part func(p syntax.WordPart, quoted bool) bool
	part = func(p syntax.WordPart, quoted bool) bool {
		switch t := p.(type) {
		case *syntax.Lit:
			b.WriteString(unescapeShellLiteral(t.Value, quoted))
		case *syntax.SglQuoted:
			if t.Dollar {
				return false // $'...' has escapes of its own
			}
			b.WriteString(t.Value)
		case *syntax.DblQuoted:
			if t.Dollar {
				return false
			}
			for _, q := range t.Parts {
				if !part(q, true) {
					return false
				}
			}
		default:
			return false
		}
		return true
	}
	for _, p := range w.Parts {
		if !part(p, false) {
			return "", false
		}
	}
	return b.String(), true
}

// unescapeShellLiteral removes the backslash escapes of a literal: outside
// quotes a backslash quotes the next byte (a backslash and a line break
// vanish); in double quotes it does so only before $ ` " \ and a line break.
func unescapeShellLiteral(value string, quoted bool) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\\' || i+1 >= len(value) {
			b.WriteByte(c)
			continue
		}
		next := value[i+1]
		switch {
		case next == '\n':
			i++
		case !quoted || next == '$' || next == '`' || next == '"' || next == '\\':
			b.WriteByte(next)
			i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	senderRemoteOperand = regexp.MustCompile(`^(?:[^@\s/:]+@)?(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9._-]*):`)
	senderURLOperand    = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
)

func remoteCopyProgram(name string) bool {
	return name == "scp" || name == "rsync" || name == "sftp"
}

// readWordSender reads one program and its words that the projection holds
// no command for (a program an unprojected part, a find or an xargs runs):
// the words are classified as a call of their own and read by the same rules
// as a projected command (upload facts, the network role, the operand shape).
// fed is set when the program's standard input is (or may be) fed: an xargs
// program reads what it was handed. A word the shell builds is any word, so a
// program the classifiers know as a network program with such a word may
// send.
func readWordSender(name string, words []string, dynamic map[int]bool, fed bool, depth int) (sends bool, hosts []string, unknown bool) {
	if remoteCopyProgram(name) {
		return readRemoteCopyArgs(name, words, dynamic)
	}
	child := Analyze(Input{Tool: "bash", Argv: append([]string{name}, words...)})
	var inner SendReading
	readProjectedSenders(child, &inner, depth)
	readNetworkRoleSenders(child, &inner, fed)
	for _, sender := range inner.Senders {
		hosts = append(hosts, sender.Hosts...)
		unknown = unknown || sender.DestinationUnknown
	}
	if len(inner.Senders) > 0 {
		return true, hosts, unknown || len(hosts) == 0
	}
	if len(dynamic) > 0 && NetworkRoleProgram(name) {
		return true, nil, true
	}
	if fed {
		// What an xargs hands the program may be its destination: the words
		// with a destination of their own show whether it would send.
		probe := Analyze(Input{Tool: "bash", Argv: append(append([]string{name}, words...), "https://probe.invalid/x")})
		var more SendReading
		readProjectedSenders(probe, &more, depth)
		if len(more.Senders) > 0 {
			return true, nil, true
		}
	}
	return false, nil, false
}

// readRemoteCopyArgs reads an scp, rsync or sftp: only a remote destination
// (the last operand; sftp's one host operand) is a send, a remote source is
// a download, local operands a local copy. A word the shell builds may be a
// remote destination.
func readRemoteCopyArgs(name string, args []string, dynamic map[int]bool) (sends bool, hosts []string, unknown bool) {
	valueFlags := "PilFoScJ"
	if name == "rsync" {
		valueFlags = "eBMTfC"
	}
	type operand struct {
		word    string
		dynamic bool
	}
	var operands []operand
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case dynamic[i]:
			operands = append(operands, operand{dynamic: true})
		case a == "--":
			for j := i + 1; j < len(args); j++ {
				operands = append(operands, operand{word: args[j], dynamic: dynamic[j]})
			}
			i = len(args)
		case strings.HasPrefix(a, "--"):
			if flag, _, hasValue := strings.Cut(a[2:], "="); !hasValue && rsyncValuedLongOption(flag) {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if last := a[len(a)-1]; strings.IndexByte(valueFlags, last) >= 0 {
				i++
			}
		default:
			operands = append(operands, operand{word: a})
		}
	}
	if len(operands) == 0 {
		return false, nil, false
	}
	if name == "sftp" {
		first := operands[0]
		if first.dynamic {
			return true, nil, true
		}
		if host, ok := remoteOperandHost(first.word); ok {
			return true, []string{host}, false
		}
		if host := strings.TrimPrefix(first.word[strings.LastIndex(first.word, "@")+1:], "@"); host != "" &&
			!strings.ContainsAny(host, "/\\ \x00") {
			return true, []string{strings.ToLower(host)}, false
		}
		return false, nil, false
	}
	if len(operands) < 2 {
		last := operands[len(operands)-1]
		return last.dynamic, nil, last.dynamic
	}
	last := operands[len(operands)-1]
	if last.dynamic {
		return true, nil, true
	}
	if host, ok := remoteOperandHost(last.word); ok {
		return true, []string{host}, false
	}
	return false, nil, false
}

func rsyncValuedLongOption(name string) bool {
	switch name {
	case "rsh", "rsync-path", "exclude", "include", "port", "filter", "files-from", "exclude-from", "include-from":
		return true
	}
	return false
}

func remoteOperandHost(word string) (string, bool) {
	if host, ok := urlOperandHost(word); ok {
		return host, true
	}
	if strings.ContainsRune(word, 0) {
		return "", false
	}
	if m := senderRemoteOperand.FindStringSubmatch(word); m != nil && len(m[1]) > 1 {
		return strings.ToLower(strings.Trim(m[1], "[]")), true
	}
	return "", false
}

func urlOperandHost(word string) (string, bool) {
	if !senderURLOperand.MatchString(word) || strings.ContainsRune(word, 0) {
		return "", false
	}
	parsed, err := url.Parse(word)
	if err != nil || parsed.Hostname() == "" {
		return "", false
	}
	return strings.ToLower(parsed.Hostname()), true
}

func appendHost(hosts []string, host string) []string {
	host = strings.ToLower(host)
	for _, existing := range hosts {
		if existing == host {
			return hosts
		}
	}
	return append(hosts, host)
}

// readInlineCodeSenders reads interpreter one-liners whose code names a
// network capability (the capability table of inline_capabilities.go, the
// same rows the opaque-code rule reads): the destination is inside code the
// projection does not read, so the sender has an unknown destination. Code
// whose destinations are all loopback literals is not a network capability.
func readInlineCodeSenders(facts Facts, reading *SendReading) {
	for _, command := range facts.Commands {
		row, argv, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		source := inlineCodeOperands(row, argv[1:])
		if source == "" || !inlineSourceNetwork(row, source) {
			continue
		}
		reading.Senders = append(reading.Senders, SenderFact{
			CommandID:          command.ID,
			Program:            senderProgramName(argv[0]),
			Origin:             SenderInlineCode,
			DestinationUnknown: true,
		})
	}
}

// hitCap records the first cap hit.
func (r *syntaxSenderResult) hitCap(c bounded.Cap) {
	if c != 0 && r.cap == 0 {
		r.cap = c
	}
}

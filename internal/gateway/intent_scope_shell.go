// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The scope floor takes the destinations of a shell command from its parsed
// effects (actionfacts: the network facts of the commands that run, with
// wrappers, bash -c and substitutions followed), never from a pattern over the
// command text (GAP-0363). Quoted text, a commit message, an echo and a
// here-document name no destination. Where actionfacts has no network fact for
// a sending program (mail, rsync, httpie, aws s3, gsutil, az, a curl -X POST),
// the program's parsed argv is read. A command that may send and cannot be read
// (a host the shell builds, a syntax error) is reported as unreadable: the floor
// then applies the unknown tier to the send, never a text scan. A command past
// shellparse's reading bounds is not parsed at all; it is a cap hit, recorded in
// the reading's bounded.Truncated (the unknown tier, named by its cap).

var (
	scopeRemoteOperand  = lazyregexp.New(`^(?:[^@\s/:]+@)?(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9._-]*):`)
	scopeShellEmailWord = lazyregexp.New(`(?i)[a-z0-9._%+-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}`)
	scopeShellURLRe     = lazyregexp.New(`(?i)^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
)

// scopeSenderPrograms can send data; a command of one whose arguments the parse
// could not read in full is an unreadable send.
var scopeSenderPrograms = map[string]bool{
	"curl": true, "wget": true, "http": true, "https": true, "xh": true, "xhs": true, "scp": true, "rsync": true,
	"sftp": true, "nc": true, "ncat": true, "netcat": true, "mail": true, "mailx": true, "sendmail": true,
	"swaks": true, "msmtp": true, "mutt": true,
}

// shellSendReader reads the parsed commands of one call into the places they send to.
type shellSendReader struct {
	trunc      *bounded.Truncated
	add        func(scopeDest)
	sends      bool
	unreadable bool
}

const maxScopeWrapperDepth = 3

// shellSendDestinations analyzes a call that has shell command values and adds
// the places its commands send to. It reports whether a command sends and
// whether a command that may send could not be read.
func shellSendDestinations(toolName, rawArgs string, commands []string, trunc *bounded.Truncated, add func(scopeDest)) (sends, unreadable bool) {
	r := &shellSendReader{trunc: trunc, add: add}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: toolName, Args: json.RawMessage(rawArgs)})
	if facts.Parse.Status != actionfacts.StatusNotApplicable {
		r.readFacts(facts, commands, 0)
		return r.sends, r.unreadable
	}
	// A tool name actionfacts does not know as a shell: read each command value as bash.
	for _, command := range commands {
		r.readFacts(actionfacts.Analyze(actionfacts.Input{Tool: "bash", Command: command}), []string{command}, 0)
	}
	return r.sends, r.unreadable
}

func (r *shellSendReader) readFacts(facts actionfacts.Facts, commands []string, depth int) {
	// A value past shellparse's reading bounds is read by no reader: actionfacts
	// projects none of its commands (its status is then partial or
	// limit_exceeded) and the parser refuses it. That is a cap hit (the unknown
	// tier, the bound rule), never "no sender" (GAP-0483), whatever the status.
	readable := make([]string, 0, len(commands))
	for _, command := range commands {
		if command == "" {
			continue
		}
		if c := scopeShellBoundCap(command); c != 0 {
			r.trunc.Hit(c)
			continue
		}
		readable = append(readable, command)
	}
	status := facts.Parse.Status
	if status == actionfacts.StatusPartial && len(facts.Commands) == 0 {
		// partial with nothing projected (an operand grammar actionfacts does
		// not know, e.g. curl -d @file) is a projection that failed, not a
		// command with no sender
		status = actionfacts.StatusUnsupported
	}
	switch status {
	case actionfacts.StatusInvalid, actionfacts.StatusLimitExceeded, actionfacts.StatusUnsupported:
		// actionfacts could not project the command. A send is still a command
		// whose name is a sending program, read from the syntax tree (not the
		// text); a command that does not parse is not one the shell runs.
		// Every shell value of the call is read, not the first alone.
		for _, command := range readable {
			if scopeSyntaxHasSender(command) {
				r.sends, r.unreadable = true, true
				break
			}
		}
		return
	}
	byID := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, c := range facts.Commands {
		byID[c.ID] = c
	}
	covered := map[int64]bool{}
	for _, n := range facts.Network {
		c := byID[n.CommandID]
		prog := scopeProgram(c.Program)
		switch {
		case n.Action == actionfacts.NetworkUpload:
			if prog == "curl" && curlGetsQuery(c.Argv) {
				covered[n.CommandID] = true
				continue
			}
		case n.Action == actionfacts.NetworkDownload && prog == "curl" && curlSendsMethod(c.Argv) && !curlGetsQuery(c.Argv):
			// curl -X POST is classified a download; the request body goes to the same host
		case n.Action == actionfacts.NetworkConnect && (prog == "nc" || prog == "ncat" || prog == "netcat") && !netcatListensOrProbes(c.Argv):
		default:
			continue
		}
		covered[n.CommandID] = true
		r.sends = true
		host := n.NormalizedHost
		if host == "" {
			host = n.Host
		}
		if host == "" || n.TargetKind == actionfacts.NetworkTargetGenerated || n.TargetKind == actionfacts.NetworkTargetUnknown {
			r.unreadable = true
			continue
		}
		r.add(scopeDest{host: strings.ToLower(host)})
	}
	for _, c := range facts.Commands {
		prog := scopeProgram(c.Program)
		args := c.Argv
		if len(args) > 0 && scopeProgram(args[0]) == prog {
			args = args[1:]
		}
		switch prog {
		case "http", "https", "xh", "xhs":
			r.readHTTPie(args)
		case "rsync", "sftp":
			r.readRemoteCopy(prog, args)
		case "mail", "mailx", "sendmail", "swaks", "msmtp", "mutt":
			r.readMail(args, c.LiteralStdin)
		case "aws":
			if len(args) > 2 && args[0] == "s3" && (args[1] == "cp" || args[1] == "sync" || args[1] == "mv") {
				r.readObjectCopy(args[2:], "s3://")
			}
		case "gsutil":
			for i, a := range args {
				if a == "cp" || a == "rsync" || a == "mv" {
					r.readObjectCopy(args[i+1:], "gs://")
					break
				}
			}
		case "az":
			if len(args) > 2 && args[0] == "storage" && args[1] == "blob" && args[2] == "upload" {
				r.sends = true
				for _, a := range args[3:] {
					if host, ok := scopeURLOperand(a); ok {
						r.add(scopeDest{host: host})
					}
				}
			}
		}
		if scopeSenderPrograms[prog] && !c.ArgvComplete && !covered[c.ID] && scopeMaySend(prog, args) && !scopeHasRemoteOperand(prog, args) {
			// the arguments hold a word the shell builds: whether and where it sends is unknown
			r.sends, r.unreadable = true, true
		}
		if inner := scopeWrappedCommand(prog, args); len(inner) > 0 {
			// env, timeout, nohup, xargs...: actionfacts lists the wrapper, not the command it runs
			if depth >= maxScopeWrapperDepth {
				r.sends, r.unreadable = true, true
				continue
			}
			joined := scopeShellJoin(inner)
			r.readFacts(actionfacts.Analyze(actionfacts.Input{Tool: "bash", Command: joined}), []string{joined}, depth+1)
		}
	}
}

// curlGetsQuery reports a curl with -G or --get: its data goes in the query of a GET.
func curlGetsQuery(argv []string) bool {
	for _, a := range argv {
		if a == "--get" {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1 && strings.Contains(a, "G") && scopeShortFlags(a) {
			return true
		}
	}
	return false
}

func scopeShortFlags(a string) bool {
	for _, c := range a[1:] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// curlSendsMethod reports a curl run with -X or --request POST, PUT or PATCH.
func curlSendsMethod(argv []string) bool {
	for i, a := range argv {
		var m string
		switch {
		case a == "-X" || a == "--request":
			if i+1 < len(argv) {
				m = argv[i+1]
			}
		case strings.HasPrefix(a, "--request="):
			m = a[len("--request="):]
		case strings.HasPrefix(a, "-X") && len(a) > 2:
			m = a[2:]
		}
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH":
			return true
		}
	}
	return false
}

// netcatListensOrProbes reports nc -l (a listener) or -z (a port probe): neither sends.
func netcatListensOrProbes(argv []string) bool {
	for _, a := range argv {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1 && (strings.Contains(a, "l") || strings.Contains(a, "z")) && scopeShortFlags(a) {
			return true
		}
	}
	return false
}

func scopeProgram(word string) string {
	return strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(word, "\\", "/"))), ".exe")
}

// scopeURLOperand returns the host of a word that is a URL (a scheme and a
// host). A host the shell builds (an expansion in it) is unknown: no host.
func scopeURLOperand(word string) (string, bool) {
	loc := scopeShellURLRe.FindStringSubmatchIndex(word)
	if loc == nil {
		return "", false
	}
	return strings.ToLower(word[loc[2]:loc[3]]), true
}

func (r *shellSendReader) readHTTPie(args []string) {
	send := false
	var target string
	for _, a := range args {
		switch {
		case a == "POST" || a == "PUT" || a == "PATCH":
			send = true
		case a == "--form" || a == "-f" || a == "--json" || a == "-j" || a == "--multipart":
			send = true
		case strings.HasPrefix(a, "-"):
		case target == "":
			target = a
		case strings.Contains(a, ":=") || strings.Contains(a, "=@") || (strings.Contains(a, "=") && !strings.Contains(a, "==")) || strings.Contains(a, "@"):
			send = true
		}
	}
	if !send || target == "" {
		return
	}
	r.sends = true
	if host, ok := scopeURLOperand(target); ok {
		r.add(scopeDest{host: host})
		return
	}
	// httpie takes a bare host: host[:port][/path]
	host := target
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	if m := scopeDomainRe.FindStringSubmatch(host); m != nil && strings.EqualFold(m[1], host) && !strings.Contains(host, "\x00") {
		r.add(scopeDest{host: strings.ToLower(host)})
	}
}

func (r *shellSendReader) readRemoteCopy(prog string, args []string) {
	valueFlags := "PilFoScJ"
	if prog == "rsync" {
		valueFlags = "eBMTfFCT"
	}
	var operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			operands = append(operands, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "--"):
			if name, _, hasVal := strings.Cut(a[2:], "="); !hasVal && (name == "rsh" || name == "rsync-path" || name == "exclude" || name == "include" || name == "port" || name == "filter" || name == "files-from") {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if last := a[len(a)-1]; strings.IndexByte(valueFlags, last) >= 0 {
				i++
			}
		default:
			operands = append(operands, a)
		}
	}
	remote := func(op string) (string, bool) {
		if host, ok := scopeURLOperand(op); ok {
			return host, true
		}
		if m := scopeRemoteOperand.FindStringSubmatch(op); m != nil && len(m[1]) > 1 && !strings.Contains(op, "\x00") {
			return strings.ToLower(m[1]), true
		}
		return "", false
	}
	switch {
	case prog == "sftp" && len(operands) > 0:
		if host, ok := remote(operands[0]); ok {
			r.sends = true
			r.add(scopeDest{host: host})
		} else if len(operands) > 0 && !strings.Contains(operands[0], "\x00") && scopeDomainRe.MatchString(operands[0]) && !strings.Contains(operands[0], "/") {
			r.sends = true
			r.add(scopeDest{host: strings.ToLower(strings.TrimPrefix(operands[0][strings.LastIndex(operands[0], "@")+1:], "@"))})
		}
	case len(operands) >= 2:
		// only a remote destination (the last operand) is a send; a remote source is a download
		if host, ok := remote(operands[len(operands)-1]); ok {
			r.sends = true
			r.add(scopeDest{host: host})
		}
	}
}

func (r *shellSendReader) readMail(args []string, here string) {
	r.sends = true
	skip := map[string]bool{"-s": true, "-S": true, "-r": true, "-f": true, "-a": true, "--from": true, "--header": true, "--attach": true, "-F": true, "--subject": true}
	found := false
	add := func(text string) {
		// The capped scanner: a repeat is not a destination, and more matches than
		// the scan allows is a cap hit (GAP-0341).
		for _, m := range scanScopeStrings(scopeShellEmailWord, text, maxScopeMailMatches, r.trunc) {
			found = true
			r.add(scopeDest{mailbox: strings.ToLower(m)})
		}
	}
	for i := 0; i < len(args); i++ {
		if skip[args[i]] {
			i++
			continue
		}
		add(args[i])
	}
	if here != "" {
		add(here)
	}
	if !found {
		// recipients come from headers or a prompt of the program: unknown
		r.unreadable = true
	}
}

func (r *shellSendReader) readObjectCopy(args []string, scheme string) {
	var operands []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			operands = append(operands, a)
		}
	}
	if len(operands) < 2 {
		return
	}
	last := operands[len(operands)-1]
	if !strings.HasPrefix(strings.ToLower(last), scheme) {
		return
	}
	r.sends = true
	if host, ok := scopeURLOperand(last); ok {
		r.add(scopeDest{host: host})
	}
}

// scopeMaySend reports whether the arguments the parse could read leave open that
// the command sends: curl and wget only with a visible body, upload or POST
// option; the programs that exist to send always.
func scopeMaySend(prog string, args []string) bool {
	switch prog {
	case "curl":
		if curlSendsMethod(args) {
			return true
		}
		for _, a := range args {
			switch {
			case a == "--json" || a == "--upload-file" || strings.HasPrefix(a, "--data") || strings.HasPrefix(a, "--form") || strings.HasPrefix(a, "--json="):
				return true
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1 && scopeShortFlags(a) && strings.ContainsAny(a, "dFT"):
				return true
			}
		}
		return false
	case "wget":
		for _, a := range args {
			if strings.HasPrefix(a, "--post-") || strings.HasPrefix(a, "--body-") || strings.HasPrefix(a, "--method=") {
				return true
			}
		}
		return false
	}
	return true
}

// scopeWrappedCommand returns the command a wrapper program runs (env, timeout,
// nohup, nice, ionice, stdbuf, setsid, time, command, exec, xargs), from its
// parsed arguments, or nil when prog is not a wrapper.
func scopeWrappedCommand(prog string, args []string) []string {
	valued := map[string]bool{}
	switch prog {
	case "env":
		valued = map[string]bool{"-u": true, "-C": true, "-S": true}
	case "timeout":
		valued = map[string]bool{"-s": true, "-k": true}
	case "nice":
		valued = map[string]bool{"-n": true}
	case "ionice":
		valued = map[string]bool{"-c": true, "-n": true, "-p": true}
	case "xargs":
		valued = map[string]bool{"-n": true, "-P": true, "-L": true, "-s": true, "-a": true, "-E": true, "-d": true, "-I": true}
	case "nohup", "stdbuf", "setsid", "time", "command", "exec", "builtin":
	default:
		return nil
	}
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case valued[a]:
			i += 2
		case strings.HasPrefix(a, "-") && len(a) > 1:
			i++
		case prog == "env" && strings.Contains(a, "="):
			i++
		case prog == "timeout" && i == firstNonOption(args) && scopeDurationWord(a):
			i++
		default:
			return args[i:]
		}
	}
	return nil
}

func firstNonOption(args []string) int {
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			return i
		}
	}
	return len(args)
}

func scopeDurationWord(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' && c != 's' && c != 'm' && c != 'h' && c != 'd' {
			return false
		}
	}
	return true
}

// scopeShellJoin quotes parsed words into one command text to hand to the parser again.
func scopeShellJoin(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

// scopeHasRemoteOperand reports that a remote-copy command names its remote end in
// static words (host:path): its destination is known whatever else the shell builds.
func scopeHasRemoteOperand(prog string, args []string) bool {
	switch prog {
	case "scp", "rsync", "sftp":
		for _, a := range args {
			if scopeRemoteOperand.MatchString(a) {
				return true
			}
		}
	}
	return false
}

// scopeShellBoundCap returns the cap a shell value past shellparse's reading
// bounds hit (shellparse.BudgetExceeded, NestedBodiesOverBudget), or 0 for a
// value within them. Such a value is refused unparsed, so whether it sends is
// unknown: its reading is cut short at that cap.
func scopeShellBoundCap(command string) bounded.Cap {
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
	default: // chain operators, tokens, brace expansion, and any reason added later
		return bounded.Items
	}
}

// scopeSyntaxHasSender reports whether the parsed command contains a command
// whose name is a sending program and whose static arguments may send. It reads
// the shell syntax tree, not the text. The caller has checked the reading
// bounds (scopeShellBoundCap): a command that does not parse here is a syntax
// error, not one the shell runs.
func scopeSyntaxHasSender(command string) bool {
	file, ok := shellparse.Parse(command)
	if !ok || file == nil {
		return false
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name, ok := scopeLiteralWord(call.Args[0])
		if !ok {
			return true
		}
		prog := scopeProgram(name)
		var args []string
		for _, w := range call.Args[1:] {
			if lit, ok := scopeLiteralWord(w); ok {
				args = append(args, lit)
			} else {
				args = append(args, "")
			}
		}
		if inner := scopeWrappedCommand(prog, args); len(inner) > 0 {
			prog, args = scopeProgram(inner[0]), inner[1:]
		}
		if scopeSenderPrograms[prog] && scopeMaySend(prog, args) && !scopeHasRemoteOperand(prog, args) {
			found = true
		}
		return !found
	})
	return found
}

// scopeLiteralWord is the text of a word made only of literals and quoted text.
func scopeLiteralWord(w *syntax.Word) (string, bool) {
	var b strings.Builder
	var part func(p syntax.WordPart) bool
	part = func(p syntax.WordPart) bool {
		switch t := p.(type) {
		case *syntax.Lit:
			b.WriteString(t.Value)
		case *syntax.SglQuoted:
			b.WriteString(t.Value)
		case *syntax.DblQuoted:
			for _, q := range t.Parts {
				if !part(q) {
					return false
				}
			}
		default:
			return false
		}
		return true
	}
	for _, p := range w.Parts {
		if !part(p) {
			return "", false
		}
	}
	return b.String(), true
}

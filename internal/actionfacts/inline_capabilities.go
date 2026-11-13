// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Inline interpreter code is opaque to the effect model: the shell parser
// sees one argument. This file classifies such code only by the capabilities
// it asks for, using ordinary documented library names from the table below,
// never by what the code is for. Code that asks for a network connection and
// for a process spawn or exec in the same one-liner is "opaque code with
// network and exec" (detection evidence, alert-only). The table is data: a
// language is one row, a capability is a list of library or builtin names.
//
// The scan is token-aware where it can read the code and conservative where
// it cannot. Reading: per language it removes comments and the contents of
// string literals before a name is looked for, so a sentence or a log message
// that mentions "subprocess" asks for nothing; a string that is exactly a
// table name (the way a module is handed to a loader) counts as that name.
// Not reading: the precision filter may only ever remove a name that is
// plainly prose, so whenever the code can hand a string to the interpreter as
// code (an eval-style sink from the row, an interpolation body), or the
// scanner is not sure what it read (an unterminated literal or comment, a
// quote-like operator, a heredoc, a "#" that cannot be a comment, a regular
// expression literal with no end), the whole operand is scanned as text, the
// same scan that existed before the filter. Unknown input is never a clean
// pass.
//
// The pairing is by design: a one-liner that fetches and also spawns a
// process is reported even when it is ordinary tarball handling. That is the
// class this rule owns; it never blocks.

type inlineSyntax struct {
	lineComments  []string
	blockComments [][2]string
	// quotes are the characters that open a string literal.
	quotes string
	// tripleQuotes: a tripled quote opens a long string (python).
	tripleQuotes bool
	// template: backtick opens a template literal whose ${...} bodies are code (javascript family).
	template bool
	// regexLiterals: a slash where an operand may start opens a regular expression literal (javascript family).
	regexLiterals bool
	// longBrackets: [[ ... ]] is a long string (lua).
	longBrackets bool
	// backtickExec: a backtick runs a command (perl, ruby, php).
	backtickExec bool
	// fStrings: a string with an f or F prefix interpolates code (python).
	fStrings bool
	// interpolation lists the markers inside a double-quoted string that start code.
	interpolation []string
	// quoteLike lists the words that open a delimited literal of their own (perl q, qq, qw, ...).
	quoteLike []string
	// percentLiterals: %q(...), %w[...] style literals (ruby).
	percentLiterals bool
	// heredocs: << followed by a word or a quote opens a heredoc whose body this scan does not read.
	heredocs bool
}

type inlineCapabilityRow struct {
	// options are the argv flags whose next operand is the code.
	options []string
	// network and exec list module, function or builtin names, matched as
	// whole identifiers (a dotted name such as os.system matches as written).
	network []string
	exec    []string
	// sinks list the names that turn a string into running code.
	sinks []string
	// dynamicInput lists the names that read a value from outside the code
	// (environment, arguments, stdin): a destination read from them is not
	// the literal next to it.
	dynamicInput []string
	syntax       inlineSyntax
}

var (
	pythonSyntax = inlineSyntax{
		lineComments: []string{"#"}, quotes: `'"`, tripleQuotes: true, fStrings: true,
	}
	jsSyntax = inlineSyntax{
		lineComments: []string{"//"}, blockComments: [][2]string{{"/*", "*/"}}, quotes: `'"`, template: true, regexLiterals: true,
	}
)

var inlineCapabilityTable = map[string]inlineCapabilityRow{
	"python": {
		options:      []string{"-c"},
		network:      []string{"socket", "urllib", "http.client", "requests", "asyncio.open_connection", "ftplib", "telnetlib", "smtplib"},
		exec:         []string{"os.system", "os.popen", "subprocess", "pty", "os.execv", "os.execve", "os.execvp", "os.execl", "os.spawnl", "commands.getoutput"},
		sinks:        []string{"eval", "exec", "compile"},
		dynamicInput: []string{"os.environ", "os.getenv", "sys.argv", "sys.stdin", "input", "getpass"},
		syntax:       pythonSyntax,
	},
	"node": {
		options:      []string{"-e", "--eval", "-p", "--print"},
		network:      []string{"net", "http", "https", "dgram", "tls", "fetch", "WebSocket"},
		exec:         []string{"child_process", "execSync", "spawnSync", "execFile", "spawn", "eval", "Function"},
		sinks:        []string{"eval", "Function", "vm"},
		dynamicInput: []string{"process.env", "process.argv", "process.stdin", "readline"},
		syntax:       jsSyntax,
	},
	"bun": {
		options:      []string{"-e", "--eval", "-p", "--print"},
		network:      []string{"fetch", "WebSocket", "Bun.connect", "net", "http", "https"},
		exec:         []string{"Bun.spawn", "Bun.spawnSync", "child_process", "eval", "Function"},
		sinks:        []string{"eval", "Function", "vm"},
		dynamicInput: []string{"process.env", "process.argv", "Bun.env", "Bun.argv", "Bun.stdin"},
		syntax:       jsSyntax,
	},
	"deno": {
		options:      []string{"eval"},
		network:      []string{"fetch", "Deno.connect", "WebSocket"},
		exec:         []string{"Deno.Command", "Deno.run", "eval", "Function"},
		sinks:        []string{"eval", "Function"},
		dynamicInput: []string{"Deno.env", "Deno.args", "Deno.stdin"},
		syntax:       jsSyntax,
	},
	"perl": {
		options:      []string{"-e", "-E"},
		network:      []string{"IO::Socket", "IO::Socket::INET", "Socket", "LWP::Simple", "HTTP::Tiny"},
		exec:         []string{"system", "exec", "qx"},
		sinks:        []string{"eval"},
		dynamicInput: []string{"ENV", "ARGV", "STDIN"},
		syntax: inlineSyntax{
			lineComments: []string{"#"}, quotes: `'"`, backtickExec: true,
			interpolation: []string{"${", "@{", "$("},
			quoteLike:     []string{"q", "qq", "qw", "qr", "qx", "m", "s", "tr", "y"}, heredocs: true,
		},
	},
	"ruby": {
		options:      []string{"-e"},
		network:      []string{"socket", "TCPSocket", "UDPSocket", "Net::HTTP", "open-uri"},
		exec:         []string{"system", "exec", "spawn", "IO.popen", "Open3", "pty"},
		sinks:        []string{"eval", "instance_eval", "class_eval", "module_eval"},
		dynamicInput: []string{"ENV", "ARGV", "STDIN", "gets"},
		syntax: inlineSyntax{
			lineComments: []string{"#"}, quotes: `'"`, backtickExec: true,
			interpolation: []string{"#{"}, percentLiterals: true, heredocs: true,
		},
	},
	"php": {
		options: []string{"-r"},
		// file_get_contents is not here: on a local path it is a file read. A URL
		// handed to it or to fopen is a string literal and counts through the
		// literal-URL test below.
		network:      []string{"fsockopen", "stream_socket_client", "socket_create", "curl_init"},
		exec:         []string{"shell_exec", "system", "passthru", "proc_open", "popen", "exec"},
		sinks:        []string{"eval", "assert", "create_function"},
		dynamicInput: []string{"getenv", "$_SERVER", "$_ENV", "$argv", "$_GET", "$_POST", "STDIN"},
		syntax: inlineSyntax{
			lineComments: []string{"//", "#"}, blockComments: [][2]string{{"/*", "*/"}}, quotes: `'"`, backtickExec: true,
			interpolation: []string{"{$", "${"}, heredocs: true,
		},
	},
	"lua": {
		options:      []string{"-e"},
		network:      []string{"socket", "socket.http"},
		exec:         []string{"os.execute", "io.popen"},
		sinks:        []string{"load", "loadstring"},
		dynamicInput: []string{"os.getenv", "arg", "io.read", "io.stdin"},
		syntax: inlineSyntax{
			lineComments: []string{"--"}, blockComments: [][2]string{{"--[[", "]]"}}, quotes: `'"`, longBrackets: true,
		},
	},
}

// inlineProgramAliases maps argv[0] base names (after dropping a version
// suffix) to a table row.
var inlineProgramAliases = map[string]string{
	"python": "python", "python2": "python", "python3": "python", "pypy": "python", "pypy3": "python",
	"node": "node", "nodejs": "node", "bun": "bun", "deno": "deno",
	"perl": "perl", "ruby": "ruby", "php": "php", "lua": "lua", "luajit": "lua",
}

var (
	inlineLiteralURLPattern = lazyMustCompile(`(?i)\bhttps?://`)
	inlineMatchers          sync.Map // map[string]*regexp.Regexp
)

func identifierMatcher(names []string) *regexp.Regexp {
	key := strings.Join(names, "\x00")
	if cached, ok := inlineMatchers.Load(key); ok {
		return cached.(*regexp.Regexp)
	}
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	matcher := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$.])(?:` + strings.Join(quoted, "|") + `)(?:$|[^A-Za-z0-9_$])`)
	inlineMatchers.Store(key, matcher)
	return matcher
}

func inlineProgramRow(command CommandFact) (inlineCapabilityRow, bool) {
	if len(command.Argv) < 2 || command.Kind != CommandKindProcess {
		return inlineCapabilityRow{}, false
	}
	base := path.Base(command.Argv[0])
	for len(base) > 0 && (base[len(base)-1] == '.' || (base[len(base)-1] >= '0' && base[len(base)-1] <= '9')) &&
		inlineProgramAliases[base] == "" {
		base = base[:len(base)-1]
	}
	key, ok := inlineProgramAliases[base]
	if !ok {
		return inlineCapabilityRow{}, false
	}
	return inlineCapabilityTable[key], true
}

func inlineCodeOperands(row inlineCapabilityRow, args []string) string {
	var code []string
	for index, argument := range args {
		if slices.Contains(row.options, argument) && index+1 < len(args) {
			code = append(code, args[index+1])
		}
	}
	return strings.Join(code, "\n")
}

// inlineScan is the code of a one-liner with comments removed and string
// contents blanked, plus the contents of its string literals. Unreadable says
// the scanner is not sure what it read; Interpolates says a string body may
// hold code.
type inlineScan struct {
	code         string
	literals     []string
	unreadable   bool
	interpolates bool
}

type inlineScanner struct {
	source     string
	pos        int
	syntax     inlineSyntax
	out        strings.Builder
	literals   []string
	unreadable bool
	interpoles bool
}

func scanInlineCode(source string, syntax inlineSyntax) inlineScan {
	scanner := &inlineScanner{source: source, syntax: syntax}
	scanner.scan(false)
	return inlineScan{
		code: scanner.out.String(), literals: scanner.literals,
		unreadable: scanner.unreadable, interpolates: scanner.interpoles,
	}
}

func isIdentifierByte(c byte) bool {
	return c == '_' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// scan reads code until the end, or until the brace that closes a template
// literal expression.
func (s *inlineScanner) scan(untilBrace bool) {
	depth := 0
	for s.pos < len(s.source) {
		rest := s.source[s.pos:]
		switch c := s.source[s.pos]; {
		case s.skipBlockComment(rest):
		case s.skipLineComment(rest):
		case s.syntax.longBrackets && strings.HasPrefix(rest, "[["):
			s.pos += 2
			s.literal(s.until("]]"))
		case strings.IndexByte(s.syntax.quotes, c) >= 0:
			s.quoted(c)
		case s.syntax.template && c == '`':
			s.pos++
			s.templateLiteral()
		case s.syntax.regexLiterals && c == '/' && s.regexMayStart():
			s.regexLiteral()
		case s.unsureConstruct(rest):
			s.unreadable = true
			s.out.WriteByte(c)
			s.pos++
		default:
			if untilBrace {
				if c == '{' {
					depth++
				} else if c == '}' {
					if depth == 0 {
						s.pos++
						return
					}
					depth--
				}
			}
			s.out.WriteByte(c)
			s.pos++
		}
	}
}

// unsureConstruct reports the start of a construct this scanner does not
// read: a quote-like operator, a percent literal, a heredoc.
func (s *inlineScanner) unsureConstruct(rest string) bool {
	if s.pos > 0 && isIdentifierByte(s.source[s.pos-1]) {
		return false
	}
	if s.syntax.heredocs && strings.HasPrefix(rest, "<<") && len(rest) > 2 &&
		(isIdentifierByte(rest[2]) || strings.IndexByte("'\"~-", rest[2]) >= 0) {
		return true
	}
	if s.syntax.percentLiterals && rest[0] == '%' && len(rest) > 1 {
		next := rest[1]
		if strings.IndexByte("qQwWiIrsx", next) >= 0 && len(rest) > 2 {
			next = rest[2]
		}
		return strings.IndexByte("([{<|!/", next) >= 0
	}
	for _, word := range s.syntax.quoteLike {
		if strings.HasPrefix(rest, word) && len(rest) > len(word) &&
			!isIdentifierByte(rest[len(word)]) && strings.IndexByte("/{([<|!#~^@%:", rest[len(word)]) >= 0 {
			return true
		}
	}
	return false
}

func (s *inlineScanner) skipBlockComment(rest string) bool {
	for _, pair := range s.syntax.blockComments {
		if strings.HasPrefix(rest, pair[0]) {
			s.pos += len(pair[0])
			if _, closed := s.untilFound(pair[1]); !closed {
				s.unreadable = true
			}
			s.out.WriteByte(' ')
			return true
		}
	}
	return false
}

// skipLineComment skips a line comment. A "#" is a comment only where a
// comment can start (the beginning of the text or after a space, a statement
// or a bracket); anywhere else it is the last-index sigil, a delimiter, a
// color, and the scan is unsure.
func (s *inlineScanner) skipLineComment(rest string) bool {
	for _, marker := range s.syntax.lineComments {
		if !strings.HasPrefix(rest, marker) {
			continue
		}
		if marker == "#" && s.pos > 0 && strings.IndexByte(" \t\r\n;{}()", s.source[s.pos-1]) < 0 {
			s.unreadable = true
			return false
		}
		end := strings.IndexByte(rest, '\n')
		if end < 0 {
			end = len(rest)
		}
		s.pos += end
		return true
	}
	return false
}

func (s *inlineScanner) untilFound(terminator string) (string, bool) {
	start := s.pos
	if end := strings.Index(s.source[start:], terminator); end >= 0 {
		s.pos = start + end + len(terminator)
		return s.source[start : start+end], true
	}
	s.pos = len(s.source)
	return s.source[start:], false
}

// until consumes up to and including terminator and returns the text before
// it; a missing terminator makes the scan unsure.
func (s *inlineScanner) until(terminator string) string {
	text, closed := s.untilFound(terminator)
	if !closed {
		s.unreadable = true
	}
	return text
}

// regexMayStart reports whether a slash here opens a regular expression
// literal: it does where an operand may start, after an operator, a bracket,
// a comma or at the start of the code.
func (s *inlineScanner) regexMayStart() bool {
	text := s.out.String()
	for i := len(text) - 1; i >= 0; i-- {
		if text[i] == ' ' || text[i] == '\t' || text[i] == '\n' {
			continue
		}
		return strings.IndexByte("(,=:[!&|?{};+-*%<>~^", text[i]) >= 0
	}
	return true
}

// regexLiteral skips a regular expression literal; one that has no end on
// its line makes the scan unsure.
func (s *inlineScanner) regexLiteral() {
	start := s.pos + 1
	inClass := false
	for i := start; i < len(s.source); i++ {
		switch c := s.source[i]; {
		case c == '\n':
			s.unreadable = true
			s.out.WriteByte('/')
			s.pos++
			return
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			s.pos = i + 1
			s.out.WriteByte(' ')
			return
		}
	}
	s.unreadable = true
	s.out.WriteByte('/')
	s.pos++
}

func (s *inlineScanner) quoted(quote byte) {
	prefix := s.stringPrefix()
	delimiter := string(quote)
	if s.syntax.tripleQuotes && strings.HasPrefix(s.source[s.pos:], strings.Repeat(delimiter, 3)) {
		delimiter = strings.Repeat(delimiter, 3)
	}
	s.pos += len(delimiter)
	start := s.pos
	closed := false
	for s.pos < len(s.source) {
		if s.source[s.pos] == '\\' {
			s.pos += 2
			continue
		}
		if strings.HasPrefix(s.source[s.pos:], delimiter) {
			closed = true
			break
		}
		s.pos++
	}
	s.pos = min(s.pos, len(s.source))
	content := s.source[start:s.pos]
	if closed {
		s.pos = min(s.pos+len(delimiter), len(s.source))
	} else {
		s.unreadable = true
	}
	if s.syntax.fStrings && strings.ContainsAny(prefix, "fF") {
		s.interpoles = true
	}
	if quote == '"' {
		for _, marker := range s.syntax.interpolation {
			if strings.Contains(content, marker) {
				s.interpoles = true
			}
		}
	}
	s.literal(content)
}

// stringPrefix returns the letters directly before the opening quote (the r, b
// and f of a python string).
func (s *inlineScanner) stringPrefix() string {
	end := s.pos
	begin := end
	for begin > 0 && end-begin < 3 && isIdentifierByte(s.source[begin-1]) {
		begin--
	}
	return s.source[begin:end]
}

// templateLiteral reads a JavaScript template literal: its text is string
// content, its ${...} bodies are code.
func (s *inlineScanner) templateLiteral() {
	var text strings.Builder
	for s.pos < len(s.source) {
		switch {
		case s.source[s.pos] == '\\':
			s.pos += 2
		case s.source[s.pos] == '`':
			s.pos++
			s.literal(text.String())
			return
		case strings.HasPrefix(s.source[s.pos:], "${"):
			s.pos += 2
			s.out.WriteByte(' ')
			s.scan(true)
		default:
			text.WriteByte(s.source[s.pos])
			s.pos++
		}
	}
	s.unreadable = true
	s.literal(text.String())
}

// literal records a string literal and writes a placeholder for it.
func (s *inlineScanner) literal(content string) {
	s.literals = append(s.literals, content)
	s.out.WriteByte(' ')
}

// InlineCodeNetworkAndExec reports an interpreter one-liner that asks for a
// network capability (a library name from the table, in code or as a whole
// string, or a URL string literal) and a process spawn or exec capability.
// Code whose destinations are all loopback literals, with no value read from
// outside the code, is a test of a local service and is not a network
// capability.
func InlineCodeNetworkAndExec(facts Facts) bool {
	for _, command := range facts.Commands {
		row, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		source := inlineCodeOperands(row, command.Argv[1:])
		if source != "" && inlineSourceNetworkAndExec(row, source) {
			return true
		}
	}
	return false
}

func inlineSourceNetworkAndExec(row inlineCapabilityRow, source string) bool {
	scan := scanInlineCode(source, row.syntax)
	// Text to match names in: the code with strings and comments removed, or,
	// where a string may be code or the scan is unsure, the whole operand.
	text, literals := scan.code, scan.literals
	opaque := scan.unreadable || scan.interpolates || identifierMatcher(row.sinks).MatchString(scan.code)
	if opaque {
		text, literals = source, []string{source}
	}
	network := identifierMatcher(row.network).MatchString(text) || inlineLiteralsAre(scan.literals, row.network) ||
		inlineLiteralsHaveURL(literals)
	if !network {
		return false
	}
	if !opaque && !identifierMatcher(row.dynamicInput).MatchString(text) && inlineCodeOnlyLoopback(literals) {
		return false
	}
	return identifierMatcher(row.exec).MatchString(text) || inlineLiteralsAre(scan.literals, row.exec) ||
		(row.syntax.backtickExec && strings.Contains(text, "`"))
}

// inlineLiteralsAre reports a string literal that is exactly one of the names:
// the way a module is handed to a loader.
func inlineLiteralsAre(literals, names []string) bool {
	for _, literal := range literals {
		if slices.Contains(names, strings.TrimPrefix(strings.TrimSpace(literal), "node:")) {
			return true
		}
	}
	return false
}

func inlineLiteralsHaveURL(literals []string) bool {
	for _, literal := range literals {
		if inlineLiteralURLPattern.MatchString(literal) {
			return true
		}
	}
	return false
}

// runnerSpec describes a package or script runner that executes the target it
// is given: the subcommand words that select that behavior ("" means the first
// operand is the target) and the options that take a separate value.
type runnerSpec struct {
	subcommands  []string
	valueOptions []string
}

var runnerTable = map[string]runnerSpec{
	"bun":     {subcommands: []string{"run", "x"}, valueOptions: []string{"--cwd", "--config", "-c", "--env-file", "--preload", "-r", "--filter"}},
	"bunx":    {subcommands: []string{""}, valueOptions: []string{"--package", "-p", "--cwd", "--config", "-c"}},
	"deno":    {subcommands: []string{"run"}, valueOptions: []string{"--config", "-c", "--import-map", "--cert", "--location", "--v8-flags", "--lock", "--reload", "-r"}},
	"npx":     {subcommands: []string{""}, valueOptions: []string{"--package", "-p", "--call", "-c", "--registry", "--cache", "--userconfig", "--prefix"}},
	"npm":     {subcommands: []string{"exec", "x"}, valueOptions: []string{"--package", "-p", "--call", "-c", "--workspace", "-w", "--registry", "--cache", "--userconfig", "--prefix"}},
	"pnpm":    {subcommands: []string{"dlx"}, valueOptions: []string{"--package", "-p", "--registry", "--reporter", "--filter"}},
	"yarn":    {subcommands: []string{"dlx"}, valueOptions: []string{"--package", "-p", "--cwd"}},
	"uv":      {subcommands: []string{"run"}, valueOptions: []string{"--with", "--python", "-p", "--directory", "--project", "--with-requirements", "--env-file", "--index", "--index-url", "--extra-index-url", "--config-file"}},
	"pipx":    {subcommands: []string{"run"}, valueOptions: []string{"--spec", "--python", "--pip-args", "--index-url", "--path"}},
	"uvx":     {subcommands: []string{""}, valueOptions: []string{"--from", "--with", "--python", "-p", "--directory", "--index", "--index-url", "--extra-index-url", "--config-file"}},
	"tsx":     {subcommands: []string{""}, valueOptions: []string{"--tsconfig", "--require", "-r", "--import"}},
	"ts-node": {subcommands: []string{""}, valueOptions: []string{"--project", "-P", "--require", "-r", "--esm"}},
}

// RemoteRunnerURL reports a package or script runner told to execute a URL:
// fetched content executed in the same call, the same fetch-then-exec shape
// the staged-download proof covers across commands. Every runner in the table
// is treated alike, deno run included: running a remote script is the class
// this rule reports, and it only alerts.
func RemoteRunnerURL(facts Facts) bool {
	for _, command := range facts.Commands {
		if command.Kind != CommandKindProcess || len(command.Argv) < 2 {
			continue
		}
		if spec, ok := runnerTable[path.Base(command.Argv[0])]; ok && runnerTargetIsURL(command.Argv[1:], spec) {
			return true
		}
	}
	return false
}

func runnerTargetIsURL(args []string, spec runnerSpec) bool {
	selected := slices.Contains(spec.subcommands, "")
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if strings.HasPrefix(argument, "-") {
			if !strings.Contains(argument, "=") && slices.Contains(spec.valueOptions, argument) {
				index++
			}
			continue
		}
		if !selected {
			if !slices.Contains(spec.subcommands, argument) {
				return false
			}
			selected = true
			continue
		}
		lower := strings.ToLower(argument)
		return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
	}
	return false
}

var (
	inlineURLAuthorityPattern = lazyMustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^/?#\s'"]*)`)
	inlineIPv4Pattern         = lazyMustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	inlineDottedNamePattern   = lazyMustCompile(`(?i)^(?:localhost|(?:[a-z0-9-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+))$`)
)

// inlineCodeOnlyLoopback reports code whose every literal host is loopback:
// the name localhost or one under .localhost, or a loopback IP literal. The
// test is an allowlist. Any other host, whatever its ending and including a
// private-range address (an internal host is a normal lateral target), makes
// the code a network client, and a host mentioned next to a loopback one is
// not hidden by it. A host is the authority of a URL literal, an IP literal,
// or a whole string literal that is an address or a dotted name, with an
// optional port. Code that names no host at all is not local (the host is
// dynamic); the caller also refuses the exemption when the code reads a value
// from outside itself.
func inlineCodeOnlyLoopback(literals []string) bool {
	var hosts []string
	for _, literal := range literals {
		authorities := inlineURLAuthorityPattern.FindAllStringSubmatch(literal, -1)
		for _, match := range authorities {
			hosts = append(hosts, urlAuthorityHost(match[1]))
		}
		if len(authorities) == 0 {
			if host := wholeLiteralHost(strings.TrimSpace(literal)); host != "" {
				hosts = append(hosts, host)
			}
		}
		hosts = append(hosts, inlineIPv4Pattern.FindAllString(literal, -1)...)
	}
	if len(hosts) == 0 {
		return false
	}
	for _, host := range hosts {
		if !isLoopbackHostName(host) {
			return false
		}
	}
	return true
}

// wholeLiteralHost returns the host of a string literal that is a host (with
// an optional :port), or "".
func wholeLiteralHost(literal string) string {
	if _, err := netip.ParseAddr(strings.Trim(literal, "[]")); err == nil {
		return strings.Trim(literal, "[]")
	}
	host := literal
	if colon := strings.LastIndexByte(literal, ':'); colon > 0 && strings.Count(literal, ":") == 1 {
		port := literal[colon+1:]
		if port != "" && strings.Trim(port, "0123456789") == "" {
			host = literal[:colon]
		}
	}
	if inlineDottedNamePattern.MatchString(host) {
		return host
	}
	return ""
}

func urlAuthorityHost(authority string) string {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	if strings.HasPrefix(authority, "[") {
		if end := strings.IndexByte(authority, ']'); end > 0 {
			return authority[1:end]
		}
	}
	if colon := strings.IndexByte(authority, ':'); colon >= 0 {
		authority = authority[:colon]
	}
	return authority
}

func isLoopbackHostName(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

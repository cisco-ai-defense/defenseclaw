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
// The scan is token-aware, not a text search. Per language it removes
// comments and the contents of string literals before a name is looked for,
// so a sentence or a log message that mentions "subprocess" asks for nothing.
// Two things stay visible on purpose: the module name handed to a loader
// (require, import, __import__), which is how a name is spelled in those
// languages, and the backtick of perl, ruby and php, which is the command
// execution operator and not a string. Known limits, kept because the rule
// only alerts: string interpolation (an f-string or "#{...}" body) is read as
// string text, and a perl "#" inside a regex is read as a comment.
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
	// longBrackets: [[ ... ]] is a long string (lua).
	longBrackets bool
	// backtickExec: a backtick runs a command (perl, ruby, php).
	backtickExec bool
}

type inlineCapabilityRow struct {
	// options are the argv flags whose next operand is the code.
	options []string
	// network and exec list module, function or builtin names, matched as
	// whole identifiers (a dotted name such as os.system matches as written).
	network []string
	exec    []string
	syntax  inlineSyntax
}

var (
	pythonSyntax = inlineSyntax{lineComments: []string{"#"}, quotes: `'"`, tripleQuotes: true}
	jsSyntax     = inlineSyntax{lineComments: []string{"//"}, blockComments: [][2]string{{"/*", "*/"}}, quotes: `'"`, template: true}
)

var inlineCapabilityTable = map[string]inlineCapabilityRow{
	"python": {
		options: []string{"-c"},
		network: []string{"socket", "urllib", "http.client", "requests", "asyncio.open_connection", "ftplib", "telnetlib", "smtplib"},
		exec:    []string{"os.system", "os.popen", "subprocess", "pty", "os.execv", "os.execve", "os.execvp", "os.execl", "os.spawnl", "commands.getoutput"},
		syntax:  pythonSyntax,
	},
	"node": {
		options: []string{"-e", "--eval", "-p", "--print"},
		network: []string{"net", "http", "https", "dgram", "tls", "fetch", "WebSocket"},
		exec:    []string{"child_process", "execSync", "spawnSync", "execFile", "spawn", "eval", "Function"},
		syntax:  jsSyntax,
	},
	"bun": {
		options: []string{"-e", "--eval", "-p", "--print"},
		network: []string{"fetch", "WebSocket", "Bun.connect", "net", "http", "https"},
		exec:    []string{"Bun.spawn", "Bun.spawnSync", "child_process", "eval", "Function"},
		syntax:  jsSyntax,
	},
	"deno": {
		options: []string{"eval"},
		network: []string{"fetch", "Deno.connect", "WebSocket"},
		exec:    []string{"Deno.Command", "Deno.run", "eval", "Function"},
		syntax:  jsSyntax,
	},
	"perl": {
		options: []string{"-e", "-E"},
		network: []string{"IO::Socket", "IO::Socket::INET", "Socket", "LWP::Simple", "HTTP::Tiny"},
		exec:    []string{"system", "exec", "qx"},
		syntax:  inlineSyntax{lineComments: []string{"#"}, quotes: `'"`, backtickExec: true},
	},
	"ruby": {
		options: []string{"-e"},
		network: []string{"socket", "TCPSocket", "UDPSocket", "Net::HTTP", "open-uri"},
		exec:    []string{"system", "exec", "spawn", "IO.popen", "Open3", "pty"},
		syntax:  inlineSyntax{lineComments: []string{"#"}, quotes: `'"`, backtickExec: true},
	},
	"php": {
		options: []string{"-r"},
		// file_get_contents is not here: on a local path it is a file read. A URL
		// handed to it or to fopen is a string literal and counts through the
		// literal-URL test below.
		network: []string{"fsockopen", "stream_socket_client", "socket_create", "curl_init"},
		exec:    []string{"shell_exec", "system", "passthru", "proc_open", "popen", "exec"},
		syntax: inlineSyntax{
			lineComments: []string{"//", "#"}, blockComments: [][2]string{{"/*", "*/"}}, quotes: `'"`, backtickExec: true,
		},
	},
	"lua": {
		options: []string{"-e"},
		network: []string{"socket", "socket.http"},
		exec:    []string{"os.execute", "io.popen"},
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
	inlineModuleLoader      = lazyMustCompile(
		`(?:^|[^A-Za-z0-9_$.])(?:require|require_once|import|__import__|from)\s*\(?\s*$|importlib\.import_module\s*\(\s*$`,
	)
	inlineModuleName = lazyMustCompile(`^[A-Za-z0-9_@./:-]+$`)
	inlineMatchers   sync.Map // map[string]*regexp.Regexp
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
// contents blanked, plus the contents of its string literals.
type inlineScan struct {
	code     string
	literals []string
}

type inlineScanner struct {
	source   string
	pos      int
	syntax   inlineSyntax
	out      strings.Builder
	literals []string
}

func scanInlineCode(source string, syntax inlineSyntax) inlineScan {
	scanner := &inlineScanner{source: source, syntax: syntax}
	scanner.scan(false)
	return inlineScan{code: scanner.out.String(), literals: scanner.literals}
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
			s.literal(s.until("]]"), false)
		case strings.IndexByte(s.syntax.quotes, c) >= 0:
			s.quoted(c)
		case s.syntax.template && c == '`':
			s.pos++
			s.templateLiteral()
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

func (s *inlineScanner) skipBlockComment(rest string) bool {
	for _, pair := range s.syntax.blockComments {
		if strings.HasPrefix(rest, pair[0]) {
			s.pos += len(pair[0])
			s.until(pair[1])
			s.out.WriteByte(' ')
			return true
		}
	}
	return false
}

func (s *inlineScanner) skipLineComment(rest string) bool {
	for _, marker := range s.syntax.lineComments {
		if strings.HasPrefix(rest, marker) {
			end := strings.IndexByte(rest, '\n')
			if end < 0 {
				end = len(rest)
			}
			s.pos += end
			return true
		}
	}
	return false
}

// until consumes up to and including terminator and returns the text before it.
func (s *inlineScanner) until(terminator string) string {
	start := s.pos
	if end := strings.Index(s.source[start:], terminator); end >= 0 {
		s.pos = start + end + len(terminator)
		return s.source[start : start+end]
	}
	s.pos = len(s.source)
	return s.source[start:]
}

func (s *inlineScanner) quoted(quote byte) {
	delimiter := string(quote)
	if s.syntax.tripleQuotes && strings.HasPrefix(s.source[s.pos:], strings.Repeat(delimiter, 3)) {
		delimiter = strings.Repeat(delimiter, 3)
	}
	s.pos += len(delimiter)
	start := s.pos
	for s.pos < len(s.source) {
		if s.source[s.pos] == '\\' {
			s.pos += 2
			continue
		}
		if strings.HasPrefix(s.source[s.pos:], delimiter) {
			break
		}
		s.pos++
	}
	s.pos = min(s.pos, len(s.source))
	content := s.source[start:s.pos]
	s.pos = min(s.pos+len(delimiter), len(s.source))
	s.literal(content, true)
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
			s.literal(text.String(), false)
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
	s.literal(text.String(), false)
}

// literal records a string literal and writes a placeholder for it. A module
// name given to a loader is how that language spells a library, so it stays.
func (s *inlineScanner) literal(content string, loaderArgument bool) {
	s.literals = append(s.literals, content)
	tail := s.out.String()
	tail = tail[max(0, len(tail)-48):]
	if loaderArgument && inlineModuleLoader.MatchString(tail) && inlineModuleName.MatchString(content) {
		s.out.WriteString(" " + content + " ")
		return
	}
	s.out.WriteByte(' ')
}

// InlineCodeNetworkAndExec reports an interpreter one-liner that asks for a
// network capability (a library name from the table in code, or a URL string
// literal) and a process spawn or exec capability. Code whose every literal
// host is loopback or private is a test of a local service and is not a
// network capability.
func InlineCodeNetworkAndExec(facts Facts) bool {
	for _, command := range facts.Commands {
		row, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		source := inlineCodeOperands(row, command.Argv[1:])
		if source == "" {
			continue
		}
		scan := scanInlineCode(source, row.syntax)
		network := identifierMatcher(row.network).MatchString(scan.code) || inlineLiteralsHaveURL(scan.literals)
		if !network || inlineCodeOnlyLocal(scan.literals) {
			continue
		}
		if identifierMatcher(row.exec).MatchString(scan.code) || (row.syntax.backtickExec && strings.Contains(scan.code, "`")) {
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

// runnerSubcommands lists the package runners that execute the target they
// are given, and the subcommand words that select that behavior ("" means the
// first operand is the target).
var runnerSubcommands = map[string][]string{
	"bun":  {"run", "x"},
	"bunx": {""},
	"deno": {"run"},
	"npx":  {""},
	"pnpm": {"dlx"},
	"yarn": {"dlx"},
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
		subcommands, ok := runnerSubcommands[path.Base(command.Argv[0])]
		if ok && runnerTargetIsURL(command.Argv[1:], subcommands) {
			return true
		}
	}
	return false
}

func runnerTargetIsURL(args, subcommands []string) bool {
	selected := slices.Contains(subcommands, "")
	for _, argument := range args {
		if strings.HasPrefix(argument, "-") {
			continue
		}
		if !selected {
			if !slices.Contains(subcommands, argument) {
				return false
			}
			selected = true
			continue
		}
		return strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://")
	}
	return false
}

var (
	inlineURLAuthorityPattern = lazyMustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^/?#\s'"]*)`)
	inlineIPv4Pattern         = lazyMustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	inlineDottedNamePattern   = lazyMustCompile(`(?i)^(?:localhost|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$`)
)

// inlineCodeOnlyLocal reports code whose every literal host is local: the name
// localhost or one under .localhost, or an IP literal in a loopback, private
// or link-local range. The test is an allowlist. Any other host, whatever its
// ending, makes the code a network client, and a host mentioned next to a
// local one is not hidden by it. A host is the authority of a URL literal, an
// IPv4 literal, or a whole string literal that is localhost or a dotted name. Code that
// names no host at all is not local (the host is dynamic).
func inlineCodeOnlyLocal(literals []string) bool {
	var hosts []string
	for _, literal := range literals {
		authorities := inlineURLAuthorityPattern.FindAllStringSubmatch(literal, -1)
		for _, match := range authorities {
			hosts = append(hosts, urlAuthorityHost(match[1]))
		}
		if len(authorities) == 0 {
			if trimmed := strings.TrimSpace(literal); inlineDottedNamePattern.MatchString(trimmed) {
				hosts = append(hosts, trimmed)
			}
		}
		hosts = append(hosts, inlineIPv4Pattern.FindAllString(literal, -1)...)
	}
	if len(hosts) == 0 {
		return false
	}
	for _, host := range hosts {
		if !isLocalHostName(host) {
			return false
		}
	}
	return true
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

func isLocalHostName(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && (address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast())
}

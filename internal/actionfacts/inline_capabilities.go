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
// The names are looked for in the whole operand as text, comments and string
// bodies included. A lexer that removed prose first was tried and dropped: on
// the owner traces the plain scan reports nothing, so the lexer bought no
// precision, and every language's quoting, regular-expression, heredoc and
// long-bracket rules made it misread balanced code as prose (code that was
// plainly there went unseen). A one-liner that merely names a network library
// and a process library in a sentence alerts; that is the price of never
// reading code as prose, and the rule only alerts.
//
// The pairing is by design: a one-liner that fetches and also spawns a
// process is reported even when it is ordinary tarball handling. That is the
// class this rule owns; it never blocks.

type inlineCapabilityRow struct {
	// options are the argv flags whose next operand is the code.
	options []string
	// network and exec list module, function or builtin names, matched as
	// whole identifiers (a dotted name such as os.system matches as written).
	network []string
	exec    []string
	// dynamicInput lists the names that read a value from outside the code
	// (environment, arguments, stdin): a destination read from them is not
	// the literal next to it.
	dynamicInput []string
	// backtickExec: a backtick runs a command (perl, ruby, php).
	backtickExec bool
}

var inlineCapabilityTable = map[string]inlineCapabilityRow{
	"python": {
		options:      []string{"-c"},
		network:      []string{"socket", "urllib", "http.client", "requests", "asyncio.open_connection", "ftplib", "telnetlib", "smtplib"},
		exec:         []string{"os.system", "os.popen", "subprocess", "pty", "os.execv", "os.execve", "os.execvp", "os.execl", "os.spawnl", "commands.getoutput"},
		dynamicInput: []string{"os.environ", "os.getenv", "sys.argv", "sys.stdin", "input", "getpass"},
	},
	"node": {
		options:      []string{"-e", "--eval", "-p", "--print"},
		network:      []string{"net", "http", "https", "dgram", "tls", "fetch", "WebSocket"},
		exec:         []string{"child_process", "execSync", "spawnSync", "execFile", "spawn", "eval", "Function"},
		dynamicInput: []string{"process.env", "process.argv", "process.stdin", "readline"},
	},
	"bun": {
		options:      []string{"-e", "--eval", "-p", "--print"},
		network:      []string{"fetch", "WebSocket", "Bun.connect", "net", "http", "https"},
		exec:         []string{"Bun.spawn", "Bun.spawnSync", "child_process", "eval", "Function"},
		dynamicInput: []string{"process.env", "process.argv", "Bun.env", "Bun.argv", "Bun.stdin"},
	},
	"deno": {
		options:      []string{"eval"},
		network:      []string{"fetch", "Deno.connect", "WebSocket"},
		exec:         []string{"Deno.Command", "Deno.run", "eval", "Function"},
		dynamicInput: []string{"Deno.env", "Deno.args", "Deno.stdin"},
	},
	"perl": {
		options:      []string{"-e", "-E"},
		network:      []string{"IO::Socket", "IO::Socket::INET", "Socket", "LWP::Simple", "HTTP::Tiny"},
		exec:         []string{"system", "exec", "qx"},
		dynamicInput: []string{"ENV", "ARGV", "STDIN"},
		backtickExec: true,
	},
	"ruby": {
		options:      []string{"-e"},
		network:      []string{"socket", "TCPSocket", "UDPSocket", "Net::HTTP", "open-uri"},
		exec:         []string{"system", "exec", "spawn", "IO.popen", "Open3", "pty"},
		dynamicInput: []string{"ENV", "ARGV", "STDIN", "gets"},
		backtickExec: true,
	},
	"php": {
		options: []string{"-r"},
		// file_get_contents is not here: on a local path it is a file read. A URL
		// handed to it or to fopen is a URL in the text and counts through the
		// URL test below.
		network:      []string{"fsockopen", "stream_socket_client", "socket_create", "curl_init"},
		exec:         []string{"shell_exec", "system", "passthru", "proc_open", "popen", "exec"},
		dynamicInput: []string{"getenv", "$_SERVER", "$_ENV", "$argv", "$_GET", "$_POST", "STDIN"},
		backtickExec: true,
	},
	"lua": {
		options:      []string{"-e"},
		network:      []string{"socket", "socket.http"},
		exec:         []string{"os.execute", "io.popen"},
		dynamicInput: []string{"os.getenv", "arg", "io.read", "io.stdin"},
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

func inlineProgramRow(command CommandFact) (inlineCapabilityRow, []string, bool) {
	argv := transparentWrapperTarget(command.Argv)
	if len(argv) < 2 || command.Kind != CommandKindProcess {
		return inlineCapabilityRow{}, nil, false
	}
	base := path.Base(argv[0])
	for len(base) > 0 && (base[len(base)-1] == '.' || (base[len(base)-1] >= '0' && base[len(base)-1] <= '9')) &&
		inlineProgramAliases[base] == "" {
		base = base[:len(base)-1]
	}
	key, ok := inlineProgramAliases[base]
	if !ok {
		return inlineCapabilityRow{}, nil, false
	}
	return inlineCapabilityTable[key], argv, true
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

// InlineCodeNetworkAndExec reports an interpreter one-liner that asks for a
// network capability (a library name from the table, or a URL) and a process
// spawn or exec capability. Code whose destinations are all loopback literals,
// with no value read from outside the code, is a test of a local service and
// is not a network capability.
func InlineCodeNetworkAndExec(facts Facts) bool {
	for _, command := range facts.Commands {
		row, argv, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		if source := inlineCodeOperands(row, argv[1:]); source != "" && inlineSourceNetworkAndExec(row, source) {
			return true
		}
	}
	return false
}

func inlineSourceNetworkAndExec(row inlineCapabilityRow, source string) bool {
	if !identifierMatcher(row.network).MatchString(source) && !inlineLiteralURLPattern.MatchString(source) {
		return false
	}
	if !identifierMatcher(row.dynamicInput).MatchString(source) && inlineCodeOnlyLoopback(source) {
		return false
	}
	return identifierMatcher(row.exec).MatchString(source) || (row.backtickExec && strings.Contains(source, "`"))
}

// transparentWrappers are the commands that start the next word as the real
// command and change nothing about it: each entry lists the options that take
// a separate value and how many plain operands precede the command (timeout
// takes a duration). env and command are read by POSIXExecWrapperTarget.
var transparentWrappers = map[string]struct {
	valueOptions []string
	operands     int
}{
	"nohup":   {},
	"time":    {valueOptions: []string{"-f", "--format", "-o", "--output"}},
	"nice":    {valueOptions: []string{"-n", "--adjustment"}},
	"ionice":  {valueOptions: []string{"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}},
	"stdbuf":  {valueOptions: []string{"-i", "--input", "-o", "--output", "-e", "--error"}},
	"timeout": {valueOptions: []string{"-s", "--signal", "-k", "--kill-after"}, operands: 1},
}

// transparentWrapperTarget returns argv without leading transparent wrappers
// (env and command through the shared reader, the rest from the table above).
func transparentWrapperTarget(argv []string) []string {
	for range 8 {
		argv = POSIXExecWrapperTarget(argv)
		if len(argv) == 0 {
			return argv
		}
		wrapper, ok := transparentWrappers[path.Base(argv[0])]
		if !ok {
			return argv
		}
		rest := argv[1:]
		operands := wrapper.operands
		for len(rest) > 0 {
			argument := rest[0]
			switch {
			case argument == "--":
				rest = rest[1:]
			case strings.HasPrefix(argument, "-") && len(argument) > 1:
				step := 1
				if !strings.Contains(argument, "=") && slices.Contains(wrapper.valueOptions, argument) {
					step = 2
				}
				rest = rest[min(step, len(rest)):]
				continue
			case operands > 0:
				operands--
				rest = rest[1:]
				continue
			}
			break
		}
		argv = rest
	}
	return argv
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
	"deno":    {subcommands: []string{"run"}, valueOptions: []string{"--config", "-c", "--import-map", "--cert", "--location", "--v8-flags", "--lock"}},
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
		argv := transparentWrapperTarget(command.Argv)
		if command.Kind != CommandKindProcess || len(argv) < 2 {
			continue
		}
		if spec, ok := runnerTable[path.Base(argv[0])]; ok && runnerTargetIsURL(argv[1:], spec) {
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

// inlineQuotedPattern finds the quoted strings of a one-liner. It is used only
// to find host literals, not to decide what is code.
var inlineQuotedPattern = lazyMustCompile(`'([^'\n]*)'|"([^"\n]*)"`)

// inlineCodeOnlyLoopback reports code whose every literal host is loopback:
// the name localhost or one under .localhost, or a loopback IP literal. The
// test is an allowlist. Any other host, whatever its ending and including a
// private-range address (an internal host is a normal lateral target), makes
// the code a network client, and a host mentioned next to a loopback one is
// not hidden by it. A host is the authority of a URL, an IP literal, or a
// whole quoted string that is an address or a dotted name, with an optional
// port. Code that names no host at all is not local (the host is dynamic);
// the caller also refuses the exemption when the code reads a value from
// outside itself.
func inlineCodeOnlyLoopback(source string) bool {
	var hosts []string
	for _, match := range inlineURLAuthorityPattern.FindAllStringSubmatch(source, -1) {
		hosts = append(hosts, urlAuthorityHost(match[1]))
	}
	for _, match := range inlineQuotedPattern.FindAllStringSubmatch(source, -1) {
		literal := strings.TrimSpace(match[1] + match[2])
		if inlineURLAuthorityPattern.MatchString(literal) {
			continue
		}
		if host := wholeLiteralHost(literal); host != "" {
			hosts = append(hosts, host)
		}
	}
	hosts = append(hosts, inlineIPv4Pattern.FindAllString(source, -1)...)
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

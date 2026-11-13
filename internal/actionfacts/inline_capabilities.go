// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"path"
	"regexp"
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

type inlineCapabilityRow struct {
	// options are the argv flags whose next operand is the code.
	options []string
	// network and exec list module, function or builtin names, matched as
	// whole identifiers (a dotted name such as os.system matches as written).
	network []string
	exec    []string
}

var inlineCapabilityTable = map[string]inlineCapabilityRow{
	"python": {
		options: []string{"-c"},
		network: []string{"socket", "urllib", "http.client", "requests", "asyncio.open_connection", "ftplib", "telnetlib", "smtplib"},
		exec:    []string{"os.system", "os.popen", "subprocess", "pty", "os.execv", "os.execve", "os.execvp", "os.execl", "os.spawnl", "commands.getoutput"},
	},
	"node": {
		options: []string{"-e", "--eval", "-p", "--print"},
		network: []string{"net", "http", "https", "dgram", "tls", "fetch", "WebSocket"},
		exec:    []string{"child_process", "execSync", "spawnSync", "execFile", "spawn", "eval", "Function"},
	},
	"bun": {
		options: []string{"-e", "--eval", "-p", "--print"},
		network: []string{"fetch", "WebSocket", "Bun.connect", "net", "http", "https"},
		exec:    []string{"Bun.spawn", "Bun.spawnSync", "child_process", "eval", "Function"},
	},
	"deno": {
		options: []string{"eval"},
		network: []string{"fetch", "Deno.connect", "WebSocket"},
		exec:    []string{"Deno.Command", "Deno.run", "eval", "Function"},
	},
	"perl": {
		options: []string{"-e", "-E"},
		network: []string{"IO::Socket", "IO::Socket::INET", "Socket", "LWP::Simple", "HTTP::Tiny"},
		exec:    []string{"system", "exec", "qx"},
	},
	"ruby": {
		options: []string{"-e"},
		network: []string{"socket", "TCPSocket", "UDPSocket", "Net::HTTP", "open-uri"},
		exec:    []string{"system", "exec", "spawn", "IO.popen", "Open3", "pty"},
	},
	"php": {
		options: []string{"-r"},
		network: []string{"fsockopen", "stream_socket_client", "socket_create", "curl_init", "file_get_contents"},
		exec:    []string{"shell_exec", "system", "passthru", "proc_open", "popen", "exec"},
	},
	"lua": {
		options: []string{"-e"},
		network: []string{"socket", "socket.http"},
		exec:    []string{"os.execute", "io.popen"},
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
	inlineLiteralURLPattern = lazyMustCompile(`https?://`)
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
		for _, option := range row.options {
			if argument == option && index+1 < len(args) {
				code = append(code, args[index+1])
			}
		}
	}
	return strings.Join(code, "\n")
}

// InlineCodeNetworkAndExec reports an interpreter one-liner that asks for a
// network capability (a library name from the table, or a literal URL) and a
// process spawn or exec capability.
func InlineCodeNetworkAndExec(facts Facts) bool {
	for _, command := range facts.Commands {
		row, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		code := inlineCodeOperands(row, command.Argv[1:])
		if code == "" {
			continue
		}
		network := (identifierMatcher(row.network).MatchString(code) || inlineLiteralURLPattern.MatchString(code)) &&
			!inlineCodeOnlyLocal(code)
		if network && identifierMatcher(row.exec).MatchString(code) {
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
// the staged-download proof covers across commands.
func RemoteRunnerURL(facts Facts) bool {
	for _, command := range facts.Commands {
		if command.Kind != CommandKindProcess || len(command.Argv) < 2 {
			continue
		}
		subcommands, ok := runnerSubcommands[path.Base(command.Argv[0])]
		if !ok {
			continue
		}
		args := command.Argv[1:]
		selected := false
		for _, subcommand := range subcommands {
			if subcommand == "" {
				selected = true
			}
		}
		for index, argument := range args {
			if strings.HasPrefix(argument, "-") {
				continue
			}
			if !selected {
				for _, subcommand := range subcommands {
					if argument == subcommand {
						selected = true
					}
				}
				if !selected {
					break
				}
				continue
			}
			if strings.HasPrefix(argument, "http://") || strings.HasPrefix(argument, "https://") {
				return true
			}
			_ = index
			break
		}
	}
	return false
}

var (
	inlineHostLiteralPattern = lazyMustCompile(
		`(?i)(?:https?://)?((?:[0-9]{1,3}\.){3}[0-9]{1,3}|localhost|::1|\[::1\]|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|org|net|io|dev|sh|ru|cn|xyz|info|biz|top|cc|tk|ml|ga|cf|gq|app|cloud|site|online|co|me|us|uk|de|fr|jp|kr))\b`,
	)
)

// inlineCodeOnlyLocal reports code whose every literal host is loopback or
// private: a test of a local service, not a connection out. Code that names
// no host at all is not local (the host is dynamic).
func inlineCodeOnlyLocal(code string) bool {
	hosts := inlineHostLiteralPattern.FindAllStringSubmatch(code, -1)
	if len(hosts) == 0 {
		return false
	}
	for _, match := range hosts {
		host := strings.ToLower(strings.Trim(match[1], "[]"))
		if host == "localhost" || host == "::1" {
			continue
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !(address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()) {
			return false
		}
	}
	return true
}

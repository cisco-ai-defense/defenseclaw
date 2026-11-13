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
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The scope floor reads a shell command by its commands, not by the words in its
// text (the owner-trace review of 2cc12b252b: 4 of the 5 floor alerts on real
// turns were this reader misreading shell). A send is a command that sends:
// curl with a body or an upload, scp or rsync to a remote, a mail program. The
// same words inside a quoted commit message, a here-document, an option of
// another command (unzip -t, stat -f), the scheme of a URL ("https://" is not
// the httpie program) or a curl -G query (--data-urlencode with -G is a GET)
// are not sends.

const maxScopeShellDepth = 4

var (
	scopeShellURLRe     = lazyregexp.New(`(?i)^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)`)
	scopeRemoteOperand  = lazyregexp.New(`^(?:[^@\s/:]+@)?(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9][A-Za-z0-9._-]*):`)
	scopeShellEmailWord = lazyregexp.New(`(?i)[a-z0-9._%+-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}`)
)

// curl short options that take a value; the value is the next word unless the
// option is clustered with it.
const curlShortValue = "AbcCdDeEFHKmoPQrtTuUwxXyYz"

var curlLongValue = map[string]bool{
	"header": true, "output": true, "user": true, "user-agent": true, "proxy": true, "proxy-user": true,
	"cookie": true, "cookie-jar": true, "referer": true, "max-time": true, "connect-timeout": true, "retry": true,
	"retry-delay": true, "retry-max-time": true, "write-out": true, "cert": true, "key": true, "cacert": true,
	"capath": true, "resolve": true, "config": true, "range": true, "limit-rate": true, "interface": true,
	"dns-servers": true, "proto": true, "proto-default": true, "time-cond": true, "continue-at": true,
	"oauth2-bearer": true, "aws-sigv4": true, "cert-type": true, "key-type": true, "ciphers": true,
	"connect-to": true, "local-port": true, "max-filesize": true, "max-redirs": true, "netrc-file": true,
	"output-dir": true, "pinnedpubkey": true, "request-target": true, "speed-limit": true, "speed-time": true,
	"unix-socket": true, "variable": true, "expect100-timeout": true, "etag-save": true, "etag-compare": true,
	"hsts": true, "alt-svc": true, "trace": true, "trace-ascii": true, "stderr": true, "dump-header": true,
}

// shellSendReader reads one shell command into the places it sends to.
type shellSendReader struct {
	trunc *bounded.Truncated
	add   func(scopeDest)
	calls func() bool
	sends bool
	// whole is the text the reading started from: a mail program that takes its
	// recipients from headers (sendmail -t) is read from it.
	whole string
}

// shellSendDestinations reports whether the shell command sends data, and adds
// the places it sends to. A command the shell parser cannot read, or that is past
// its reading bounds, is read as text (the pattern below), as before.
func shellSendDestinations(command string, trunc *bounded.Truncated, add func(scopeDest)) bool {
	r := &shellSendReader{trunc: trunc, add: add, whole: command}
	counter := bounded.NewCounter(trunc, bounded.Nodes, maxScopeValues)
	r.calls = counter.Take
	r.read(command, 0)
	return r.sends
}

func (r *shellSendReader) read(command string, depth int) {
	if !r.trunc.Within(bounded.Depth, depth, maxScopeShellDepth) {
		return
	}
	if shellparse.PastReadingBounds(command) {
		r.readAsText(command)
		return
	}
	file, ok := shellparse.Parse(command)
	if !ok || file == nil {
		r.readAsText(command)
		return
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		stmt, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		if !r.calls() {
			return false
		}
		argv := make([]string, 0, len(call.Args))
		for _, w := range call.Args {
			argv = append(argv, scopeWordText(w))
		}
		var here strings.Builder
		for _, redir := range stmt.Redirs {
			if redir.Hdoc != nil {
				here.WriteString(scopeWordText(redir.Hdoc))
				here.WriteByte('\n')
			} else if redir.Word != nil && (redir.Op == syntax.WordHdoc) {
				here.WriteString(scopeWordText(redir.Word))
				here.WriteByte('\n')
			}
		}
		r.readCall(scopeUnwrapCommand(argv), here.String(), depth)
		return true
	})
}

// readAsText reads a command the parser did not: the pattern for a send, and the
// addresses and URLs in the text.
func (r *shellSendReader) readAsText(command string) {
	if !scopeShellSendRe.MatchString(command) {
		return
	}
	r.sends = true
	mail := scopeMailProgramRe.MatchString(command)
	for _, m := range scopeURLHostRe.FindAllStringSubmatch(command, maxScopeDestinations+1) {
		r.add(scopeDest{host: strings.ToLower(m[1])})
	}
	for _, m := range scopeEmailRe.FindAllStringSubmatch(command, maxScopeDestinations+1) {
		if mail {
			r.add(scopeDest{mailbox: strings.ToLower(m[0])})
		} else {
			r.add(scopeDest{host: strings.ToLower(m[1])})
		}
	}
}

// scopeWordText is the text of a shell word: literals and quoted text as
// written; an expansion (a variable, a command substitution) as a NUL byte, so a
// host built by the shell is seen as unknown, never as a different host.
func scopeWordText(w *syntax.Word) string {
	var b strings.Builder
	var part func(p syntax.WordPart)
	part = func(p syntax.WordPart) {
		switch t := p.(type) {
		case *syntax.Lit:
			b.WriteString(strings.ReplaceAll(t.Value, "\\\n", ""))
		case *syntax.SglQuoted:
			b.WriteString(t.Value)
		case *syntax.DblQuoted:
			for _, q := range t.Parts {
				part(q)
			}
		default:
			b.WriteByte(0)
		}
	}
	for _, p := range w.Parts {
		part(p)
	}
	return b.String()
}

// scopeUnwrapCommand drops wrappers (sudo, env, nohup, time, timeout, nice...)
// from the front of a command.
func scopeUnwrapCommand(argv []string) []string {
	for len(argv) > 0 {
		switch scopeProgram(argv[0]) {
		case "sudo", "doas":
			i := 1
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				switch argv[i] {
				case "-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T":
					i++
				}
				i++
			}
			argv = argv[min(i, len(argv)):]
		case "env":
			i := 1
			for i < len(argv) && (strings.HasPrefix(argv[i], "-") || strings.Contains(argv[i], "=")) {
				if argv[i] == "-u" || argv[i] == "-C" || argv[i] == "-S" {
					i++
				}
				i++
			}
			argv = argv[min(i, len(argv)):]
		case "nohup", "time", "command", "exec", "builtin", "nice", "ionice", "stdbuf", "setsid", "unbuffer", "timeout":
			i := 1
			for i < len(argv) && (strings.HasPrefix(argv[i], "-") || scopeNumericWord(argv[i])) {
				i++
			}
			argv = argv[min(i, len(argv)):]
		default:
			return argv
		}
	}
	return argv
}

func scopeNumericWord(s string) bool {
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
	if loc[3] < len(word) && word[loc[3]] == 0 {
		return "", false
	}
	return strings.ToLower(word[loc[2]:loc[3]]), true
}

func (r *shellSendReader) readCall(argv []string, here string, depth int) {
	if len(argv) == 0 {
		return
	}
	switch prog := scopeProgram(argv[0]); prog {
	case "bash", "sh", "zsh", "dash", "ksh", "fish":
		for i := 1; i < len(argv)-1; i++ {
			if a := argv[i]; strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
				r.read(argv[i+1], depth+1)
				return
			}
		}
	case "eval":
		r.read(strings.Join(argv[1:], " "), depth+1)
	case "curl":
		r.readCurl(argv[1:])
	case "wget":
		r.readWget(argv[1:])
	case "http", "https", "xh", "xhs":
		r.readHTTPie(argv[1:])
	case "scp", "rsync", "sftp":
		r.readRemoteCopy(prog, argv[1:])
	case "nc", "ncat", "netcat":
		r.readNetcat(argv[1:])
	case "mail", "mailx", "sendmail", "swaks", "msmtp", "mutt":
		r.readMail(argv[1:], here)
	case "aws":
		if len(argv) > 3 && argv[1] == "s3" && (argv[2] == "cp" || argv[2] == "sync" || argv[2] == "mv") {
			r.readObjectCopy(argv[3:], "s3://")
		}
	case "gsutil":
		for i := 1; i < len(argv); i++ {
			if argv[i] == "cp" || argv[i] == "rsync" || argv[i] == "mv" {
				r.readObjectCopy(argv[i+1:], "gs://")
				break
			}
		}
	case "az":
		if len(argv) > 3 && argv[1] == "storage" && argv[2] == "blob" && argv[3] == "upload" {
			r.sends = true
			for _, a := range argv[4:] {
				if host, ok := scopeURLOperand(a); ok {
					r.add(scopeDest{host: host})
				}
			}
		}
	}
}

func (r *shellSendReader) readCurl(args []string) {
	var data, form, get bool
	var method string
	var urls []string
	operands := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case operands:
			urls = append(urls, a)
		case a == "--":
			operands = true
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			value := func() string {
				if hasVal {
					return val
				}
				if i+1 < len(args) {
					i++
					return args[i]
				}
				return ""
			}
			switch name {
			case "data", "data-raw", "data-binary", "data-ascii", "data-urlencode":
				data = true
				value()
			case "form", "form-string", "upload-file", "json":
				form = true
				value()
			case "get":
				get = true
			case "request":
				method = strings.ToUpper(value())
			case "url":
				urls = append(urls, value())
			default:
				if curlLongValue[name] {
					value()
				}
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for k := 1; k < len(a); k++ {
				c := a[k]
				if c == 'G' {
					get = true
					continue
				}
				if strings.IndexByte(curlShortValue, c) < 0 {
					continue
				}
				val := a[k+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				switch c {
				case 'd':
					data = true
				case 'F', 'T':
					form = true
				case 'X':
					method = strings.ToUpper(val)
				}
				break
			}
		default:
			urls = append(urls, a)
		}
	}
	send := form || (data && !get) || method == "POST" || method == "PUT" || method == "PATCH"
	if !send {
		return
	}
	r.sends = true
	for _, u := range urls {
		if host, ok := scopeURLOperand(u); ok {
			r.add(scopeDest{host: host})
		}
	}
}

func (r *shellSendReader) readWget(args []string) {
	send := false
	for i, a := range args {
		name, val, hasVal := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if !strings.HasPrefix(a, "--") {
			continue
		}
		switch name {
		case "post-data", "post-file", "body-data", "body-file":
			send = true
		case "method":
			if !hasVal && i+1 < len(args) {
				val = args[i+1]
			}
			switch strings.ToUpper(val) {
			case "POST", "PUT", "PATCH":
				send = true
			}
		}
	}
	if !send {
		return
	}
	r.sends = true
	for _, a := range args {
		if host, ok := scopeURLOperand(a); ok {
			r.add(scopeDest{host: host})
		}
	}
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

func (r *shellSendReader) readNetcat(args []string) {
	valueFlags := "psWwiqxXPIOT"
	var operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.ContainsAny(a, "lz") && !strings.HasPrefix(a, "--") {
				return
			}
			if last := a[len(a)-1]; !strings.HasPrefix(a, "--") && strings.IndexByte(valueFlags, last) >= 0 {
				i++
			}
		default:
			operands = append(operands, a)
		}
	}
	if len(operands) == 0 {
		return
	}
	r.sends = true
	if host := operands[0]; !strings.Contains(host, "\x00") && (scopeDomainRe.MatchString(host) || scopeIPv4Word(host)) {
		r.add(scopeDest{host: strings.ToLower(host)})
	}
}

func scopeIPv4Word(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || !scopeNumericWord(p) {
			return false
		}
	}
	return true
}

func (r *shellSendReader) readMail(args []string, here string) {
	r.sends = true
	skip := map[string]bool{"-s": true, "-S": true, "-r": true, "-f": true, "-a": true, "--from": true, "--header": true, "--attach": true, "-F": true, "--subject": true}
	found := false
	add := func(text string) {
		for _, m := range scopeShellEmailWord.FindAllString(text, maxScopeDestinations+1) {
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
		// recipients come from headers (sendmail -t): read them from the command text
		add(r.whole)
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

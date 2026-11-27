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
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// Bounds of userDownloadRequests.
const (
	// userRequestPrompts is the number of prompts weighed: this turn's and
	// the two before it, so "download X and run it" then "yes, go ahead"
	// counts.
	userRequestPrompts     = 3
	maxUserRequestHosts    = 16
	maxUserRequestSessions = 256
	maxUserRequestScan     = 64 << 10
	userRequestTTL         = 30 * time.Minute
	// maxUserRequestCommands and maxUserRequestCommandBytes bound the
	// download commands userRequestFileOperandsMasked parses in one prompt.
	maxUserRequestCommands     = 8
	maxUserRequestCommandBytes = 4 << 10
)

// userDownloadRequests remembers, per connector session, the hosts that the
// user's recent prompts ask to download from and run (#1390). It is what
// lets chain.download_then_execute_same_artifact stay quiet on a download the
// user asked for. It keeps host names only, never prompt text, in memory,
// bounded by session count, prompt count and age, and it does not need the
// LLM judge. The hosts are untrusted text: they may only lower that
// detection-only finding, never allow a call.
type userDownloadRequests struct {
	mu       sync.Mutex
	sessions map[string]userDownloadRequestSession
}

type userDownloadRequestSession struct {
	// prompts holds the requested hosts of each recent prompt, newest
	// last. A prompt that asks for nothing still takes a slot.
	prompts  [][]string
	lastSeen time.Time
}

// observeUserDownloadRequest records the hosts the user's prompt asks to
// download from and run, for the session in ctx. Call it on the connector's
// turn-start prompt only: other prompt-shaped events can carry text the
// user did not type.
func (a *APIServer) observeUserDownloadRequest(ctx context.Context, prompt string) {
	if a == nil {
		return
	}
	a.userDownloads.observe(sandboxSessionStateKey(ctx, SessionIDFromContext(ctx)), prompt, time.Now())
}

// resetUserDownloadRequests forgets a session at a lifecycle boundary.
func (a *APIServer) resetUserDownloadRequests(sessionKey string) {
	if a == nil || strings.TrimSpace(sessionKey) == "" {
		return
	}
	a.userDownloads.mu.Lock()
	delete(a.userDownloads.sessions, sessionKey)
	a.userDownloads.mu.Unlock()
}

func (r *userDownloadRequests) observe(sessionKey, prompt string, now time.Time) {
	if sessionKey == "" || strings.TrimSpace(prompt) == "" {
		return
	}
	hosts := userRequestedRunHosts(prompt)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = make(map[string]userDownloadRequestSession)
	}
	session, ok := r.sessions[sessionKey]
	if !ok || now.Sub(session.lastSeen) >= userRequestTTL {
		session = userDownloadRequestSession{}
	}
	if !ok && len(r.sessions) >= maxUserRequestSessions {
		r.pruneLocked(now)
	}
	prompts := append(session.prompts, hosts)
	if len(prompts) > userRequestPrompts {
		prompts = append([][]string(nil), prompts[len(prompts)-userRequestPrompts:]...)
	}
	r.sessions[sessionKey] = userDownloadRequestSession{prompts: prompts, lastSeen: now}
}

// requested reports whether one of the session's recent prompts asked to
// download from host and run what it got.
func (r *userDownloadRequests) requested(sessionKey, host string, now time.Time) bool {
	host = normalizeRequestHost(host)
	if sessionKey == "" || host == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[sessionKey]
	if !ok || now.Sub(session.lastSeen) >= userRequestTTL {
		return false
	}
	for _, hosts := range session.prompts {
		for _, candidate := range hosts {
			if candidate == host {
				return true
			}
		}
	}
	return false
}

// pruneLocked drops expired sessions, then the oldest ones, until a new
// session fits.
func (r *userDownloadRequests) pruneLocked(now time.Time) {
	for key, session := range r.sessions {
		if now.Sub(session.lastSeen) >= userRequestTTL {
			delete(r.sessions, key)
		}
	}
	for len(r.sessions) >= maxUserRequestSessions {
		oldestKey, oldest := "", time.Time{}
		for key, session := range r.sessions {
			if oldestKey == "" || session.lastSeen.Before(oldest) {
				oldestKey, oldest = key, session.lastSeen
			}
		}
		delete(r.sessions, oldestKey)
	}
}

var userRequestRunWord = lazyregexp.New(`(?i)\b(run|runs|running|execute|executes|executing|exec|install|installs|installing|launch|launches|launching|invoke|invokes)\b`)

// userRequestRunsDownloader matches the text right after a run word whose
// object is the download command itself ("run exactly: curl -o page URL",
// "run exactly this command and nothing else: curl -o page URL"): that asks
// to download, not to run what was downloaded. Only a closed set of filler
// words may stand between the run word and curl or wget, so "run it: curl"
// still names what the download fetches as the thing to run. The second
// form is how a person asks Claude Code to run one command; before it was
// read as a request to run the download, and the unasked run of the file
// in the next turn did not alert (rel-1-0-6:GAP-0031, L-emac-J3-002). An
// aside in parentheses among those words ("run exactly this command and
// nothing else (it fetches a test page): curl ...") is skipped too; a run
// word inside it is weighed on its own (rel-1-0-6:GAP-0173, L-ewin-J3-002).
var userRequestRunsDownloader = lazyregexp.New(`^(?i)(?:[\s:"'\x60]+|\([^()]{0,240}\)|(?:exactly|just|only|please|the|this|following|command|commands|and|nothing|else|for|me)\b)*(?:curl|wget)\b`)

// userRequestAsksToRun reports a prompt with a run, execute or install word
// whose object is not the download command. A run word is read from the
// prompt's prose only, never from a path or URL: a whitespace-separated
// token that holds a path separator ("/var/tmp/run-x/page.txt",
// "C:\run\page.txt", "https://example.net/install/r") names a file or an
// address, and a component of it that is a run word asks nothing. Reading
// such a component as a request to run kept
// chain.download_then_execute_same_artifact quiet on an unasked run of the
// downloaded file whenever its path had a directory named run, run-x or
// install (rel-1-0-10:GAP-1884; the cause of GAP-0774).
func userRequestAsksToRun(prompt string) bool {
	if !userRequestRunWord.MatchString(prompt) {
		return false
	}
	for start := 0; start < len(prompt); {
		if userRequestSpace(prompt[start]) {
			start++
			continue
		}
		end := start
		for end < len(prompt) && !userRequestSpace(prompt[end]) {
			end++
		}
		if token := prompt[start:end]; !strings.ContainsAny(token, `/\`) {
			for _, match := range userRequestRunWord.FindAllStringIndex(token, -1) {
				if !userRequestRunsDownloader.MatchString(prompt[start+match[1]:]) {
					return true
				}
			}
		}
		start = end
	}
	return false
}

// userRequestSpace reports an ASCII white-space byte, the separator of the
// prompt tokens userRequestAsksToRun weighs.
func userRequestSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// userRequestedRunHosts returns the host names and IP addresses a prompt
// names when it also asks to run, execute or install something other than
// the download command (userRequestAsksToRun). A name is matched whole:
// "example.net" is not a part of "cdn.example.net". Neither the run words
// nor the hosts are read from a file operand of a download command the
// prompt quotes (userRequestFileOperandsMasked).
func userRequestedRunHosts(prompt string) []string {
	if len(prompt) > maxUserRequestScan {
		prompt = prompt[:maxUserRequestScan]
	}
	prompt = strings.ToLower(userRequestFileOperandsMasked(prompt))
	if !userRequestAsksToRun(prompt) {
		return nil
	}
	var hosts []string
	add := func(host string) {
		host = normalizeRequestHost(host)
		if host == "" || len(hosts) >= maxUserRequestHosts {
			return
		}
		for _, existing := range hosts {
			if existing == host {
				return
			}
		}
		hosts = append(hosts, host)
	}
	nameByte := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
	}
	addrByte := func(c byte) bool {
		return c >= 'a' && c <= 'f' || c >= '0' && c <= '9' || c == ':' || c == '.'
	}
	for start := 0; start < len(prompt); {
		if !nameByte(prompt[start]) && prompt[start] != ':' {
			start++
			continue
		}
		end := start
		for end < len(prompt) && nameByte(prompt[end]) {
			end++
		}
		if name := strings.Trim(prompt[start:end], ".-"); strings.Contains(name, ".") {
			add(name)
		}
		// An IPv6 address, bare or in brackets.
		addrEnd := start
		for addrEnd < len(prompt) && addrByte(prompt[addrEnd]) {
			addrEnd++
		}
		if candidate := prompt[start:addrEnd]; strings.Count(candidate, ":") >= 2 {
			if address, err := netip.ParseAddr(strings.TrimRight(candidate, ".")); err == nil && address.Is6() {
				add(address.String())
			}
		}
		if addrEnd > end {
			end = addrEnd
		}
		if end == start {
			end++
		}
		start = end
	}
	return hosts
}

// userRequestDownloadCommand finds the curl and wget commands a prompt
// quotes ("run exactly: curl -o page URL", "run `wget -O page URL`").
var userRequestDownloadCommand = lazyregexp.New(`(?i)\b(?:curl|wget)\b`)

// userRequestFileOperandsMasked returns the prompt with the file operands of
// each curl or wget command it quotes blanked out: the output file of -o,
// --output, -O (wget), --output-document, the cookie jar, the upload or
// config file. A file operand names where the command writes or what it
// reads, never a request to run or a host to trust: "run exactly: curl -o
// run URL" asks only for the download, and "-o /tmp/example.net/page" does
// not name example.net. Which words are file operands is read the way the
// guardrail reads the command when the agent runs it: the shell parse
// (shellparse) gives the command's words and their bytes, the program table
// (effects.Extract) gives each word's role. The command's URL operands and
// the prose after them ("curl -o page URL and then run ./page") are kept,
// as a shell word list cannot tell a positional from the prose that
// follows it. A command that does not parse, or has a word that is not
// static text, is left as it is, the reading of 1.0.10. Blanking can only
// take run words and hosts away, so chain.download_then_execute_same_artifact
// alerts more, never less, and it never blocks (rel-1-0-10:GAP-1895, the
// residual of GAP-1884).
func userRequestFileOperandsMasked(prompt string) string {
	var masked []byte
	for _, match := range userRequestDownloadCommand.FindAllStringIndex(prompt, maxUserRequestCommands) {
		start := match[0]
		end := len(prompt)
		if newline := strings.IndexByte(prompt[start:], '\n'); newline >= 0 {
			end = start + newline
		}
		// A command the prompt puts in quotes or backticks ends at the
		// closing one.
		if start > 0 && strings.IndexByte("`'\"", prompt[start-1]) >= 0 {
			if closing := strings.IndexByte(prompt[start:end], prompt[start-1]); closing >= 0 {
				end = start + closing
			}
		}
		if end-start > maxUserRequestCommandBytes {
			end = start + maxUserRequestCommandBytes
		}
		for _, span := range userRequestCommandFileOperands(prompt[start:end]) {
			if masked == nil {
				masked = []byte(prompt)
			}
			for index := start + span[0]; index < start+span[1]; index++ {
				masked[index] = ' '
			}
		}
	}
	if masked == nil {
		return prompt
	}
	return string(masked)
}

// userRequestCommandFileOperands returns the byte spans, in command, of the
// words of its first simple command that the program table reads as a
// file. curl and wget take a file only as an option's value, so such a
// word is the value after an option word (-o FILE) or the option word that
// carries it (--output=FILE, -oFILE); a positional with the same text is a
// URL or the prose after the command, and is kept.
func userRequestCommandFileOperands(command string) [][2]int {
	file, ok := shellparse.Parse(command)
	if !ok {
		// The prose after the command can hold what a shell does not parse
		// (an apostrophe, a parenthesis): the command is the words the
		// recovering parse reads, or the words before its first error.
		recovered, err := shellparse.ParseRecovering(command, 1, nil)
		var parseErr syntax.ParseError
		switch {
		case recovered != nil && len(recovered.Stmts) > 0:
			file = recovered
		case errors.As(err, &parseErr) && parseErr.Pos.Offset() > 0 && int(parseErr.Pos.Offset()) < len(command):
			if file, ok = shellparse.Parse(command[:parseErr.Pos.Offset()]); !ok {
				return nil
			}
		default:
			return nil
		}
	}
	if file == nil || len(file.Stmts) == 0 {
		return nil
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 || len(call.Assigns) != 0 {
		return nil
	}
	argv := make([]string, len(call.Args))
	for index, word := range call.Args {
		text, static := staticWordText(word)
		if !static {
			return nil
		}
		argv[index] = text
	}
	argv[0] = strings.ToLower(argv[0])
	if argv[0] != "curl" && argv[0] != "wget" {
		return nil
	}
	result := effects.Extract(effects.Call{Surface: effects.SurfaceArgv, Argv: argv},
		effects.Options{Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX, CWD: "/"})
	files := make(map[string]bool)
	for _, effect := range result.Effects {
		if effect.Target.Type == effects.TargetPath && effect.Target.Spelling != "" {
			files[effect.Target.Spelling] = true
		}
	}
	var spans [][2]int
	for index := 1; index < len(argv); index++ {
		word := argv[index]
		carries := strings.HasPrefix(word, "-") && func() bool {
			for spelling := range files {
				if len(word) > len(spelling) && strings.HasSuffix(word, spelling) {
					return true
				}
			}
			return false
		}()
		if files[word] && strings.HasPrefix(argv[index-1], "-") || carries {
			spans = append(spans, [2]int{int(call.Args[index].Pos().Offset()), int(call.Args[index].End().Offset())})
		}
	}
	return spans
}

// normalizeRequestHost lowercases a host, drops IPv6 brackets and a final
// dot, and writes an IP address in its canonical form.
func normalizeRequestHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String()
	}
	return host
}

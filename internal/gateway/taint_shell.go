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
	"regexp"
	"strings"
)

// ShellOps describes file I/O, deletions, upload payloads, and network
// destinations extracted from a tool call's arguments. It is the structured
// output of ParseExec and feeds the TaintTracker's file-level propagation
// logic and the OPA taint-context overlay.
//
// The parser is best-effort. Commands using pipes ("|"), eval, command
// substitution, or heredocs are flagged via Suspicious=true so the caller
// can fall back to session-level (weak) taint instead of trusting the
// extracted file references.
type ShellOps struct {
	// Reads are file paths the command reads (cat, head, tail, less, more,
	// or the source side of cp/mv/cat-redirect).
	Reads []string
	// Writes are file paths the command writes (the destination of
	// cp/mv/cat-redirect, or `tee DST`, or `> DST` redirects).
	Writes []string
	// WriteSources maps each destination in Writes to the list of source
	// paths that flowed into it. Used by the taint tracker to propagate
	// file taint through copies.
	WriteSources map[string][]string
	// UploadSources are file paths referenced as upload payloads in
	// network-bound consumers (curl --upload-file, curl --data @file,
	// curl -F field=@file, wget --post-file).
	UploadSources []string
	// Deletes are file paths destroyed by rm/rm -rf, dd of=, shred,
	// truncate, mv FILE /dev/null, or stand-alone `> FILE` truncate
	// redirects with no source.
	Deletes []string
	// NetworkDest is the first http(s) URL referenced by a network
	// consumer (curl, wget). Empty when the consumer is not network-bound
	// or no URL was extractable.
	NetworkDest string
	// Suspicious is true when the command contains constructs the parser
	// cannot reliably analyze (pipes, eval, $(...), backticks, heredocs).
	// Callers should treat extracted paths cautiously and prefer
	// session-level taint signals.
	Suspicious bool
}

// shellLikeTool returns true for tool names whose arguments commonly
// contain raw shell. The match is a permissive substring set rather than
// an exact list because providers vary (run_command, terminal, exec,
// shell_exec, bash, sh, ...). The cost of false-positive parsing is just
// a few unmatched regexes against non-shell args, which is cheap.
func shellLikeTool(name string) bool {
	if name == "" {
		return false
	}
	n := strings.ToLower(name)
	for _, needle := range []string{"exec", "shell", "bash", "command", "terminal", "run_", "openshell"} {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

// Pre-compiled regexes used by ParseExec. All are case-insensitive where
// shell flag/keyword casing tolerance is useful.
var (
	// cat SRC > DST  /  cat SRC >> DST  (writes flow from SRC to DST)
	taintReCatRedirect = regexp.MustCompile(`(?i)\bcat\s+([^\s|;&<>]+)\s*>>?\s*([^\s|;&<>]+)`)

	// >> DST  /  > DST  with NO leading source command (truncate/clobber).
	// Anchored on whitespace/semicolon/start so it doesn't match the cat
	// case above. We extract these as writes-with-no-source which the
	// caller can interpret as deletes when the redirect uses `>` alone.
	taintReBareRedirect = regexp.MustCompile(`(?:^|[\s;]|&&|\|\|)>\s*([^\s|;&<>]+)`)

	// curl URL extraction (best-effort, first https?:// per command).
	taintReURL = regexp.MustCompile(`(?i)https?://[^\s'"<>|;&]+`)

	// Upload payload references for curl/wget.
	taintReCurlUpload   = regexp.MustCompile(`(?i)\bcurl\b[^\n;|]*?(?:--upload-file|-T)\s+([^\s|;&"']+)`)
	taintReCurlDataAt   = regexp.MustCompile(`(?i)\bcurl\b[^\n;|]*?--data(?:-binary|-raw|-urlencode)?\s+@([^\s|;&"']+)`)
	taintReCurlForm     = regexp.MustCompile(`(?i)\bcurl\b[^\n;|]*?-F\s+\S*?=[<@]([^\s|;&"']+)`)
	taintReWgetPostFile = regexp.MustCompile(`(?i)\bwget\b[^\n;|]*?--post-file=([^\s|;&"']+)`)

	// dd if=... of=DST  (we capture only the destination — taint sink).
	taintReDdOf = regexp.MustCompile(`(?i)\bdd\b[^\n;|]*?\bof=([^\s|;&"']+)`)

	// Best-effort Python file-open extraction for `python -c '...open("/path") ...'`.
	taintRePythonOpen = regexp.MustCompile(`(?i)\bopen\s*\(\s*['"]([^'"]+)['"]`)

	// Suspicious constructs that defeat reliable parsing.
	taintReSuspicious = regexp.MustCompile("(?:\\beval\\b|\\$\\(|`|<<-?\\s*['\"]?[A-Za-z_])")
)

// ParseExec extracts file I/O and network destinations from tool arguments.
//
// argsRaw is the raw JSON-encoded arguments object as passed to the tool
// (e.g. `{"command": "cat /etc/passwd > /tmp/x"}`). The parser first tries
// to decode argsRaw as JSON and extract common command-bearing keys
// (command, cmd, script, code, input, args). If decoding fails we fall
// back to treating argsRaw as raw shell text. This lets us handle both
// JSON-wrapped tool calls and pre-extracted command strings without
// hardcoding a single arg shape.
//
// For non-shell-like tools, ParseExec returns an empty ShellOps.
func ParseExec(toolName, argsRaw string) ShellOps {
	if !shellLikeTool(toolName) || argsRaw == "" {
		return ShellOps{}
	}
	cmd := extractCommandText(argsRaw)
	if cmd == "" {
		// Couldn't extract a usable command string. Fall back to raw
		// args so regex-based extraction can still pick up patterns
		// from non-conforming arg shapes.
		cmd = argsRaw
	}

	ops := ShellOps{WriteSources: make(map[string][]string)}
	if taintReSuspicious.MatchString(cmd) || strings.Contains(cmd, "|") {
		// "|" in the command is a shell pipe (or eval/sub). Either way
		// we can't trust file-flow extraction across the pipe, so we
		// still extract what we can but tell the caller the result is
		// best-effort.
		ops.Suspicious = true
	}

	// 1. cat SRC > DST  (or >>) — strong propagation signal.
	for _, m := range taintReCatRedirect.FindAllStringSubmatch(cmd, -1) {
		src := unquote(m[1])
		dst := unquote(m[2])
		ops.Reads = appendUnique(ops.Reads, src)
		ops.Writes = appendUnique(ops.Writes, dst)
		ops.WriteSources[dst] = appendUnique(ops.WriteSources[dst], src)
	}

	// 2. Bare `> DST` or `>> DST` redirects (no leading `cat ...`). We
	// already grabbed the cat case above; this handles standalone
	// truncate-style redirects. We surface them as Deletes when the
	// caller infers no source, otherwise as Writes with empty source.
	for _, m := range taintReBareRedirect.FindAllStringSubmatch(cmd, -1) {
		dst := unquote(m[1])
		if dst == "" {
			continue
		}
		// Skip if this destination was already paired with a source above
		// (the cat-redirect regex already accounted for it).
		if _, hasSource := ops.WriteSources[dst]; hasSource {
			continue
		}
		// `> FILE` without a source is effectively a truncate-to-empty;
		// the file's prior contents are destroyed. We log it as both a
		// Write (no source) and a Delete so consumer logic can react.
		ops.Writes = appendUnique(ops.Writes, dst)
		ops.Deletes = appendUnique(ops.Deletes, dst)
	}

	// 3. Token-driven parsing for cp/mv/tee/head/tail/less/more/rm/shred/truncate.
	// Regex-only would mishandle flag positions (e.g. `cp -rT a b`); a tiny
	// tokenizer keeps the rules readable.
	parseTokenCommands(cmd, &ops)

	// 4. Upload payloads (curl/wget).
	for _, m := range taintReCurlUpload.FindAllStringSubmatch(cmd, -1) {
		ops.UploadSources = appendUnique(ops.UploadSources, unquote(m[1]))
	}
	for _, m := range taintReCurlDataAt.FindAllStringSubmatch(cmd, -1) {
		ops.UploadSources = appendUnique(ops.UploadSources, unquote(m[1]))
	}
	for _, m := range taintReCurlForm.FindAllStringSubmatch(cmd, -1) {
		ops.UploadSources = appendUnique(ops.UploadSources, unquote(m[1]))
	}
	for _, m := range taintReWgetPostFile.FindAllStringSubmatch(cmd, -1) {
		ops.UploadSources = appendUnique(ops.UploadSources, unquote(m[1]))
	}

	// 5. dd if=... of=DST captures only the destructive sink, since the
	// `if=` source is typically /dev/zero or /dev/random, not a real file
	// we'd want to taint-track. (`if=` from a sensitive file is rare and
	// already caught by the path rules.)
	for _, m := range taintReDdOf.FindAllStringSubmatch(cmd, -1) {
		dst := unquote(m[1])
		ops.Writes = appendUnique(ops.Writes, dst)
		ops.Deletes = appendUnique(ops.Deletes, dst)
	}

	// 6. Best-effort python file open. Treated as a Read.
	for _, m := range taintRePythonOpen.FindAllStringSubmatch(cmd, -1) {
		ops.Reads = appendUnique(ops.Reads, unquote(m[1]))
	}

	// 7. First URL referenced by a network consumer.
	if loc := taintReURL.FindStringIndex(cmd); loc != nil {
		ops.NetworkDest = cmd[loc[0]:loc[1]]
	}

	return ops
}

// extractCommandText pulls a usable shell command string out of a tool's
// raw JSON args. Handles common provider shapes:
//
//   - {"command": "<shell>"}     - OpenAI, Anthropic, generic exec tools
//   - {"cmd": "<shell>"}         - alternate spelling
//   - {"script": "<shell>"}      - some script-runner tools
//   - {"code": "<shell>"}        - code interpreter tools
//   - {"input": "<shell>"}       - some open-source agent frameworks
//   - {"args": ["arg1", "arg2"]} - argv-style array; joined with spaces
//   - {"command": ["arg1", ...]} - argv-style under "command"
//
// Returns the empty string if the input is not valid JSON or contains
// none of the recognized keys; callers should fall back to argsRaw.
func extractCommandText(argsRaw string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(argsRaw), &obj); err != nil {
		return ""
	}
	keys := []string{"command", "cmd", "script", "code", "input", "args"}
	var parts []string
	for _, k := range keys {
		raw, ok := obj[k]
		if !ok {
			continue
		}
		// Try string first.
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			parts = append(parts, s)
			continue
		}
		// Try []string (argv-style).
		var arr []string
		if err := json.Unmarshal(raw, &arr); err == nil {
			parts = append(parts, strings.Join(arr, " "))
			continue
		}
		// Try []interface{} for mixed-type arrays — coerce each
		// element via fmt-style conversion. We accept whatever the
		// stringification produces; the parser is tolerant.
		var anyArr []interface{}
		if err := json.Unmarshal(raw, &anyArr); err == nil {
			var elems []string
			for _, v := range anyArr {
				if s, ok := v.(string); ok {
					elems = append(elems, s)
				}
			}
			if len(elems) > 0 {
				parts = append(parts, strings.Join(elems, " "))
			}
		}
	}
	return strings.Join(parts, " ")
}

// parseTokenCommands walks the args looking for cp/mv/tee/head/tail/less/
// more/rm/shred/truncate invocations and updates ops accordingly. It uses
// a quote-aware tokenizer keyed on common shell separators so flag
// positioning ("cp -r SRC DST", "rm -rf -- FILE") works without
// command-specific regex.
func parseTokenCommands(argsRaw string, ops *ShellOps) {
	tokens := tokenizeShell(argsRaw)
	for i := 0; i < len(tokens); i++ {
		t := strings.ToLower(strings.Trim(tokens[i], "\"'"))
		switch t {
		case "cp", "mv":
			src, dst, advance := nextTwoOperands(tokens, i+1)
			if src != "" && dst != "" {
				ops.Reads = appendUnique(ops.Reads, src)
				if t == "mv" && dst == "/dev/null" {
					ops.Deletes = appendUnique(ops.Deletes, src)
				} else {
					ops.Writes = appendUnique(ops.Writes, dst)
					ops.WriteSources[dst] = appendUnique(ops.WriteSources[dst], src)
				}
			}
			if advance > 0 {
				i += advance
			}
		case "tee":
			// `tee DST` (with optional flags). Stdin source is typically a
			// pipe so we mark Suspicious=true elsewhere; here we just
			// record the destination as a write with no source.
			if dst, advance := nextOperand(tokens, i+1); dst != "" {
				ops.Writes = appendUnique(ops.Writes, dst)
				if advance > 0 {
					i += advance
				}
			}
		case "head", "tail", "less", "more":
			if src, advance := nextOperand(tokens, i+1); src != "" {
				ops.Reads = appendUnique(ops.Reads, src)
				if advance > 0 {
					i += advance
				}
			}
		case "cat":
			// Plain `cat SRC` (without redirect, which was handled above).
			// We add ALL operand tokens as reads since cat can stream
			// multiple files.
			advance := 0
			for j := i + 1; j < len(tokens); j++ {
				next := tokens[j]
				if isShellSeparator(next) || isShellRedirect(next) {
					break
				}
				if isFlag(next) || isLikelyNumeric(next) {
					advance++
					continue
				}
				ops.Reads = appendUnique(ops.Reads, unquote(next))
				advance++
			}
			i += advance
		case "rm":
			// rm/rm -rf/rm -f — every non-flag operand is a delete target.
			// Once `--` is seen, all subsequent tokens are literal file
			// names even if they start with a dash (POSIX end-of-options).
			advance := 0
			afterDoubleDash := false
			for j := i + 1; j < len(tokens); j++ {
				next := tokens[j]
				if isShellSeparator(next) {
					break
				}
				if !afterDoubleDash && next == "--" {
					afterDoubleDash = true
					advance++
					continue
				}
				if !afterDoubleDash && isFlag(next) {
					advance++
					continue
				}
				ops.Deletes = appendUnique(ops.Deletes, unquote(next))
				advance++
			}
			i += advance
		case "shred":
			advance := 0
			for j := i + 1; j < len(tokens); j++ {
				next := tokens[j]
				if isShellSeparator(next) {
					break
				}
				if isFlag(next) || isLikelyNumeric(next) {
					advance++
					continue
				}
				ops.Deletes = appendUnique(ops.Deletes, unquote(next))
				advance++
			}
			i += advance
		case "truncate":
			// truncate -s SIZE FILE. We only escalate when SIZE is 0,
			// since truncate can also grow a file. The `-s 0` and
			// `--size=0` forms are checked explicitly; anything else
			// is treated as a write (not a destructive truncate).
			advance := 0
			zeroSize := false
			fileTarget := ""
			for j := i + 1; j < len(tokens); j++ {
				next := tokens[j]
				if isShellSeparator(next) {
					break
				}
				switch {
				case next == "-s" && j+1 < len(tokens) && (tokens[j+1] == "0" || tokens[j+1] == "+0"):
					zeroSize = true
					advance += 2
					j++
				case strings.HasPrefix(next, "--size=") && (next == "--size=0" || next == "--size=+0"):
					zeroSize = true
					advance++
				case isFlag(next):
					advance++
				case isLikelyNumeric(next):
					advance++
				default:
					if fileTarget == "" {
						fileTarget = unquote(next)
					}
					advance++
				}
			}
			if fileTarget != "" {
				if zeroSize {
					ops.Deletes = appendUnique(ops.Deletes, fileTarget)
				}
				ops.Writes = appendUnique(ops.Writes, fileTarget)
			}
			i += advance
		}
	}
}

// nextOperand returns the first non-flag, non-numeric, non-separator
// operand at or after position start, plus the number of tokens
// consumed (relative to start). Empty string if none found.
func nextOperand(tokens []string, start int) (string, int) {
	for j := start; j < len(tokens); j++ {
		t := tokens[j]
		if isShellSeparator(t) || isShellRedirect(t) {
			return "", j - start
		}
		if isFlag(t) || isLikelyNumeric(t) {
			continue
		}
		return unquote(t), j - start + 1
	}
	return "", 0
}

// nextTwoOperands returns the first two non-flag operands.
func nextTwoOperands(tokens []string, start int) (string, string, int) {
	first, n1 := nextOperand(tokens, start)
	if first == "" {
		return "", "", 0
	}
	second, n2 := nextOperand(tokens, start+n1)
	if second == "" {
		return "", "", n1
	}
	return first, second, n1 + n2
}

// isFlag returns true for tokens that look like a CLI flag (-x, --foo,
// --foo=bar). `-` alone (stdin marker) is not a flag for our purposes.
func isFlag(t string) bool {
	if len(t) < 2 {
		return false
	}
	return t[0] == '-' && t != "--"
}

// isLikelyNumeric returns true for plain numeric tokens. Used to skip
// `-n 5` style arg pairs.
func isLikelyNumeric(t string) bool {
	if t == "" {
		return false
	}
	for _, c := range t {
		if (c < '0' || c > '9') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// isShellSeparator returns true for tokens that end one command and start
// another (`;`, `&&`, `||`, newlines we already split on).
func isShellSeparator(t string) bool {
	switch t {
	case ";", "&&", "||", "&", "|":
		return true
	}
	return false
}

// isShellRedirect returns true for redirect operators.
func isShellRedirect(t string) bool {
	switch t {
	case ">", ">>", "<", "<<":
		return true
	}
	return false
}

// tokenizeShell splits a shell-ish string into tokens, respecting single
// and double quotes and emitting redirect/separator operators as their
// own tokens. Backslash escapes are not interpreted — sufficient for
// detection-grade parsing without requiring a full shell parser.
func tokenizeShell(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(c)
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && !inSingle && !inDouble:
			flush()
		case (c == '|' || c == ';' || c == '&' || c == '<' || c == '>') && !inSingle && !inDouble:
			flush()
			op := string(c)
			if i+1 < len(s) {
				n := s[i+1]
				if (c == '>' && n == '>') || (c == '<' && n == '<') ||
					(c == '&' && n == '&') || (c == '|' && n == '|') {
					op = string(c) + string(n)
					i++
				}
			}
			tokens = append(tokens, op)
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return tokens
}

// unquote strips a single pair of surrounding ASCII quotes if present.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if (first == '"' || first == '\'') && first == last {
		return s[1 : len(s)-1]
	}
	return s
}

// appendUnique appends item to slice if not already present and not empty.
func appendUnique(slice []string, item string) []string {
	if item == "" {
		return slice
	}
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

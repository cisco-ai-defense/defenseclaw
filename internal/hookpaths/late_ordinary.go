// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// LateOrdinaryCall reports a Claude Code or Codex shell or Read call that
// plainly names nothing a protected file could be reached through. The hook
// client asks it only when its verified gateway took the call and gave no
// answer by the deadline (GAP-0518): such a call may then follow the outage
// mode of the account (open with a visible warning in the default and
// permissive tiers, closed in strict and managed ones) instead of being
// denied for a gateway that is merely slow. Every other call stays closed.
//
// It is a cheap, linear and deliberately over-approximating text scan with
// one Lstat per path word, never a verdict. A call is not ordinary when any
// of these holds, and the answer is then the closed one it always was:
//   - it uses a shell feature the scan does not model (expansion, a glob, a
//     tilde, a backslash, a substitution, a subshell, a background job, a
//     here-document, an unmodelled redirect, a pipe into anything but a
//     plain filter, a shell, eval or interpreter code);
//   - a path word, or the working directory, names the SSH folder, an
//     authorized-keys file or a DefenseClaw, OpenClaw or ZeptoClaw folder
//     or file in any case (the text carries "ssh", "authorized",
//     "defenseclaw", "openclaw" or "zeptoclaw", or a hidden folder name
//     with "claw" or "defense" in it), is "..", or reaches the root or the
//     user's home itself; an ordinary word such as claw or defense is not
//     a name, because a protected file is a place and a place is told by
//     its folder, its link or its state-folder name, not by one word;
//   - a path word, or a folder in front of it, is a link, or the file is a
//     regular file with a second hard link: a link candidate. A program may
//     read a path out of any word (-ofile, of=file, --out=file, a:file), so
//     every part of a word that can start a value is looked at, not only
//     the word;
//   - the call has a key the scan does not know, so it may carry a path.
//
// A protected target spelled in a way the scan cannot see is a detection
// miss and belongs to the hook-path detection work (#1189).
func LateOrdinaryCall(connector string, payload []byte) bool {
	if runtime.GOOS == "windows" || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode", "codex":
	default:
		return false
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return false
	}
	toolRaw, _, toolConflict := firstAlias(envelope, []string{"tool_name", "toolName"})
	argsRaw, _, argsConflict := firstAlias(envelope,
		[]string{"tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments"})
	if toolConflict || argsConflict {
		return false
	}
	var tool, cwd string
	var args map[string]json.RawMessage
	if json.Unmarshal(toolRaw, &tool) != nil || json.Unmarshal(envelope["cwd"], &cwd) != nil ||
		json.Unmarshal(argsRaw, &args) != nil || !filepath.IsAbs(cwd) {
		return false
	}
	scan, ok := newLateScan(cwd)
	if !ok {
		return false
	}
	switch strings.TrimSpace(tool) {
	case "Read":
		if !lateKeysOnly(args, "file_path", "offset", "limit") {
			return false
		}
		var path string
		return json.Unmarshal(args["file_path"], &path) == nil && filepath.IsAbs(path) && scan.path(path)
	case "Bash", "exec_command", "shell":
		if !lateKeysOnly(args, "command", "cmd", "description", "timeout", "run_in_background",
			"workdir", "yield_time_ms", "max_output_tokens", "tty", "login", "justification") {
			return false
		}
		if raw, present := args["workdir"]; present {
			var workdir string
			if json.Unmarshal(raw, &workdir) != nil || workdir == "" || strings.HasPrefix(workdir, "~") {
				return false
			}
			if !filepath.IsAbs(workdir) {
				workdir = filepath.Join(cwd, workdir)
			}
			if scan, ok = newLateScan(workdir); !ok {
				return false
			}
		}
		command, ok := lateCommandText(args)
		return ok && scan.command(command)
	}
	return false
}

// lateKeysOnly reports a tool call whose argument keys are all among known.
func lateKeysOnly(args map[string]json.RawMessage, known ...string) bool {
	for key := range args {
		if !slices.Contains(known, key) {
			return false
		}
	}
	return true
}

// lateCommandText is the one shell text of a call: "command" (a string, or
// an argv joined by spaces) or "cmd", not both.
func lateCommandText(args map[string]json.RawMessage) (string, bool) {
	command, hasCommand := args["command"]
	cmd, hasCmd := args["cmd"]
	if hasCommand == hasCmd {
		return "", false
	}
	if hasCmd {
		command = cmd
	}
	var text string
	if json.Unmarshal(command, &text) == nil {
		return text, text != ""
	}
	var argv []string
	if json.Unmarshal(command, &argv) != nil || len(argv) == 0 {
		return "", false
	}
	// An argv is a list of words, not a shell text: each element is one
	// quoted word, so a space, a semicolon or a dash inside one stays in it.
	words := make([]string, len(argv))
	for i, arg := range argv {
		if strings.ContainsAny(arg, "\x27\"\\$`\n\r\x00") {
			return "", false
		}
		words[i] = "\x27" + arg + "\x27"
	}
	return strings.Join(words, " "), true
}

// lateScan is the state of one call's scan: the physical working directory
// and home, and the folders and files already looked at.
type lateScan struct {
	cwd, home string
	seen      map[string]bool
}

func newLateScan(cwd string) (*lateScan, bool) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil, false
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return nil, false
	}
	realCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil || lateNamesProtected(realCWD) || realCWD == string(filepath.Separator) {
		return nil, false
	}
	return &lateScan{cwd: realCWD, home: realHome, seen: map[string]bool{}}, true
}

// lateNamesProtected reports text that names, in any case, the SSH folder,
// an authorized-keys file, or a DefenseClaw, OpenClaw or ZeptoClaw folder or
// file, or a hidden folder (.name) with "claw" or "defense" in it. A word
// such as claw or defense on its own names nothing: the working directory
// and every link are checked as places.
func lateNamesProtected(text string) bool {
	lower := strings.ToLower(text)
	for _, name := range []string{"ssh", "authorized", "defenseclaw", "openclaw", "zeptoclaw"} {
		if strings.Contains(lower, name) {
			return true
		}
	}
	for _, part := range strings.Split(lower, "/") {
		if strings.HasPrefix(part, ".") && (strings.Contains(part, "claw") || strings.Contains(part, "defense")) {
			return true
		}
	}
	return false
}

// path reports a path word that is ordinary: no protected name, no ".."
// component, no link on the way or at its end (an existing regular file with
// a second hard link included), and not the root or the home itself or one
// of their parents. A name that does not exist yet is ordinary.
func (s *lateScan) path(word string) bool {
	if word == "" || strings.IndexByte(word, 0) >= 0 || strings.HasPrefix(word, "~") || lateNamesProtected(word) {
		return false
	}
	current := s.cwd
	if filepath.IsAbs(word) {
		current = string(filepath.Separator)
	}
	for _, name := range strings.Split(word, "/") {
		switch name {
		case "", ".":
			continue
		case "..":
			return false
		}
		current = filepath.Join(current, name)
		if state, known := s.seen[current]; known {
			if !state {
				return false
			}
			continue
		}
		ok, exists := s.entryOrdinary(current)
		s.seen[current] = ok
		if !ok {
			return false
		}
		if !exists {
			break
		}
	}
	return current != string(filepath.Separator) && current != s.home &&
		!strings.HasPrefix(s.home, current+string(filepath.Separator))
}

// entryOrdinary reports an entry that is not a link; exists is false for an
// entry that is not there, which ends the walk of a path.
func (s *lateScan) entryOrdinary(path string) (ordinary, exists bool) {
	info, err := pathLstat(path)
	if err != nil {
		return os.IsNotExist(err), false
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false, true
	}
	if info.Mode().IsRegular() && linkCount(path, info) > 1 {
		return false, true
	}
	return true, true
}

var (
	// lateSeparators end a simple command.
	lateSeparators = []string{";", "&&", "||"}
	// lateFilters are the programs a call may pipe into.
	lateFilters = []string{"tail", "head", "grep", "egrep", "wc", "sort", "uniq", "cut", "tr", "cat", "less", "jq"}
	// lateWrappers run another program or a shell text the scan cannot read.
	lateWrappers = []string{"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "eval", "exec", "source", ".",
		"env", "sudo", "su", "doas", "xargs", "nohup", "command", "builtin", "time", "watch", "timeout", "setsid",
		"ssh", "scp", "sftp", "nc", "ncat", "socat", "script", "screen", "tmux", "at", "crontab",
		"vi", "vim", "view", "nvim", "ex", "ed", "emacs", "nano"}
	// lateInterpreters run program text given on the command line.
	lateInterpreters = []string{"python", "python2", "python3", "node", "nodejs", "deno", "bun", "perl", "ruby", "php",
		"lua", "awk", "gawk", "tclsh", "Rscript"}
	lateCodeFlags = []string{"-c", "-e", "-E", "-p", "-r", "-x", "--eval", "--print", "--command"}
	// lateTextPrograms read and write no file: their words are text, so only
	// a redirect target is a path.
	lateTextPrograms = []string{"echo", "printf", "true", "false", "pwd", "whoami", "uname", "id", "sleep", "seq",
		"basename", "dirname", "expr"}
	// lateShortOptions lists, for programs whose options are known, the short
	// flags and the short options that take a value: in -la nothing is a
	// value, in -Ifile the file is. A cluster with any other letter, and a
	// program that is not listed, may take a value at any letter.
	lateShortOptions = map[string]lateOptions{
		"ls":    {"lLaAbBcCdDfFgGhHikmnNopqQrRsStuUvxXZ1", "ITw"},
		"cat":   {"AbeEnstTuv", ""},
		"wc":    {"clLmw", ""},
		"head":  {"qvz", "nc"},
		"tail":  {"fFqrvz", "ncs"},
		"sort":  {"bcCdfgGhiMmnRrsuVz", "okStT"},
		"uniq":  {"cdDiuz", "fsw"},
		"cut":   {"nsz", "bcdf"},
		"tr":    {"cdst", ""},
		"grep":  {"EFGPiyvwxcLlonqsHhbaIrRTUzZ", "efmABCdD"},
		"touch": {"acfhm", "drt"},
		"mkdir": {"pvZ", "m"},
		"rm":    {"fFiIrRdv", ""},
		"cp":    {"abdfHiLlnPpRrsTuvxZ", "St"},
		"mv":    {"bfinTuvxZ", "St"},
	}
)

// lateOptions are the short flags and the short options with a value of one program.
type lateOptions struct{ flags, values string }

// lateToken is one word of the command text, its quotes removed.
type lateToken struct {
	text     string
	operator bool
}

// lateTokens splits a command into words and the few operators the scan
// models. ok is false for any other shell syntax.
func lateTokens(command string) ([]lateToken, bool) {
	var tokens []lateToken
	var word strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			tokens = append(tokens, lateToken{text: word.String()})
			word.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case c == '\'' || c == '"':
			end := strings.IndexByte(command[i+1:], c)
			if end < 0 {
				return nil, false
			}
			quoted := command[i+1 : i+1+end]
			if strings.ContainsAny(quoted, "\\$`\n\r\x00") {
				return nil, false
			}
			word.WriteString(quoted)
			inWord = true
			i += end + 1
		case c == ' ' || c == '\t':
			flush()
		case strings.HasPrefix(command[i:], "2>&1") && (!inWord || word.Len() == 0):
			flush()
			i += len("2>&1") - 1
		case c == ';' || c == '&' || c == '|' || c == '<' || c == '>':
			flush()
			j := i
			for j < len(command) && strings.IndexByte(";&|<>", command[j]) >= 0 {
				j++
			}
			operator := command[i:j]
			if !slices.Contains([]string{";", "&&", "||", "|", ">", ">>", "<"}, operator) {
				return nil, false
			}
			tokens = append(tokens, lateToken{text: operator, operator: true})
			i = j - 1
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.,:+@%=/-", c) >= 0:
			word.WriteByte(c)
			inWord = true
		default:
			return nil, false
		}
	}
	flush()
	return tokens, len(tokens) > 0
}

// command reports a command text of plain statements.
func (s *lateScan) command(command string) bool {
	tokens, ok := lateTokens(command)
	if !ok {
		return false
	}
	atCommand, afterPipe, redirect := true, false, false
	var program string
	var sed lateSed
	for _, token := range tokens {
		if token.operator {
			switch {
			case slices.Contains(lateSeparators, token.text):
				atCommand, afterPipe = true, false
			case token.text == "|":
				atCommand, afterPipe = true, true
			default:
				redirect = true
			}
			continue
		}
		text := token.text
		switch {
		case redirect:
			redirect = false
			if !s.word("", text) {
				return false
			}
		case atCommand:
			if name, value, assigned := strings.Cut(text, "="); assigned && lateIdentifier(name) {
				if !s.word("", value) {
					return false
				}
				continue
			}
			base := filepath.Base(text)
			if slices.Contains(lateWrappers, base) || afterPipe && !slices.Contains(lateFilters, base) {
				return false
			}
			atCommand, afterPipe, program, sed = false, false, base, lateSed{}
			if !s.word("", text) {
				return false
			}
		case slices.Contains(lateInterpreters, program) && slices.Contains(lateCodeFlags, text):
			return false
		case slices.Contains(lateTextPrograms, program):
		case program == "sed":
			ordinary, isPath := sed.accept(text)
			if !ordinary || isPath && !s.word(program, text) {
				return false
			}
		default:
			if !s.word(program, text) {
				return false
			}
		}
	}
	return !atCommand && !redirect
}

// lateIdentifier reports a shell variable name.
func lateIdentifier(name string) bool {
	if name == "" || strings.IndexByte("0123456789", name[0]) >= 0 {
		return false
	}
	for i := range len(name) {
		if strings.IndexByte(lateLetters+"0123456789", name[i]) < 0 {
			return false
		}
	}
	return true
}

const lateLetters = "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// lateSed follows the words of one sed call. A sed script is a small
// program that can write a file (w), read one (r), or run a command (e), so
// the script is ordinary only in the two plain shapes lateSedScript knows;
// any other script, and a script file, is not.
type lateSed struct{ expectScript, haveScript bool }

// accept reports a sed word that is ordinary; isPath is true when the word
// is also a path or a path-bearing option to look at.
func (q *lateSed) accept(text string) (ordinary, isPath bool) {
	switch {
	case q.expectScript:
		q.expectScript, q.haveScript = false, true
		return lateSedScript(text), true
	case !strings.HasPrefix(text, "-") || text == "-":
		if q.haveScript {
			return true, true
		}
		q.haveScript = true
		return lateSedScript(text), true
	case text == "--expression":
		q.expectScript = true
		return true, false
	case strings.HasPrefix(text, "--expression="):
		q.haveScript = true
		return lateSedScript(strings.TrimPrefix(text, "--expression=")), true
	case strings.HasPrefix(text, "--"):
		return slices.Contains([]string{"--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered",
			"--null-data", "--posix", "--debug", "--sandbox", "--follow-symlinks", "--binary"}, text), false
	}
	for i := 1; i < len(text); i++ {
		switch {
		case strings.IndexByte("nEsuzr", text[i]) >= 0:
		case text[i:i+1] == "i":
			return true, true
		case text[i:i+1] == "e":
			if i+1 == len(text) {
				q.expectScript = true
				return true, false
			}
			q.haveScript = true
			return lateSedScript(text[i+1:]), true
		default:
			return false, false
		}
	}
	return true, false
}

// lateSedScript reports a script of one command that touches no file and
// runs nothing: [address]p, d, q, P, D, = or n, or [address]s/old/new/flags
// with the flags g, p, I, i, M or a number. An address is a line number, a
// range of two, or a /regexp/; ! may follow it. The delimiter of s is one of
// / | # and a comma, and old and new hold no further delimiter.
func lateSedScript(script string) bool {
	rest := script
	number := func() bool {
		n := len(rest) - len(strings.TrimLeft(rest, "0123456789"))
		rest = rest[n:]
		return n > 0
	}
	switch {
	case strings.HasPrefix(rest, "/"):
		end := strings.Index(rest[1:], "/")
		if end < 0 {
			return false
		}
		rest = rest[end+2:]
	case number():
		if strings.HasPrefix(rest, ",") {
			rest = rest[1:]
			if !number() {
				return false
			}
		}
	}
	rest = strings.TrimPrefix(rest, "!")
	if slices.Contains([]string{"p", "d", "q", "P", "D", "=", "n"}, rest) {
		return true
	}
	if len(rest) < 4 || !strings.HasPrefix(rest, "s") || strings.IndexByte("/|#,", rest[1]) < 0 {
		return false
	}
	parts := strings.Split(rest[2:], rest[1:2])
	if len(parts) != 3 {
		return false
	}
	return strings.Trim(parts[2], "gpIiM0123456789") == ""
}

// word checks every path an argument of program may name: see
// lateCandidates. A word of more than a few thousand bytes is not scanned.
func (s *lateScan) word(program, text string) bool {
	if len(text) > 4096 || lateNamesProtected(text) {
		return false
	}
	for _, candidate := range lateCandidates(program, text) {
		if !s.path(candidate) {
			return false
		}
	}
	return true
}

// lateCandidates are the paths a program may read out of one word: the word
// itself (an operand, a redirect target, a file named like an option), each
// space-separated part of it (a quoted word may hold several), the part
// after any "=", ":", ",", "@", "+" or "%" (--out=file, of=file, a:file),
// and for a short option the value attached to it (-ofile, -vofile,
// -f/path). A part that is a link, a hard link or ".." makes the call not
// ordinary; a part that is no file is ordinary.
func lateCandidates(program, text string) []string {
	parts := []string{text}
	if fields := strings.Fields(text); len(fields) != 1 || fields[0] != text {
		parts = append(parts, fields...)
	}
	var candidates []string
	for _, part := range parts {
		candidates = append(candidates, part)
		for i := 1; i < len(part); i++ {
			if strings.IndexByte("=:,@+%", part[i-1]) >= 0 {
				candidates = append(candidates, part[i:])
			}
		}
		candidates = append(candidates, lateAttached(program, part)...)
	}
	return candidates
}

// lateAttached are the values attached to a short option (-ofile). For a
// program in lateShortOptions it is what follows its first value-taking
// letter, and nothing for a cluster of its flags such as -la. For any other
// program or cluster every tail counts, because any letter might take one.
func lateAttached(program, part string) []string {
	if len(part) < 2 || !strings.HasPrefix(part, "-") || strings.HasPrefix(part, "--") {
		return nil
	}
	if known, listed := lateShortOptions[program]; listed {
		plain := true
		for i := 1; i < len(part) && plain; i++ {
			switch {
			case strings.IndexByte(known.values, part[i]) >= 0:
				if i+1 < len(part) {
					return []string{part[i+1:]}
				}
				return nil
			case strings.IndexByte(known.flags+"0123456789", part[i]) < 0:
				plain = false
			}
		}
		if plain {
			return nil
		}
	}
	var tails []string
	for i := 1; i < len(part); i++ {
		tails = append(tails, part[i:])
	}
	return tails
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"os/user"
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
//   - a path word, or a folder in front of it, is a link whose way to its
//     end is not ordinary (a missing target, a protected name in any link
//     text or place on the way, the root, the home or a parent of it), or
//     the place it ends at is a protected one by identity (an authorized-keys
//     file wherever it was moved to, a protected folder or anything below
//     it); or the file is a regular file with a second hard link that is the
//     same file as one in a protected folder (late_ordinary_reach.go). A
//     link or a hard link whose whole way and identity are ordinary is as
//     ordinary as its target, because a program that reads or writes through
//     it touches only that target. A program may
//     read a path out of any word (-ofile, of=file, --out=file, a:file), so
//     every part of a word that can start a value is looked at, not only
//     the word;
//   - the call has a key the scan does not know, so it may carry a path.
//
// A protected target spelled in a way the scan cannot see is a detection
// miss and belongs to the hook-path detection work (#1189).
func LateOrdinaryCall(connector string, payload []byte) bool {
	return LateOrdinaryCallAt("", connector, payload)
}

// LateOrdinaryCallAt is LateOrdinaryCall for an account whose home is given:
// every home-relative answer (the protected folders and authorized-keys files,
// the hard-link identities, the home itself) is told against home, not against
// the home of the process. A shell hook replaces HOME with a scratch folder
// before it runs the helper, so the helper of such a hook must be given the
// account home it saved, or a hard link to a protected file is not found
// (GAP-0850). An empty home is the home of the process.
func LateOrdinaryCallAt(home, connector string, payload []byte) bool {
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
	scan, ok := newLateScan(cwd, home)
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
			if scan, ok = newLateScan(JoinDirectoryText(cwd, workdir), home); !ok {
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

// lateScan is the state of one call's scan: the physical working directories
// a command may run in (the first is where the call starts; a cd adds the
// folder it enters, and the old one stays because a cd that fails leaves the
// shell where it was), the physical home, and the folders and files already
// looked at.
type lateScan struct {
	cwds   []string // where the next command may run
	chain  []string // every folder the shell may have stood in so far
	orSeen bool     // a "||" since the last ";": a later "&&" may run without the cd before it
	home   string
	// indexHomes: the homes whose protected files the scan indexes, the home
	// first. A given home that is no folder adds the other homes the call
	// can mean (lateFallbackHomes).
	indexHomes []string
	seen       map[string]lateEntry
	reach      lateReach // what is protected, found when a link or a hard link needs it
}

// lateEntry is what the scan found at one path: whether the entry is
// ordinary, whether it exists, and its physical path (a link is replaced by
// the place it leads to).
type lateEntry struct {
	ok, exists bool
	real       string
}

// lateMaxCwds bounds the working directories one call may visit.
const lateMaxCwds = 8

func newLateScan(cwd, home string) (*lateScan, bool) {
	given := home != ""
	if !given {
		var err error
		if home, err = os.UserHomeDir(); err != nil {
			return nil, false
		}
	}
	realCWD, err := pathEvalSymlinks(OSCleanedDirectory(cwd))
	if err != nil || lateNamesProtected(realCWD) || realCWD == string(filepath.Separator) {
		return nil, false
	}
	realHome, ok := lateUsableHome(home)
	indexHomes := []string{realHome}
	// A home that was given but is no folder (a relative path, a missing
	// path, a regular file) holds no protected file of its own. The protected
	// files the call can reach are then those of the homes it can mean: the
	// account database home (the scan tells that one) and the others
	// lateFallbackHomes lists. Their identities are indexed as for a usable
	// home, so a hard link to a protected file stays closed and a hard link
	// to an ordinary file stays ordinary.
	if !ok && given {
		current, err := user.Current()
		if err != nil {
			return nil, false
		}
		if realHome, ok = lateUsableHome(current.HomeDir); ok {
			indexHomes = lateFallbackHomes(home, realCWD, realHome)
		}
	}
	if !ok {
		return nil, false
	}
	return &lateScan{cwds: []string{realCWD}, chain: []string{realCWD}, home: realHome, indexHomes: indexHomes, seen: map[string]lateEntry{}}, true
}

// lateFallbackHomes lists the homes whose protected files an unusable given
// home leaves open, the account database home first: the home of the
// process, and the given home read against the folder the call runs in when
// it is a relative path (by file system rules, a link before a parent step
// included). Only folders are listed, each once.
func lateFallbackHomes(given, cwd, account string) []string {
	homes := []string{account}
	candidates := []string{}
	if env, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, env)
	}
	if !filepath.IsAbs(given) {
		candidates = append(candidates, JoinDirectoryText(cwd, given))
	}
	for _, candidate := range candidates {
		if real, ok := lateUsableHome(candidate); ok && !slices.Contains(homes, real) {
			homes = append(homes, real)
		}
	}
	return homes
}

// lateUsableHome resolves a home by file system rules (a parent step or a
// trailing slash included) and reports it only when it is an absolute path
// to a folder.
func lateUsableHome(home string) (string, bool) {
	if !filepath.IsAbs(home) {
		return "", false
	}
	real, err := pathEvalSymlinks(home)
	if err != nil {
		return "", false
	}
	if info, err := pathStat(real); err != nil || !info.IsDir() {
		return "", false
	}
	return real, true
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
func (s *lateScan) path(word string) bool { return s.check(word, true) }

// textWord checks a word a program takes as text (an echo word, a grep
// pattern, an ls ignore pattern): it is no path, so a plain word is not told
// by its name (echo openclaw), but a word that is a link, a hard link or
// ".." is still not ordinary, and a word with a slash is a path and is
// told by its name as well.
func (s *lateScan) textWord(word string) bool {
	return len(word) <= 4096 && s.check(word, strings.Contains(word, "/"))
}

// check walks word from every working directory the command may run in.
func (s *lateScan) check(word string, names bool) bool {
	if word == "" || strings.IndexByte(word, 0) >= 0 || strings.HasPrefix(word, "~") || names && lateNamesProtected(word) {
		return false
	}
	for _, cwd := range s.cwds {
		if !s.walk(cwd, word) {
			return false
		}
		if filepath.IsAbs(word) {
			break
		}
	}
	return true
}

// walk is the link, hard link, ".." and home walk of one word from cwd.
func (s *lateScan) walk(cwd, word string) bool {
	current := cwd
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
		entry := s.entry(filepath.Join(current, name))
		if !entry.ok {
			return false
		}
		current = entry.real
		if !entry.exists {
			break
		}
	}
	return s.placeReachable(current)
}

// placeReachable reports a physical path that is not the root, the home or a
// parent of the home.
func (s *lateScan) placeReachable(path string) bool {
	return path != string(filepath.Separator) && path != s.home && !strings.HasPrefix(s.home, path+string(filepath.Separator))
}

// placeOrdinary reports a physical path that is also free of protected names.
func (s *lateScan) placeOrdinary(path string) bool {
	return !lateNamesProtected(path) && s.placeReachable(path)
}

// entry looks at one path once. A missing entry is ordinary and ends a walk.
// A link is followed hop by hop (follow) and a link, or a regular file with a
// second hard link, is as ordinary as the place it reaches: not a missing
// target, a protected name on any hop, the root or the home, and not the
// identity of a protected file or folder (reachesProtected). An ordinary
// file with a second hard link stays ordinary.
func (s *lateScan) entry(path string) lateEntry {
	if known, seen := s.seen[path]; seen {
		return known
	}
	found := s.lookup(path)
	s.seen[path] = found
	return found
}

func (s *lateScan) lookup(path string) lateEntry {
	info, err := pathLstat(path)
	if err != nil {
		return lateEntry{ok: os.IsNotExist(err), real: path}
	}
	found := lateEntry{exists: true, real: path}
	if info.Mode()&os.ModeIrregular != 0 {
		return found
	}
	linked := info.Mode()&os.ModeSymlink != 0
	if linked {
		var ok bool
		if found.real, ok = s.follow(path); !ok {
			return found
		}
		if info, err = pathLstat(found.real); err != nil {
			return found
		}
	}
	hardLinked := info.Mode().IsRegular() && linkCount(found.real, info) > 1
	found.ok = (!linked && !hardLinked) || !s.reachesProtected(found.real, info)
	return found
}

// chdir moves the folders the next command may run in to the folders "cd dir"
// enters. Each must exist as a real folder (no link on the way, no hard link,
// no name of a protected folder, not the root, the home or a parent of it);
// ".." steps to the parent of a folder already known to be real. After "&&"
// only the new folders count, because the next command runs only when the
// cd worked; after ";" or "||" the old folders count too (lateSeparator).
func (s *lateScan) chdir(word string) bool {
	if word == "" || strings.IndexByte(word, 0) >= 0 || strings.HasPrefix(word, "-") || strings.HasPrefix(word, "~") ||
		lateNamesProtected(word) || len(word) > 4096 {
		return false
	}
	var entered []string
	for _, cwd := range s.cwds {
		current := cwd
		if filepath.IsAbs(word) {
			current = string(filepath.Separator)
		}
		for _, name := range strings.Split(word, "/") {
			switch name {
			case "", ".":
				continue
			case "..":
				current = filepath.Dir(current)
				continue
			}
			current = filepath.Join(current, name)
			if entry := s.entry(current); !entry.ok || !entry.exists || entry.real != current {
				return false
			}
		}
		info, err := pathLstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !s.placeOrdinary(current) {
			return false
		}
		if !slices.Contains(entered, current) {
			entered = append(entered, current)
		}
		if filepath.IsAbs(word) {
			break
		}
	}
	chain := slices.Clone(s.chain)
	for _, dir := range entered {
		if !slices.Contains(chain, dir) {
			chain = append(chain, dir)
		}
	}
	if len(chain) > lateMaxCwds {
		return false
	}
	s.cwds, s.chain = entered, chain
	if s.orSeen {
		s.cwds = slices.Clone(chain)
	}
	return true
}

// separator applies a command separator to the folders: after "&&" the next
// command runs in the folders the last cd entered; after ";" or "||" it may
// also run where an earlier cd of the chain failed, so every folder the
// chain has stood in counts. Once a "||" has come, a later "&&" may run
// although the cd before it was skipped (true || cd d && cmd), so a cd then
// adds its folders to the old ones, until the next ";".
func (s *lateScan) separator(separator string) {
	switch separator {
	case "||":
		s.orSeen = true
		s.cwds = slices.Clone(s.chain)
	case ";":
		s.orSeen = false
		s.cwds = slices.Clone(s.chain)
	}
}

var (
	// lateSeparators end a simple command.
	lateSeparators = []string{";", "&&", "||"}
	// lateFilters are the programs a call may pipe into.
	lateFilters = []string{"tail", "head", "grep", "egrep", "wc", "sort", "uniq", "cut", "tr", "cat", "less", "jq"}
	// lateWrappers run another program or a shell text the scan cannot read.
	lateWrappers = []string{"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "eval", "exec", "source", ".",
		"pushd", "popd", "env", "sudo", "su", "doas", "xargs", "nohup", "command", "builtin", "time", "watch", "timeout", "setsid",
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
	// cd is 1 after "cd" and 2 once it has its folder; only a separator may
	// follow, so no later word runs in a folder the scan does not know.
	cd := 0
	var program string
	var sed lateSed
	var pattern latePattern
	for _, token := range tokens {
		if token.operator {
			if cd == 1 || cd == 2 && !slices.Contains(lateSeparators, token.text) {
				return false
			}
			cd = 0
			switch {
			case slices.Contains(lateSeparators, token.text):
				atCommand, afterPipe = true, false
				s.separator(token.text)
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
			if strings.Contains(text, "/") {
				// A program given by a path is not the one of that name:
				// its words are read as if its options were unknown.
				base = ""
			}
			if base == "egrep" || base == "fgrep" {
				base = "grep"
			}
			atCommand, afterPipe, program, sed, pattern = false, false, base, lateSed{}, latePattern{}
			if base == "cd" {
				cd = 1
			}
			if !s.word("", text) {
				return false
			}
		case cd != 0:
			if cd == 2 || !s.chdir(text) {
				return false
			}
			cd = 2
		case slices.Contains(lateInterpreters, program) && slices.Contains(lateCodeFlags, text):
			return false
		case slices.Contains(lateTextPrograms, program):
			if !s.textWord(text) {
				return false
			}
		case program == "sed":
			ordinary, isPath := sed.accept(text)
			if !ordinary || isPath && !s.word(program, text) {
				return false
			}
		default:
			if handled, ok := s.patternWord(program, &pattern, text); handled {
				if !ok {
					return false
				}
			} else if !s.word(program, text) {
				return false
			}
		}
	}
	return !atCommand && !redirect && cd != 1
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
		return lateSedScript(text), false
	case !strings.HasPrefix(text, "-") || text == "-":
		if q.haveScript {
			return true, true
		}
		q.haveScript = true
		return lateSedScript(text), false
	case text == "--expression":
		q.expectScript = true
		return true, false
	case strings.HasPrefix(text, "--expression="):
		q.haveScript = true
		return lateSedScript(strings.TrimPrefix(text, "--expression=")), false
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
			return lateSedScript(text[i+1:]), false
		default:
			return false, false
		}
	}
	return true, false
}

// lateSedScript reports a script of commands that touch no file and run
// nothing. A script is read as sed reads it, command by command, so a
// semicolon inside a regexp or a replacement, spaces around a separator and
// a trailing separator are what they are. Each command is [address[,address]]
// [!] and one of p, d, q, Q, P, D, =, n, N, g, G, h, H, x, l, F or z (q, Q
// and l may end in a number), y/old/new/ or s/old/new/flags with the flags
// g, p, I, i, M, m or a number. Any other command (w, r, e, a, c, i, a block,
// a label, a comment) and any flag but those, and a backslash anywhere, is
// not ordinary.
func lateSedScript(script string) bool {
	if strings.Contains(script, "\\") {
		return false
	}
	rest := strings.TrimLeft(script, " \t;")
	for rest != "" {
		var ok bool
		if rest, ok = lateSedCommand(rest); !ok {
			return false
		}
		rest = strings.TrimLeft(rest, " \t")
		if rest != "" && rest[0] != ';' {
			return false
		}
		rest = strings.TrimLeft(rest, " \t;")
	}
	return true
}

// lateSedAddress takes one address off the front of script: a line number,
// $, first~step, or /regexp/ with the flags I and M. ok is false for a
// regexp that does not end.
func lateSedAddress(script string) (rest string, found, ok bool) {
	switch {
	case strings.HasPrefix(script, "/"):
		end := strings.Index(script[1:], "/")
		if end < 0 {
			return script, false, false
		}
		return strings.TrimLeft(script[end+2:], "IM"), true, true
	case strings.HasPrefix(script, "$"):
		return script[1:], true, true
	}
	rest = strings.TrimLeft(script, "0123456789")
	if rest == script {
		return script, false, true
	}
	if strings.HasPrefix(rest, "~") {
		rest = strings.TrimLeft(rest[1:], "0123456789")
	}
	return rest, true, true
}

// lateSedCommand reads one command of the shapes lateSedScript knows and
// returns what follows it.
func lateSedCommand(script string) (rest string, ok bool) {
	rest, found, ok := lateSedAddress(script)
	if !ok {
		return script, false
	}
	if found {
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, ",") {
			second := strings.TrimLeft(rest[1:], " \t")
			if strings.HasPrefix(second, "+") || strings.HasPrefix(second, "~") {
				second = second[1:]
			}
			if rest, found, ok = lateSedAddress(second); !ok || !found {
				return script, false
			}
		}
	}
	rest = strings.TrimLeft(rest, " \t")
	if found && strings.HasPrefix(rest, "!") {
		rest = strings.TrimLeft(rest[1:], " \t!")
	}
	if rest == "" {
		return script, false
	}
	switch rest[0] {
	case 'p', 'd', 'P', 'D', '=', 'n', 'N', 'g', 'G', 'h', 'H', 'x', 'F', 'z':
		return rest[1:], true
	case 'q', 'Q', 'l':
		return strings.TrimLeft(rest[1:], "0123456789"), true
	case 'y', 's':
		delimiter := rest[1:]
		if delimiter == "" || strings.IndexByte(lateLetters+"0123456789 \t", delimiter[0]) >= 0 {
			return script, false
		}
		parts := strings.SplitN(delimiter[1:], delimiter[:1], 3)
		if len(parts) != 3 {
			return script, false
		}
		flags := strings.TrimLeft(parts[2], "gpIiMm0123456789")
		if rest[0] == 'y' {
			flags = parts[2]
		}
		return flags, true
	}
	return script, false
}

// latePatternOptions describes the options of a program whose words are
// text: a pattern or a plain value (grep: -e, -f, -A 3, --include=glob; ls:
// -I). short and long hold the options whose value is the pattern, file the
// short letters and files the long options whose value is a path (patterns
// or names read from it), text the short letters and values the long
// options that take a plain value (a count, a glob), and flags the other
// long options, which are listed only so an abbreviation (--incl) is told
// like GNU getopt tells it. first is true when the first operand is the
// pattern unless an option gave it.
type latePatternOptions struct {
	short, file, text string
	long, files       []string
	values, flags     []string
	first             bool
}

var latePatternPrograms = map[string]latePatternOptions{
	"grep": {
		short: "e", file: "f", text: "ABCmdD", first: true,
		long:  []string{"regexp"},
		files: []string{"file", "exclude-from"},
		values: []string{"max-count", "after-context", "before-context", "context", "directories", "devices",
			"binary-files", "include", "exclude", "exclude-dir", "label", "group-separator"},
		flags: []string{"basic-regexp", "extended-regexp", "fixed-regexp", "fixed-strings", "perl-regexp", "ignore-case",
			"no-ignore-case", "invert-match", "word-regexp", "line-regexp", "count", "color", "colour", "files-without-match",
			"files-with-matches", "only-matching", "quiet", "silent", "no-messages", "byte-offset", "with-filename",
			"no-filename", "line-number", "initial-tab", "null", "null-data", "text", "recursive", "dereference-recursive",
			"line-buffered", "binary", "unix-byte-offsets", "no-group-separator", "help", "version"},
	},
	"ls": {short: "I", long: []string{"ignore", "hide"}},
}

// lateOptionKind is what a long option takes after it.
type lateOptionKind int

const (
	lateOptionOther   lateOptionKind = iota // no value, or not told: read as a path word
	lateOptionPattern                       // a pattern: text
	lateOptionText                          // a plain value: text
	lateOptionFile                          // a path
)

// longKind tells a long option name (without the dashes), also when it is an
// abbreviation every option it could stand for agrees on.
func (o latePatternOptions) longKind(name string) lateOptionKind {
	kind, seen := lateOptionOther, false
	for _, group := range []struct {
		names []string
		kind  lateOptionKind
	}{{o.long, lateOptionPattern}, {o.files, lateOptionFile}, {o.values, lateOptionText}, {o.flags, lateOptionOther}} {
		for _, candidate := range group.names {
			switch {
			case candidate == name:
				return group.kind
			case strings.HasPrefix(candidate, name):
				if seen && kind != group.kind {
					return lateOptionOther
				}
				kind, seen = group.kind, true
			}
		}
	}
	return kind
}

// latePattern follows the pattern and value words of one program call:
// expect says what the next word is, and done that the pattern is given.
type latePattern struct {
	expect lateOptionKind
	done   bool
}

// patternWord handles a word that is text of program (a pattern, or a value
// of an option that takes a plain one), or the path value of an option.
// handled is false for any other word, which the caller reads as a path word.
func (s *lateScan) patternWord(program string, st *latePattern, text string) (handled, ok bool) {
	opts, listed := latePatternPrograms[program]
	if !listed {
		return false, false
	}
	if expected := st.expect; expected != lateOptionOther {
		st.expect = lateOptionOther
		if expected == lateOptionFile {
			return false, false
		}
		return true, s.textWord(text)
	}
	switch {
	case strings.HasPrefix(text, "--") && len(text) > 2:
		name, value, hasValue := strings.Cut(text[2:], "=")
		switch opts.longKind(name) {
		case lateOptionPattern:
			st.done = true
			return st.optionValue(s, lateOptionPattern, value, hasValue)
		case lateOptionText:
			return st.optionValue(s, lateOptionText, value, hasValue)
		case lateOptionFile:
			// --file reads the patterns from its value, the next word when it
			// is not attached: a path, whatever it looks like (--regexp).
			if strings.HasPrefix("file", name) {
				st.done = true
			}
			if !hasValue {
				st.expect = lateOptionFile
			}
		}
	case strings.HasPrefix(text, "-") && len(text) > 1:
		known := lateShortOptions[program]
		for i := 1; i < len(text); i++ {
			letter := text[i]
			switch {
			case strings.IndexByte(opts.short, letter) >= 0:
				st.done = true
				return st.optionValue(s, lateOptionPattern, text[i+1:], i+1 < len(text))
			case strings.IndexByte(opts.text, letter) >= 0:
				return st.optionValue(s, lateOptionText, text[i+1:], i+1 < len(text))
			case strings.IndexByte(opts.file, letter) >= 0:
				st.done = true
				if i+1 == len(text) {
					st.expect = lateOptionFile
				}
				return false, false
			case strings.IndexByte(known.flags, letter) < 0:
				return false, false
			}
		}
	case opts.first && !st.done:
		st.done = true
		return true, s.textWord(text)
	}
	return false, false
}

// optionValue reads the value of an option that takes text: the part of the
// word after the option when it has one, else the next word.
func (st *latePattern) optionValue(s *lateScan, kind lateOptionKind, value string, attached bool) (handled, ok bool) {
	if !attached {
		st.expect = kind
		return true, true
	}
	return true, value == "" || s.textWord(value)
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

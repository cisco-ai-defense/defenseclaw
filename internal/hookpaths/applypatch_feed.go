// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// A staged patch is an apply_patch call that reads its envelope from a file:
// apply_patch < FILE, env apply_patch < FILE, cat FILE | apply_patch or
// Get-Content FILE | apply_patch. Its targets are the directives in that
// file, which the hook reads as the user before the call runs (classifier
// refix 1, RV3-1). The read is trusted only when nothing else in the command
// can change the file first: every other statement prints text or applies
// an inline envelope, and no patch of the command writes a staged file.
// Any other shape keeps the targets unknown (TGT-0194).

const patchFeedPlaceholder = "_dc_inline_patch_"

// patchFeedProgram matches a program word the staged-patch reading knows.
var patchFeedProgram = lazyregexp.New(`^[A-Za-z][A-Za-z0-9_.-]*$`)

// patchStagedFeeds returns the files that the apply_patch calls of a shell
// text read on stdin. ok is false unless the text is a staged-patch command
// (see above) with at least one such file.
func patchStagedFeeds(text string) (files []string, powershell []bool, ok bool) {
	collapsed, collapsedOK := patchCollapseEnvelopes(text)
	if !collapsedOK || strings.ContainsAny(collapsed, ">`(){}") || strings.Contains(collapsed, "$(") {
		return nil, nil, false
	}
	segments, separators, split := patchFeedSegments(collapsed)
	if !split {
		return nil, nil, false
	}
	for i := 0; i < len(segments); i++ {
		words := segments[i]
		if len(words) == 0 {
			continue
		}
		pipedNext := i+1 < len(segments) && separators[i] == "|"
		if len(words) == 1 && words[0] == patchFeedPlaceholder {
			continue // PowerShell sends a here-string down the pipeline
		}
		program := strings.ToLower(words[0])
		if !patchFeedProgram.MatchString(program) {
			return nil, nil, false
		}
		if program != "get-content" && program != "gc" {
			for _, word := range words {
				if patchFeedEscaped(word) {
					return nil, nil, false
				}
			}
		}
		switch program {
		case "echo", "printf", "write-output", "write-host":
			for _, word := range words[1:] {
				if strings.HasPrefix(word, "<") {
					return nil, nil, false
				}
			}
			continue
		case "cat", "get-content", "gc":
			file, shellPS, fed := patchFeedReader(program, words[1:])
			if !fed || !pipedNext || !patchApplyCall(segments[i+1]) {
				return nil, nil, false
			}
			files = append(files, file)
			powershell = append(powershell, shellPS)
			continue
		}
		rest, applies := patchApplyRest(words)
		if !applies {
			return nil, nil, false
		}
		switch {
		case len(rest) == 0,
			len(rest) == 1 && rest[0] == patchFeedPlaceholder,
			len(rest) == 2 && (rest[0] == "<<" || rest[0] == "<<<") && rest[1] == patchFeedPlaceholder:
		case len(rest) == 2 && rest[0] == "<",
			len(rest) == 1 && strings.HasPrefix(rest[0], "<") && !strings.HasPrefix(rest[0], "<<"):
			name := strings.TrimPrefix(rest[len(rest)-1], "<")
			if len(rest) == 2 {
				name = rest[1]
			}
			file, static := patchFeedFileWord(name, false)
			if !static {
				return nil, nil, false
			}
			files = append(files, file)
			powershell = append(powershell, false)
		default:
			return nil, nil, false
		}
	}
	return files, powershell, len(files) > 0
}

// patchApplyCall reports a segment that is a bare apply_patch call.
func patchApplyCall(words []string) bool {
	rest, applies := patchApplyRest(words)
	return applies && len(rest) == 0
}

// patchApplyRest returns the words after an apply_patch program word, behind
// env, command, exec, nohup or time with no options.
func patchApplyRest(words []string) ([]string, bool) {
	for len(words) > 0 {
		switch strings.ToLower(words[0]) {
		case "env", "command", "exec", "nohup", "time":
			words = words[1:]
			continue
		case "apply_patch", "applypatch", "apply-patch":
			return words[1:], true
		}
		return nil, false
	}
	return nil, false
}

// patchFeedReader reads the file operand of cat FILE or Get-Content
// [-Raw] [-Path|-LiteralPath] FILE [-Raw].
func patchFeedReader(program string, words []string) (string, bool, bool) {
	shellPS := program != "cat"
	var operands []string
	for i := 0; i < len(words); i++ {
		word := strings.ToLower(words[i])
		switch {
		case shellPS && word == "-raw":
			continue
		case shellPS && (word == "-path" || word == "-literalpath") && i+1 < len(words):
			continue
		case strings.HasPrefix(word, "-"):
			return "", false, false
		}
		operands = append(operands, words[i])
	}
	if len(operands) != 1 {
		return "", false, false
	}
	file, static := patchFeedFileWord(operands[0], shellPS)
	return file, shellPS, static
}

// patchFeedFileWord reads a file operand that names one file in POSIX shells
// and PowerShell alike: plain, or wholly single- or double-quoted, with no
// expansion, wildcard, provider or stream name. A backslash is a separator
// only for a PowerShell reader; to a POSIX shell it is an escape.
func patchFeedFileWord(word string, powershell bool) (string, bool) {
	quoted := byte(0)
	if len(word) >= 2 && (word[0] == '\'' || word[0] == '"') && word[len(word)-1] == word[0] {
		quoted, word = word[0], word[1:len(word)-1]
	}
	switch {
	case word == "" || len(word) > MaxWriteTargetPathBytes,
		strings.ContainsAny(word, "$`*?[]{}<>|;&\x00\r\n"),
		quoted == 0 && strings.ContainsAny(word, "'\" \t"),
		quoted != 0 && strings.IndexByte(word, quoted) >= 0,
		// A backslash is a separator only to PowerShell; a POSIX shell
		// reads it as an escape outside single quotes.
		strings.Contains(word, `\`) && quoted != '\'' && (!powershell || strings.Contains(word, `\\`)),
		// ~user, or a quoted ~ that a POSIX shell keeps literal.
		strings.HasPrefix(word, "~") && (quoted != 0 || len(word) > 1 && word[1] != '/' && word[1] != '\\'):
		return "", false
	}
	// A drive letter is the only colon: no PowerShell provider (env:,
	// function:) and no NTFS stream name.
	if colon := strings.IndexByte(word, ':'); colon >= 0 &&
		(colon != 1 || len(word) < 3 || word[2] != '\\' && word[2] != '/' || strings.Count(word, ":") > 1) {
		return "", false
	}
	return word, true
}

// patchFeedEscaped reports a word with a backslash outside single quotes:
// a POSIX shell may read it as an escape of a quote or a separator, which
// the plain split of patchFeedSegments does not follow.
func patchFeedEscaped(word string) bool {
	return strings.Contains(withoutSingleQuoted(word), `\`)
}

// patchCollapseEnvelopes replaces every inline envelope, with the quote,
// here-document or here-string that feeds it, by patchFeedPlaceholder. It
// fails when a feed is not proven to close right after its envelope with
// only patch lines inside (the rules of patchShellInvocationsKnown).
func patchCollapseEnvelopes(text string) (string, bool) {
	lines := strings.Split(text, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		begin := strings.Index(line, patchBeginMarker)
		if begin < 0 {
			if strings.Contains(line, patchEndMarker) {
				return "", false
			}
			out = append(out, line)
			continue
		}
		if strings.TrimSpace(line[begin+len(patchBeginMarker):]) != "" {
			return "", false
		}
		end := i + 1
		for end < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[end]), patchEndMarker) {
			end++
		}
		if end == len(lines) {
			return "", false
		}
		ownLine := strings.TrimSpace(line[:begin]) == "" && len(out) > 0
		opener := line[:begin]
		if ownLine {
			opener = out[len(out)-1]
			out = out[:len(out)-1]
		}
		feed, fed := patchOpenerFeed(opener, ownLine)
		if !fed {
			return "", false
		}
		for _, body := range lines[i+1 : end] {
			body = strings.TrimRight(strings.TrimLeft(body, "\t"), "\r")
			if !patchBodyShape(body) || feed.ends(body) || feed.expands(body) {
				return "", false
			}
		}
		rest := strings.TrimSpace(strings.TrimSpace(lines[end])[len(patchEndMarker):])
		next := ""
		if end+1 < len(lines) {
			next = strings.TrimSpace(lines[end+1])
		}
		var head, tail string
		switch {
		case feed.quote != 0:
			head = opener[:strings.LastIndexByte(opener, feed.quote)]
			if rest == "" {
				rest, end = next, end+1
			}
			if rest == "" || rest[0] != feed.quote {
				return "", false
			}
			tail = rest[1:]
		case feed.powershell:
			head = strings.TrimSuffix(strings.TrimSpace(opener), "@"+feed.delim[:1])
			if rest != "" || !strings.HasPrefix(next, feed.delim) {
				return "", false
			}
			tail, end = strings.TrimPrefix(next, feed.delim), end+1
		default:
			match := heredocOperator.FindStringSubmatchIndex(opener)
			if match == nil || rest != "" || next != feed.delim {
				return "", false
			}
			after := match[1]
			if after > 0 && after <= len(opener) && strings.ContainsRune(" \t|;&)>", rune(opener[after-1])) {
				after-- // the operator pattern ends on the next separator
			}
			head, tail, end = opener[:match[0]]+" << ", opener[after:], end+1
		}
		out = append(out, head+" "+patchFeedPlaceholder+" "+tail)
		i = end
	}
	return strings.Join(out, "\n"), true
}

// patchFeedSegments splits a collapsed text into simple commands at newlines,
// ;, &, &&, || and |, outside quotes, and each command into words. separators
// holds the operator after each command.
func patchFeedSegments(text string) (segments [][]string, separators []string, ok bool) {
	var words []string
	var word strings.Builder
	inWord := false
	var quote byte
	flushWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	flush := func(separator string) {
		flushWord()
		segments = append(segments, words)
		separators = append(separators, separator)
		words = nil
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			word.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			inWord = true
			word.WriteByte(c)
		case ' ', '\t', '\r':
			flushWord()
		case '\n', ';':
			flush(";")
		case '&', '|':
			separator := string(c)
			if i+1 < len(text) && text[i+1] == c {
				separator += string(c)
				i++
			}
			if separator == "&&" || separator == "||" || separator == "&" {
				separator = ";"
			}
			flush(separator)
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, nil, false
	}
	flush(";")
	return segments, separators, true
}

// patchStagedTargets lists the directive paths of every staged patch file a
// shell text feeds to apply_patch, read as this process from cwd and home.
// ok is false when the text is not a staged-patch command, a file cannot be
// read or holds no complete envelope, or a patch of the command writes a
// staged file (its content at run time is then unknown).
func patchStagedTargets(text, cwd, home string, inline []string) ([]string, bool) {
	files, _, staged := patchStagedFeeds(text)
	if !staged {
		return nil, false
	}
	var paths, feeds []string
	for _, name := range files {
		file, placed := patchFeedPath(name, cwd, home)
		if !placed {
			return nil, false
		}
		content, read := readPatchFeed(file)
		if !read {
			return nil, false
		}
		directives, envelopes, parsed := patchEnvelopePaths(content)
		if !parsed || envelopes == 0 {
			return nil, false
		}
		feeds = append(feeds, file)
		paths = append(paths, directives...)
	}
	for _, path := range append(append([]string(nil), inline...), paths...) {
		base := patchPathBase(path)
		for _, feed := range feeds {
			if strings.EqualFold(base, patchPathBase(feed)) {
				return nil, false
			}
		}
	}
	return paths, true
}

func patchPathBase(path string) string {
	path = strings.Trim(path, `"'`)
	if index := strings.LastIndexAny(path, `/\`); index >= 0 {
		path = path[index+1:]
	}
	return path
}

// patchFeedPath places a staged patch file operand in home or cwd.
func patchFeedPath(name, cwd, home string) (string, bool) {
	if rest, homeForm := strings.CutPrefix(name, "~"); homeForm {
		if !filepath.IsAbs(home) {
			return "", false
		}
		return filepath.Join(home, strings.TrimLeft(rest, `/\`)), true
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name), true
	}
	if !filepath.IsAbs(cwd) || runtime.GOOS == "windows" &&
		(filepath.VolumeName(name) != "" || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`)) {
		return "", false
	}
	return filepath.Join(cwd, name), true
}

// readPatchFeed reads a regular file of at most MaxPayloadBytes.
func readPatchFeed(path string) (string, bool) {
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > MaxPayloadBytes {
		return "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() {
		return "", false
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxPayloadBytes+1))
	if err != nil || len(content) > MaxPayloadBytes {
		return "", false
	}
	return string(content), true
}

// ApplyPatchStagedFeed reports a shell call that feeds apply_patch a staged
// patch file (apply_patch < FILE, cat FILE | apply_patch, Get-Content FILE |
// apply_patch) in a command that cannot change the file first. The user's
// hook reads that file and lists its targets; a gateway that cannot read it
// (ProtectHome) judges the hook's list.
func ApplyPatchStagedFeed(args json.RawMessage, command string) bool {
	var fields map[string]json.RawMessage
	if len(args) != 0 {
		_ = json.Unmarshal(args, &fields)
	}
	for _, text := range []string{command, patchTextField(fields["command"]), patchTextField(fields["cmd"])} {
		if text == "" {
			continue
		}
		if body, ok := patchShellCommandBody(text); ok {
			text = body
		}
		if _, _, staged := patchStagedFeeds(text); staged {
			return true
		}
	}
	return false
}

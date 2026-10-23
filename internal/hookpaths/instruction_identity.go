// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// InstructionFileNames are the agent instruction and identity files that the
// cognitive-file rules (COG-*) protect. Protection follows the file, not one
// spelling of its name (GAP-0869): a symlink, a hard link, a case variant on a
// case-insensitive volume and a Windows short or stream name all write it.
var InstructionFileNames = [...]string{
	"AGENTS.md", "CLAUDE.md", "SOUL.md", "IDENTITY.md",
	"MEMORY.md", "TOOLS.md", "openclaw.json", "gateway.json",
}

// InstructionIdentityKey carries the hook client's file-identity check of a
// call's write targets and hard-link sources. The value is the path of the
// protected instruction file that one of them names under another name, or
// InstructionIdentityUnknown for a file with more than one hard link whose
// other names cannot be listed. A gateway that cannot read the user's files
// (ProtectHome) judges the call from it.
const InstructionIdentityKey = "\x00instruction-identity"

// InstructionIdentityUnknown is a write target or hard-link source with more
// than one hard link whose names this platform cannot list. POSIX has no call
// that lists a file's names, so such a file may be an instruction file.
const InstructionIdentityUnknown = "?"

// InstructionFileName returns the protected name that base spells: exactly,
// or without case when foldCase (Windows, where the file system ignores it).
func InstructionFileName(base string, foldCase bool) (string, bool) {
	for _, name := range InstructionFileNames {
		if base == name || foldCase && strings.EqualFold(base, name) {
			return name, true
		}
	}
	return "", false
}

func instructionNameFold() bool { return runtime.GOOS == "windows" }

// InstructionAlias reports the protected instruction file that an existing
// write target names under another name: through a symlink, as a case,
// short-name or stream variant of a file in its directory, or as a hard link.
// unknown reports a target with more than one hard link whose names cannot
// all be checked; it may be another name of an instruction file anywhere on
// its volume. A missing file, one that is not regular, one the caller cannot
// read and one already spelled as an instruction name are neither: the name
// rules judge the last.
func InstructionAlias(path, cwd, home string) (instruction string, unknown bool) {
	if !filepath.IsAbs(path) {
		return "", false
	}
	path = filepath.Clean(path)
	real := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		real = resolved
	}
	info, err := os.Stat(real)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	if _, named := InstructionFileName(filepath.Base(real), instructionNameFold()); named {
		if real == path {
			return "", false
		}
		return real, false
	}
	same := func(candidate string) bool {
		other, err := os.Stat(candidate)
		return err == nil && other.Mode().IsRegular() && os.SameFile(info, other)
	}
	// A case variant on a case-insensitive volume, and a Windows short or
	// stream name, open a file of the same directory with one link.
	dir := filepath.Dir(real)
	for _, name := range InstructionFileNames {
		if candidate := filepath.Join(dir, name); same(candidate) {
			return candidate, false
		}
	}
	if linkCount(real, info) <= 1 {
		return "", false
	}
	if names, complete, listed := fileLinkNames(real); listed {
		for _, name := range names {
			if _, named := InstructionFileName(filepath.Base(name), true); named {
				return name, false
			}
		}
		if complete {
			return "", false
		}
	}
	for _, directory := range instructionDirectories(dir, cwd, home) {
		for _, name := range InstructionFileNames {
			if candidate := filepath.Join(directory, name); same(candidate) {
				return candidate, false
			}
		}
	}
	return "", true
}

// instructionDirectories are the places agents load instruction files from,
// checked to name the file a hard link reaches: the target's directory, the
// working directory and its parents, and the home and agent folders.
func instructionDirectories(dir, cwd, home string) []string {
	directories := []string{dir}
	add := func(directory string) {
		if filepath.IsAbs(directory) && !slices.Contains(directories, directory) {
			directories = append(directories, directory)
		}
	}
	if filepath.IsAbs(cwd) {
		for current, steps := filepath.Clean(cwd), 0; steps < 64; steps++ {
			add(current)
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	if filepath.IsAbs(home) {
		for _, sub := range []string{"", ".claude", ".codex", ".openclaw", filepath.Join(".openclaw", "workspace")} {
			add(filepath.Join(home, sub))
		}
	}
	return directories
}

var (
	// hardLinkCall is an interpreter, PowerShell or Windows tool call that
	// creates a hard link from text this package does not evaluate.
	hardLinkCall = regexp.MustCompile(`(?i)\.link(?:sync)?\s*\(|\.(?:hardlink_to|link_to)\s*\(|` +
		`\bfileutils\.(?:ln|link)\s*\(|\bmklink(?:\.exe)?\s+(?:/[dj]\s+)*/h\b|` +
		`\bfsutil(?:\.exe)?\s+hardlink\b|-(?:itemtype|type|it)[\s:]+['"]?hardlink\b|\bcreatehardlink`)
	// instructionNameText names an instruction file in command text.
	instructionNameText = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.-])((?:agents|claude|soul|identity|memory|tools)\.md|(?:openclaw|gateway)\.json)(?:$|[^a-z0-9_-])`)
)

// InstructionLinkCreation reports a hard link that a shell command creates to
// a protected instruction file: its path, the instruction name the command
// text gives such a link when its operands cannot be read, or unknown for a
// hard link whose source cannot be listed or whose names cannot be checked.
// A new hard link is another name for the file, so creating one is refused
// like a write (GAP-0869). Symbolic links are left to write resolution,
// which follows them. The command of an apply_patch tool is a patch
// envelope, not shell.
func InstructionLinkCreation(tool, command, cwd, home string) (instruction string, unknown bool) {
	if command == "" || isApplyPatchToolName(tool) || !filepath.IsAbs(cwd) {
		return "", false
	}
	sources, opaque, wrapped := hardLinkSources(command, cwd, home)
	for _, source := range sources {
		literal := OperandPath(source, cwd)
		if name, named := InstructionFileName(filepath.Base(literal), instructionNameFold()); named {
			return filepath.Join(filepath.Dir(literal), name), false
		}
		resolved, ok := resolveWritePath(literal, 0)
		if !ok {
			unknown = true
			continue
		}
		if name, named := InstructionFileName(filepath.Base(resolved), instructionNameFold()); named {
			return filepath.Join(filepath.Dir(resolved), name), false
		}
		alias, aliasUnknown := InstructionAlias(resolved, cwd, home)
		if alias != "" {
			return alias, false
		}
		unknown = unknown || aliasUnknown
	}
	if opaque || wrapped {
		if match := instructionNameText.FindStringSubmatch(command); match != nil {
			name, _ := InstructionFileName(match[1], true)
			return name, false
		}
		// A wrapped ln without an instruction name is left to the write:
		// a later write through the link meets InstructionAlias.
		unknown = unknown || opaque
	}
	return "", unknown
}

// hardLinkSources lists the static source operands of the hard links a shell
// command creates with ln, link or cp --link (also through busybox or
// toybox). opaque reports a hard link whose operands are not static and an
// interpreter or Windows hard-link call; wrapped reports a wrapper (sudo, sh
// -c, find -exec, xargs) that may run ln or cp, whose options this package
// does not read.
func hardLinkSources(command, cwd, home string) (sources []string, opaque, wrapped bool) {
	file, parsed := parseShell(command)
	if !parsed {
		return nil, hardLinkCall.MatchString(command), tactics.RunsProgram(command, linkPrograms...)
	}
	if hardLinkCall.MatchString(command) {
		for _, stmt := range file.Stmts {
			if !dataStatement(stmt, home) {
				opaque = true
				break
			}
		}
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	boundPrograms := actionBoundProgramWords(file, home)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		args := call.Args
		words := make([]string, len(args))
		static := make([]bool, len(args))
		for i, arg := range args {
			words[i], static[i] = staticShellWord(arg, env, home != "")
		}
		if !static[0] {
			words[0], static[0] = staticProgramWord(args[0], home)
		}
		if !static[0] {
			words[0] = boundPrograms[call]
			static[0] = words[0] != ""
		}
		program, start := "", call.Pos()
		if static[0] {
			program = programBase(words[0])
		}
		for slices.Contains(multicallPrograms, program) && len(args) > 1 {
			args, words, static, start = args[1:], words[1:], static[1:], args[1].Pos()
			program = ""
			if static[0] {
				program = programBase(words[0])
			}
		}
		switch {
		case slices.Contains(linkPrograms, program):
			if symbolicLinkCall(program, words[1:], static[1:]) {
				return true
			}
			if slices.Contains(static, false) {
				opaque = true
				return true
			}
			var links shellLinks
			if !links.add(program, words[1:], cwd) {
				opaque = true
				return true
			}
			for _, alias := range links.aliases {
				if !slices.Contains(sources, alias.target) {
					sources = append(sources, alias.target)
				}
			}
		case slices.Contains(copyPrograms, program):
			option, dynamic := copyLinkOptions(args[1:], words[1:], static[1:])
			if dynamic {
				opaque = true
				return true
			}
			if !option {
				return true
			}
			parsed := cpOperands(words[1:], static[1:])
			if !parsed.ok {
				opaque = true
				return true
			}
			if !parsed.hard {
				return true
			}
			if slices.Contains(static, false) {
				opaque = true
				return true
			}
			for _, source := range parsed.sources {
				if !slices.Contains(sources, source) {
					sources = append(sources, source)
				}
			}
		case program == "":
			// A program named by a parameter or substitution may be ln.
			if tactics.RunsProgram(command[start.Offset():call.End().Offset()], linkPrograms...) {
				wrapped = true
			}
		case program == "find" || program == "xargs" || program == "parallel":
			// find -exec and xargs run a program named by a later word.
			text := command[start.Offset():call.End().Offset()]
			for _, word := range words[1:] {
				if slices.Contains(linkPrograms, programBase(word)) ||
					slices.Contains(copyPrograms, programBase(word)) && copyLinkOption.MatchString(text) {
					wrapped = true
				}
			}
		default:
			// A wrapper (sudo, env, nice, sh -c, eval) may run one.
			text := command[start.Offset():call.End().Offset()]
			if tactics.RunsProgram(text, linkPrograms...) ||
				tactics.RunsProgram(text, copyPrograms...) && copyLinkOption.MatchString(text) {
				wrapped = true
			}
		}
		return true
	})
	return sources, opaque, wrapped
}

// symbolicLinkCall reports an ln call with a static symbolic option. link
// always creates a hard link.
func symbolicLinkCall(program string, args []string, static []bool) bool {
	if program == "link" || program == "glink" {
		return false
	}
	for i, arg := range args {
		if !static[i] || arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "--") {
			name, _, _ := strings.Cut(arg[2:], "=")
			if option, ok := longOption(name, lnLongOptions); ok && option == "symbolic" {
				return true
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 's':
				return true
			case 't', 'S':
				// The rest of the word is the option's value.
				j = len(arg)
			}
		}
	}
	return false
}

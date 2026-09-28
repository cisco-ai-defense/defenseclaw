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

// Package wrapper writes and removes the shell wrapper `defenseclaw sandbox
// enable <harness>` installs: one marked block in the user's shell rc file
// (bash, zsh or fish) that defines a function per wrapped harness, so typing
// `claude` runs `defenseclaw sandbox run claude -- "$@"`. The block is the
// only thing the package ever changes in an rc file; everything outside the
// markers is preserved byte for byte, and removing the last wrapper removes
// the block. DEFENSECLAW_NO_SANDBOX=1 bypasses a wrapper, and a shell inside a
// sandbox (DEFENSECLAW_SANDBOX_ID set) runs the harness natively. PATH shims
// are deliberately not used.
package wrapper

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Shell is a supported interactive shell.
type Shell string

const (
	Bash Shell = "bash"
	Zsh  Shell = "zsh"
	Fish Shell = "fish"
)

// Shells lists the supported shells.
var Shells = []Shell{Bash, Zsh, Fish}

// Block markers. The begin marker line starts the block and the end marker
// line ends it; both are matched as whole lines.
const (
	BeginMarker = "# >>> defenseclaw sandbox wrappers >>>"
	EndMarker   = "# <<< defenseclaw sandbox wrappers <<<"
)

// EnvBypass runs the harness directly, without a sandbox.
const EnvBypass = "DEFENSECLAW_NO_SANDBOX"

// envNested is set inside every DefenseClaw sandbox (openshell.EnvSandboxID);
// a wrapper there runs the harness natively.
const envNested = "DEFENSECLAW_SANDBOX_ID"

// maxRCBytes bounds the rc files the package reads.
const maxRCBytes = 4 << 20

// ParseShell resolves a shell name or a $SHELL path.
func ParseShell(s string) (Shell, error) {
	base := strings.TrimSpace(filepath.Base(strings.TrimSpace(s)))
	switch Shell(base) {
	case Bash, Zsh, Fish:
		return Shell(base), nil
	}
	return "", fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", s)
}

// RCPath returns the rc file the wrapper block goes in: ~/.bashrc,
// ${ZDOTDIR:-~}/.zshrc, or ${XDG_CONFIG_HOME:-~/.config}/fish/config.fish.
func RCPath(shell Shell, home string, getenv func(string) string) (string, error) {
	if home == "" || !filepath.IsAbs(home) {
		return "", fmt.Errorf("wrapper: home directory %q is not absolute", home)
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	switch shell {
	case Bash:
		return filepath.Join(home, ".bashrc"), nil
	case Zsh:
		if dir := strings.TrimSpace(getenv("ZDOTDIR")); dir != "" && filepath.IsAbs(dir) {
			return filepath.Join(dir, ".zshrc"), nil
		}
		return filepath.Join(home, ".zshrc"), nil
	case Fish:
		if dir := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); dir != "" && filepath.IsAbs(dir) {
			return filepath.Join(dir, "fish", "config.fish"), nil
		}
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	}
	return "", fmt.Errorf("wrapper: unsupported shell %q", shell)
}

// Wrap is one wrapped harness.
type Wrap struct {
	// Command is the name the user types (claude, codex).
	Command string
	// Harness is the name passed to `sandbox run` (claude, codex).
	Harness string
}

var commandPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func (w Wrap) validate() error {
	if !commandPattern.MatchString(w.Command) || !commandPattern.MatchString(w.Harness) {
		return fmt.Errorf("wrapper: invalid harness command %q/%q", w.Command, w.Harness)
	}
	return nil
}

// Block is the parsed wrapper block of one rc file.
type Block struct {
	// Binary is the DefenseClaw executable the functions call.
	Binary string
	Wraps  []Wrap
}

// Commands returns the wrapped command names, sorted.
func (b Block) Commands() []string {
	out := make([]string, 0, len(b.Wraps))
	for _, w := range b.Wraps {
		out = append(out, w.Command)
	}
	sort.Strings(out)
	return out
}

// Has reports whether command is wrapped.
func (b Block) Has(command string) bool {
	for _, w := range b.Wraps {
		if w.Command == command {
			return true
		}
	}
	return false
}

// Render returns the block text for shell, ending in a newline. An empty
// block renders as nothing.
func Render(shell Shell, b Block) (string, error) {
	if len(b.Wraps) == 0 {
		return "", nil
	}
	if !filepath.IsAbs(b.Binary) || strings.ContainsAny(b.Binary, "\x00\n\r") {
		return "", fmt.Errorf("wrapper: the DefenseClaw binary path %q must be absolute", b.Binary)
	}
	wraps := append([]Wrap(nil), b.Wraps...)
	sort.Slice(wraps, func(i, j int) bool { return wraps[i].Command < wraps[j].Command })
	var sb strings.Builder
	sb.WriteString(BeginMarker + "\n")
	sb.WriteString("# Added by `defenseclaw sandbox enable`; remove with `defenseclaw sandbox disable <harness>`.\n")
	sb.WriteString("# " + EnvBypass + "=1 runs the harness directly, without a sandbox.\n")
	bin := shellQuote(b.Binary)
	for _, w := range wraps {
		if err := w.validate(); err != nil {
			return "", err
		}
		switch shell {
		case Bash, Zsh:
			// An alias of the same name (Claude Code's installer adds one)
			// would expand inside the definition, a syntax error that
			// leaves the alias running the harness natively, and would
			// win over the function when typed.
			fmt.Fprintf(&sb, "unalias %s 2>/dev/null || true\n", w.Command)
			fmt.Fprintf(&sb, "%s() {\n", w.Command)
			fmt.Fprintf(&sb, "  if [ -n \"${%s:-}\" ] || [ -n \"${%s:-}\" ]; then command %s \"$@\"; return; fi\n", EnvBypass, envNested, w.Command)
			fmt.Fprintf(&sb, "  if [ ! -x %s ]; then echo '%s' >&2; return 127; fi\n", bin, missingMessage(w.Command))
			fmt.Fprintf(&sb, "  %s sandbox run %s -- \"$@\"\n", bin, w.Harness)
			sb.WriteString("}\n")
		case Fish:
			fmt.Fprintf(&sb, "function %s --wraps %s --description 'Run %s in a DefenseClaw sandbox'\n", w.Command, w.Command, w.Command)
			fmt.Fprintf(&sb, "    if test -n \"$%s\"; or test -n \"$%s\"\n", EnvBypass, envNested)
			fmt.Fprintf(&sb, "        command %s $argv\n", w.Command)
			sb.WriteString("        return\n    end\n")
			fmt.Fprintf(&sb, "    if not test -x %s\n", bin)
			fmt.Fprintf(&sb, "        echo '%s' >&2\n", missingMessage(w.Command))
			sb.WriteString("        return 127\n    end\n")
			fmt.Fprintf(&sb, "    %s sandbox run %s -- $argv\n", bin, w.Harness)
			sb.WriteString("end\n")
		default:
			return "", fmt.Errorf("wrapper: unsupported shell %q", shell)
		}
	}
	sb.WriteString(EndMarker + "\n")
	return sb.String(), nil
}

// missingMessage is what a wrapper prints when the DefenseClaw binary it
// calls is gone. It never runs the harness unsandboxed on its own.
func missingMessage(command string) string {
	return "defenseclaw: the sandbox launcher is missing (reinstall DefenseClaw or run `defenseclaw sandbox disable " +
		command + "`); " + EnvBypass + "=1 " + command + " starts " + command + " without a sandbox"
}

// ErrMalformedBlock reports an rc file whose wrapper markers are unbalanced
// or repeated; the package refuses to edit it.
var ErrMalformedBlock = errors.New("wrapper: the DefenseClaw wrapper block markers are damaged")

// split cuts an rc file into the text before the block, the block (with its
// markers) and the text after it. found is false when there is no block.
func split(data []byte) (before, block, after []byte, found bool, err error) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	begin, end := -1, -1
	for i, l := range lines {
		t := strings.TrimRight(string(l), "\r\n")
		switch t {
		case BeginMarker:
			if begin >= 0 {
				return nil, nil, nil, false, ErrMalformedBlock
			}
			begin = i
		case EndMarker:
			if begin < 0 || end >= 0 {
				return nil, nil, nil, false, ErrMalformedBlock
			}
			end = i
		}
	}
	if begin < 0 && end < 0 {
		return data, nil, nil, false, nil
	}
	if begin < 0 || end < 0 {
		return nil, nil, nil, false, ErrMalformedBlock
	}
	join := func(ls [][]byte) []byte { return bytes.Join(ls, nil) }
	return join(lines[:begin]), join(lines[begin : end+1]), join(lines[end+1:]), true, nil
}

var (
	posixFunc = regexp.MustCompile(`^([a-z][a-z0-9_-]{0,31})\(\) \{$`)
	fishFunc  = regexp.MustCompile(`^function ([a-z][a-z0-9_-]{0,31}) `)
	runLine   = regexp.MustCompile(`^\s*(.+) sandbox run ([a-z][a-z0-9_-]{0,31}) -- `)
)

// parse reads the wraps and binary out of a block written by Render.
func parse(block []byte) Block {
	var b Block
	current := ""
	for _, raw := range strings.Split(string(block), "\n") {
		line := strings.TrimRight(raw, "\r")
		if m := posixFunc.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := fishFunc.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := runLine.FindStringSubmatch(line); m != nil && current != "" {
			b.Binary = shellUnquote(strings.TrimSpace(m[1]))
			b.Wraps = append(b.Wraps, Wrap{Command: current, Harness: m[2]})
			current = ""
		}
	}
	return b
}

// Read returns the wrapper block of the rc file at path (empty when the file
// or the block does not exist).
func Read(path string) (Block, error) {
	data, err := readRC(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Block{}, nil
		}
		return Block{}, err
	}
	_, block, _, found, err := split(data)
	if err != nil || !found {
		return Block{}, err
	}
	return parse(block), nil
}

// Change is the outcome of Enable or Disable.
type Change struct {
	Path    string
	Changed bool
	// Block is the block now in the file.
	Block Block
}

// Enable adds (or refreshes) the wrapper for w in the rc file at path,
// creating the file when needed. binary is the absolute DefenseClaw
// executable the functions call; every wrap in the block is re-rendered
// with it.
func Enable(shell Shell, path, binary string, w Wrap) (Change, error) {
	if err := w.validate(); err != nil {
		return Change{}, err
	}
	return edit(shell, path, func(b *Block) {
		b.Binary = binary
		for i, have := range b.Wraps {
			if have.Command == w.Command {
				b.Wraps[i] = w
				return
			}
		}
		b.Wraps = append(b.Wraps, w)
	})
}

// Disable removes the wrapper for command; the block goes when it is the
// last one. A missing file or block is not an error.
func Disable(shell Shell, path, command string) (Change, error) {
	data, err := readRC(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Change{Path: path}, nil
	}
	if err != nil {
		return Change{}, err
	}
	if _, _, _, found, err := split(data); err != nil {
		return Change{}, err
	} else if !found {
		return Change{Path: path}, nil
	}
	return edit(shell, path, func(b *Block) {
		kept := b.Wraps[:0]
		for _, have := range b.Wraps {
			if have.Command != command {
				kept = append(kept, have)
			}
		}
		b.Wraps = kept
	})
}

// RemoveAll deletes the wrapper block from the rc file, whatever it wraps.
func RemoveAll(shell Shell, path string) (Change, error) {
	data, err := readRC(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Change{Path: path}, nil
	}
	if err != nil {
		return Change{}, err
	}
	if _, _, _, found, err := split(data); err != nil || !found {
		return Change{Path: path}, err
	}
	return edit(shell, path, func(b *Block) { b.Wraps = nil })
}

func edit(shell Shell, path string, fn func(*Block)) (Change, error) {
	target, err := resolveRC(path)
	if err != nil {
		return Change{}, err
	}
	data, err := readRC(target)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Change{}, err
	}
	before, block, after, found, err := split(data)
	if err != nil {
		return Change{}, fmt.Errorf("%w in %s; remove the lines from %q to %q by hand", err, target, BeginMarker, EndMarker)
	}
	b := parse(block)
	fn(&b)
	rendered, err := Render(shell, b)
	if err != nil {
		return Change{}, err
	}
	var out []byte
	switch {
	case found:
		if rendered == "" && bytes.HasSuffix(before, []byte("\n\n")) {
			// Drop the blank line Enable put in front of the block.
			before = before[:len(before)-1]
		}
		out = append(append(append(out, before...), rendered...), after...)
	case rendered == "":
		return Change{Path: target, Block: b}, nil
	default:
		out = append(out, data...)
		if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
			out = append(out, '\n')
		}
		if len(out) > 0 {
			out = append(out, '\n')
		}
		out = append(out, rendered...)
	}
	if exists && bytes.Equal(out, data) {
		return Change{Path: target, Block: b}, nil
	}
	if err := writeRC(target, out, exists); err != nil {
		return Change{}, err
	}
	return Change{Path: target, Changed: true, Block: b}, nil
}

// resolveRC follows a symlinked rc file (dotfile managers) to the file it
// names, so the edit lands there instead of replacing the link.
func resolveRC(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("wrapper: rc path %q is not absolute", path)
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return path, nil
	case err != nil:
		return "", err
	case info.Mode()&fs.ModeSymlink != 0:
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", fmt.Errorf("wrapper: %s is a dangling symlink: %w", path, err)
		}
		return real, nil
	case !info.Mode().IsRegular():
		return "", fmt.Errorf("wrapper: %s is not a regular file", path)
	}
	return path, nil
}

func readRC(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("wrapper: %s is not a regular file", path)
	}
	if info.Size() > maxRCBytes {
		return nil, fmt.Errorf("wrapper: %s is larger than %d bytes", path, maxRCBytes)
	}
	buf := make([]byte, 0, info.Size())
	b := bytes.NewBuffer(buf)
	if _, err := b.ReadFrom(f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeRC replaces path atomically, keeping an existing file's mode.
func writeRC(path string, data []byte, exists bool) error {
	mode := fs.FileMode(0o644)
	if exists {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode = info.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".defenseclaw-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// shellQuote single-quotes s for a POSIX shell and fish.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellUnquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], `'\''`, "'")
	}
	return s
}

// Installed is one rc file that carries wrappers.
type Installed struct {
	Shell Shell
	Path  string
	Block Block
	Err   error
}

// Scan reads the wrapper block of every supported shell's rc file under home.
// Files without a block are left out.
func Scan(home string, getenv func(string) string) []Installed {
	var out []Installed
	for _, sh := range Shells {
		p, err := RCPath(sh, home, getenv)
		if err != nil {
			continue
		}
		b, err := Read(p)
		if err == nil && len(b.Wraps) == 0 {
			continue
		}
		out = append(out, Installed{Shell: sh, Path: p, Block: b, Err: err})
	}
	return out
}

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

package sandboxcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

const (
	ansiBold   = "\x1b[1m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiDim    = "\x1b[90m"
	ansiReset  = "\x1b[0m"
)

func (a *App) style(text string, codes ...string) string {
	if !a.IO.Color || len(codes) == 0 {
		return text
	}
	return strings.Join(codes, "") + text + ansiReset
}

func (a *App) bold(s string) string { return a.style(s, ansiBold) }
func (a *App) dim(s string) string  { return a.style(s, ansiDim) }

// The helpers below print human-readable text through terminalText: the
// agent names the files, branches, commands and hosts that reach the
// review, the summary and the prompts. JSON output (writeJSON) and the
// harness's own streams do not go through them.

func (a *App) printf(format string, args ...any) {
	fmt.Fprint(a.IO.Out, terminalText(fmt.Sprintf(format, args...)))
}
func (a *App) println(args ...any) { fmt.Fprint(a.IO.Out, terminalText(fmt.Sprintln(args...))) }

// line prints one indented line.
func (a *App) line(text string) { fmt.Fprintln(a.IO.Out, terminalText("  "+text)) }

// maxPathText is the most of a file name the workload chose that a list
// prints (pathText).
const maxPathText = 160

// pathText is a file name the workload chose as a list prints it: on one
// line, with its control characters escaped as Go writes them (\n, \t,
// \x1b), every other unsafe character as U+FFFD (sandboxapi.DisplayText),
// and a long name cut in the middle, so a hostile name cannot forge lines
// of the review a user trusts before bringing the work back (GAP-0291).
func pathText(p string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(p, string(utf8.RuneError)) {
		if r < 0x20 || r == 0x7f {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	s := sandboxapi.DisplayText(b.String())
	if rs := []rune(s); len(rs) > maxPathText {
		s = string(rs[:maxPathText/2]) + "…" + string(rs[len(rs)-maxPathText/2+1:])
	}
	return s
}

// pathTexts is pathText of every name.
func pathTexts(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = pathText(p)
	}
	return out
}

// palette are the escape sequences this file prints itself.
var palette = []string{ansiBold, ansiCyan, ansiGreen, ansiYellow, ansiRed, ansiDim, ansiReset}

// terminalText makes text safe to print on a terminal: newlines, tabs and
// the palette's color codes pass, and every other control character (an
// escape sequence that clears the screen, moves the cursor, sets the title
// or writes the clipboard; a carriage return that overwrites a line), C1
// control, bidirectional override and invalid byte prints as U+FFFD
// (sandboxapi.DisplayText).
func terminalText(s string) string {
	if plainText(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	start := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '\n', '\t':
			b.WriteString(sandboxapi.DisplayText(s[start:i]))
			b.WriteByte(s[i])
			i++
			start = i
			continue
		case 0x1b:
			if code := paletteCode(s[i:]); code != "" {
				b.WriteString(sandboxapi.DisplayText(s[start:i]))
				b.WriteString(code)
				i += len(code)
				start = i
				continue
			}
		}
		i++
	}
	b.WriteString(sandboxapi.DisplayText(s[start:]))
	return b.String()
}

func paletteCode(s string) string {
	for _, code := range palette {
		if strings.HasPrefix(s, code) {
			return code
		}
	}
	return ""
}

// plainText reports text of printable ASCII, newlines and tabs only.
func plainText(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x7f || (c < 0x20 && c != '\n' && c != '\t') {
			return false
		}
	}
	return true
}

func (a *App) ok(text string)   { a.line(a.style("✓", ansiGreen, ansiBold) + " " + text) }
func (a *App) warn(text string) { a.line(a.style("⚠", ansiYellow, ansiBold) + " " + text) }
func (a *App) bad(text string)  { a.line(a.style("✗", ansiRed, ansiBold) + " " + text) }
func (a *App) note(text string) { a.line(a.dim(text)) }

// warnErr prints a warning to stderr (while a harness owns stdout).
func (a *App) warnErr(text string) {
	fmt.Fprintln(a.IO.Err, terminalText(a.style("⚠", ansiYellow, ansiBold)+" "+text))
}

func (a *App) mark(ok bool) string {
	if ok {
		return a.style("✓", ansiGreen)
	}
	return a.style("✗", ansiRed)
}

// table writes aligned columns.
func (a *App) table(header []string, rows [][]string) {
	w := tabwriter.NewWriter(a.IO.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, r := range rows {
		// A tab or newline in a cell would break the columns.
		fmt.Fprintln(w, strings.Join(sandboxapi.DisplayTexts(r), "\t"))
	}
	_ = w.Flush()
}

// writeJSON prints v as indented JSON.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// OutputFormat is --output.
type OutputFormat string

const (
	OutputText OutputFormat = "text"
	OutputJSON OutputFormat = "json"
)

// jsonOutput prepares a command that talks to the user before its result:
// with -o json it returns stdout, kept for the one JSON document the
// command prints, and until restore runs every human-readable line
// (progress, the preview a prompt asks about, the prompt, warnings) goes to
// stderr. For text output it returns a nil writer and changes nothing.
func (a *App) jsonOutput(format OutputFormat) (stdout io.Writer, restore func()) {
	a.defaults()
	if format != OutputJSON {
		return nil, func() {}
	}
	out := a.IO.Out
	a.IO.Out = a.IO.Err
	return out, func() { a.IO.Out = out }
}

// ParseOutput validates --output.
func ParseOutput(s string) (OutputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text", "table":
		return OutputText, nil
	case "json":
		return OutputJSON, nil
	}
	return "", fmt.Errorf("--output must be text or json, not %q", s)
}

// ErrNoTerminal refuses a prompt without a terminal. Every command that
// asks takes --yes (internal/cli pins that).
var ErrNoTerminal = errors.New("this needs an answer but there is no terminal; pass --yes to accept the defaults")

// ask asks a yes/no question. Without a terminal it returns def when
// allowed, else ErrNoTerminal.
func (a *App) ask(question string, def bool, assumeDefault bool) (bool, error) {
	a.defaults()
	if assumeDefault {
		return def, nil
	}
	if !a.IO.TTY {
		return false, ErrNoTerminal
	}
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprint(a.IO.Out, terminalText(question+" "+a.dim(hint)+" "))
		ans, err := a.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(ans) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(a.IO.Out, terminalText(a.dim("answer y or n")))
	}
}

// confirm asks before a destructive step; yes (--yes) answers it.
func (a *App) confirm(question string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	return a.ask(question, false, false)
}

// choice is one answer of choose.
type choice struct {
	Key   string
	Label string
}

// errInterrupted is a choice the user answered with Ctrl-C; the caller
// says what that leaves as it is.
var errInterrupted = errors.New("interrupted")

// choose asks for one of choices; an empty answer selects def. An answer
// is a letter and Enter, which the prompt says, and Ctrl-C returns
// errInterrupted instead of ending the process.
func (a *App) choose(question string, choices []choice, def string) (string, error) {
	a.defaults()
	if !a.IO.TTY {
		return def, nil
	}
	var parts []string
	for _, c := range choices {
		label := "[" + c.Key + "] " + c.Label
		if c.Key == def {
			label = "[" + strings.ToUpper(c.Key) + "] " + c.Label
		}
		parts = append(parts, label)
	}
	for {
		fmt.Fprint(a.IO.Out, terminalText(question+" "+strings.Join(parts, "  ")+" "+a.dim("(then Enter)")+" "))
		ans, err := a.readAnswer()
		if err != nil {
			return "", err
		}
		ans = strings.ToLower(ans)
		if ans == "" {
			return def, nil
		}
		keys := make([]string, 0, len(choices))
		for _, c := range choices {
			if ans == c.Key || ans == strings.ToLower(c.Label) {
				return c.Key, nil
			}
			keys = append(keys, c.Key)
		}
		fmt.Fprintln(a.IO.Out, terminalText(a.dim("answer "+strings.Join(keys, ", "))))
	}
}

// lineRead is one line a prompt read.
type lineRead struct {
	s   string
	err error
}

// readAnswer reads a line, or returns errInterrupted when the user presses
// Ctrl-C first. The line an interrupted read was waiting for goes to the
// next prompt.
func (a *App) readAnswer() (string, error) {
	sig, stop := a.interruptSource()
	defer stop()
	// This prompt decides what Ctrl-C means here, not the command's
	// interruptible context (released before sig stops receiving them).
	release := holdSignals()
	defer release()
	ch := a.pending
	a.pending = nil
	if ch == nil {
		ch = make(chan lineRead, 1)
		go func() {
			s, err := a.readLineNow()
			ch <- lineRead{s, err}
		}()
	}
	select {
	case r := <-ch:
		return r.s, r.err
	case <-sig:
		a.pending = ch
		fmt.Fprintln(a.IO.Out)
		return "", errInterrupted
	}
}

// interruptSource delivers Ctrl-C while a prompt waits.
func (a *App) interruptSource() (<-chan os.Signal, func()) {
	if a.interrupts != nil {
		return a.interrupts()
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// page prints text, through a pager when the terminal cannot show it at
// once (a long diff).
func (a *App) page(text string) {
	text = strings.TrimRight(text, "\n")
	pager := a.pager
	if pager == nil {
		pager = a.terminalPager
	}
	if !pager(text) {
		a.println(text)
	}
}

// terminalPager shows text longer than the terminal with $PAGER (default
// `less -FRX`), which gets it made safe for the terminal like every line
// this package prints. It reports false when it did not show it.
func (a *App) terminalPager(text string) bool {
	out, ok := a.IO.Out.(*os.File)
	if !ok || !a.IO.TTY || !term.IsTerminal(int(out.Fd())) {
		return false
	}
	_, rows, err := term.GetSize(int(out.Fd()))
	if err != nil || strings.Count(text, "\n")+1 < rows-2 {
		return false
	}
	argv := strings.Fields(a.Getenv("PAGER"))
	if len(argv) == 0 {
		argv = []string{"less", "-FRX"}
	}
	path, err := a.LookPath(argv[0])
	if err != nil {
		return false
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdin = strings.NewReader(terminalText(text) + "\n")
	cmd.Stdout, cmd.Stderr = out, a.IO.Err
	// A Ctrl-C in the pager is the pager's; this process waits for it.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	return cmd.Run() == nil
}

// readLine reads one answer (the one an interrupted prompt was waiting
// for first). In an interruptible command (interrupt.go) an interrupt ends
// the wait with context.Canceled, so the command's cleanup runs; the read
// stays pending for a later prompt.
func (a *App) readLine() (string, error) {
	if a.pending == nil {
		if a.intr == nil {
			return a.readLineNow()
		}
		ch := make(chan lineRead, 1)
		a.pending = ch
		go func() {
			s, err := a.readLineNow()
			ch <- lineRead{s, err}
		}()
	}
	var done <-chan struct{}
	if a.intr != nil {
		done = a.intr.ctx.Done()
	}
	select {
	case r := <-a.pending:
		a.pending = nil
		return r.s, r.err
	case <-done:
		// The prompt's line ends here; what follows is the cleanup.
		fmt.Fprintln(a.IO.Out)
		return "", context.Canceled
	}
}

func (a *App) readLineNow() (string, error) {
	s, err := a.reader.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		if errors.Is(err, io.EOF) {
			return "", errors.New("no answer (end of input)")
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// tildePath abbreviates the home directory.
func (a *App) tildePath(p string) string {
	home, err := a.Home()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+string(filepath.Separator)) {
		return "~" + p[len(home):]
	}
	return p
}

// tildeText abbreviates the home directory in every path of a message.
func (a *App) tildeText(s string) string {
	home, err := a.Home()
	if err != nil || home == "" || home == string(filepath.Separator) {
		return s
	}
	return strings.ReplaceAll(s, home+string(filepath.Separator), "~"+string(filepath.Separator))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// truncateLeft is truncate keeping the end of s, such as a path's file
// name.
func truncateLeft(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-(n-1):])
}

func humanDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "-"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	default:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// withArticle is name after "a" or "an": "an OpenHands", "a Codex".
func withArticle(name string) string {
	if name != "" && strings.ContainsRune("AEIOUaeiou", rune(name[0])) {
		return "an " + name
	}
	return "a " + name
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

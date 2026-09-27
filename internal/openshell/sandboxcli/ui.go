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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"
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

func (a *App) printf(format string, args ...any) { fmt.Fprintf(a.IO.Out, format, args...) }
func (a *App) println(args ...any)               { fmt.Fprintln(a.IO.Out, args...) }

// line prints one indented line.
func (a *App) line(text string) { fmt.Fprintln(a.IO.Out, "  "+text) }

func (a *App) ok(text string)   { a.line(a.style("✓", ansiGreen, ansiBold) + " " + text) }
func (a *App) warn(text string) { a.line(a.style("⚠", ansiYellow, ansiBold) + " " + text) }
func (a *App) bad(text string)  { a.line(a.style("✗", ansiRed, ansiBold) + " " + text) }
func (a *App) note(text string) { a.line(a.dim(text)) }

// warnErr prints a warning to stderr (while a harness owns stdout).
func (a *App) warnErr(text string) {
	fmt.Fprintln(a.IO.Err, a.style("⚠", ansiYellow, ansiBold)+" "+text)
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
		fmt.Fprintln(w, strings.Join(r, "\t"))
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

// ErrNoTerminal refuses a prompt without a terminal.
var ErrNoTerminal = errors.New("this needs an answer but there is no terminal; pass --yes (or --non-interactive) to accept the defaults")

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
		fmt.Fprintf(a.IO.Out, "%s %s ", question, a.dim(hint))
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

// choose asks for one of choices; an empty answer selects def.
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
		fmt.Fprintf(a.IO.Out, "%s %s ", question, strings.Join(parts, "  "))
		ans, err := a.readLine()
		if err != nil {
			return "", err
		}
		ans = strings.ToLower(ans)
		if ans == "" {
			return def, nil
		}
		for _, c := range choices {
			if ans == c.Key || ans == strings.ToLower(c.Label) {
				return c.Key, nil
			}
		}
	}
}

func (a *App) readLine() (string, error) {
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

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
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

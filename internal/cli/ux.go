// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// ANSI SGR fragments (reset applied once at end of Style).
const (
	ansiBold          = "\x1b[1m"
	ansiFgCyan        = "\x1b[36m"
	ansiFgGreen       = "\x1b[32m"
	ansiFgYellow      = "\x1b[33m"
	ansiFgRed         = "\x1b[31m"
	ansiFgBrightBlack = "\x1b[90m"
	ansiReset         = "\x1b[0m"
)

func envTruthy(key string) bool {
	return strings.TrimSpace(os.Getenv(key)) != ""
}

// ColorEnabled reports whether ANSI styling should be applied.
// Evaluated on each call (no caching) so tests and subprocesses that
// mutate the environment see updates immediately.
//
// Order matches cli/defenseclaw/ux.py::_color_enabled:
//  1. CLICOLOR_FORCE or FORCE_COLOR truthy → true (even when stdout is not a TTY).
//  2. NO_COLOR present in the environment (any value, including empty) → false.
//  3. Otherwise → true iff stdout is a terminal.
func ColorEnabled() bool {
	if envTruthy("CLICOLOR_FORCE") || envTruthy("FORCE_COLOR") {
		return true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fd := int(os.Stdout.Fd())
	return term.IsTerminal(fd)
}

// Style applies zero or more attributes then resets.
// Supported attrs: "bold", "fg=cyan", "fg=green", "fg=yellow", "fg=red", "fg=bright_black".
// When colors are disabled, text is returned unchanged.
func Style(text string, attrs ...string) string {
	if !ColorEnabled() || len(attrs) == 0 {
		return text
	}
	var b strings.Builder
	for _, a := range attrs {
		switch a {
		case "bold":
			b.WriteString(ansiBold)
		default:
			if after, ok := strings.CutPrefix(a, "fg="); ok {
				switch after {
				case "cyan":
					b.WriteString(ansiFgCyan)
				case "green":
					b.WriteString(ansiFgGreen)
				case "yellow":
					b.WriteString(ansiFgYellow)
				case "red":
					b.WriteString(ansiFgRed)
				case "bright_black":
					b.WriteString(ansiFgBrightBlack)
				}
			}
		}
	}
	b.WriteString(text)
	b.WriteString(ansiReset)
	return b.String()
}

// Bold wraps text in bold SGR (no color change).
func Bold(text string) string {
	return Style(text, "bold")
}

// Dim renders text in bright black / gray.
func Dim(text string) string {
	return Style(text, "fg=bright_black")
}

// Accent renders cyan emphasis for inline highlights.
func Accent(text string) string {
	return Style(text, "fg=cyan")
}

// Section prints a bold cyan heading with a cyan underline matching the title width.
func Section(title string) {
	fmt.Println()
	fmt.Println("  " + Style(title, "fg=cyan", "bold"))
	w := utf8.RuneCountInString(title)
	fmt.Println("  " + Style(strings.Repeat("─", w), "fg=cyan"))
}

// Banner prints a full-width "── Title ──…──" line (~54 cols) plus a trailing blank line.
func Banner(title string) {
	fmt.Println()
	const width = 54
	const indent = "  "
	label := fmt.Sprintf(" %s ", title)
	side := max(2, (width-len(label))/2)
	left := strings.Repeat("─", side)
	right := strings.Repeat("─", width-side-len(label))
	if ColorEnabled() {
		fmt.Printf("%s%s %s %s\n", indent, Dim(left), Style(title, "fg=cyan", "bold"), Dim(right))
	} else {
		fmt.Printf("%s%s%s%s\n", indent, left, label, right)
	}
	fmt.Println()
}

// Subhead prints one dim explanatory line.
func Subhead(text string) {
	fmt.Println("  " + Dim(text))
}

// OK prints a green success marker line.
func OK(text string) {
	fmt.Printf("  %s %s\n", Style("✓", "fg=green", "bold"), text)
}

// Warn prints a yellow warning marker line.
func Warn(text string) {
	fmt.Printf("  %s %s\n", Style("⚠", "fg=yellow", "bold"), Style(text, "fg=yellow"))
}

// Err prints a red error marker line (stdout; matches Python ux.err convention).
func Err(text string) {
	fmt.Printf("  %s %s\n", Style("✗", "fg=red", "bold"), Style(text, "fg=red"))
}

// KV prints a dim bold key column and a plain value (30-char label column, 4-space indent).
func KV(key string, value any) {
	const indent = "    "
	const keyWidth = 30
	textValue := ""
	if value != nil {
		textValue = fmt.Sprint(value)
	}
	rendered := textValue
	if rendered == "" {
		rendered = Dim("—")
	}
	label := fmt.Sprintf("%-*s", keyWidth, key+":")
	fmt.Printf("%s%s %s\n", indent, Style(label, "fg=bright_black", "bold"), rendered)
}

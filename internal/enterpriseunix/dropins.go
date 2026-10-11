// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// codeUnitDropIn names local systemd drop-ins on the DefenseClaw units that
// keep the units' identity, sandbox and inputs (a site proxy, say).
const codeUnitDropIn = "unit_drop_in"

// dropInReporter is implemented by service managers that list the drop-in
// files systemd merged into a unit.
type dropInReporter interface {
	DropInPaths(ctx context.Context, unit Unit) []string
}

// DropInPaths lists the drop-ins systemd merged into the unit, global ones
// (service.d) included.
func (m *systemdManager) DropInPaths(ctx context.Context, unit Unit) []string {
	return strings.Fields(m.properties(ctx, unit.Name, "DropInPaths")["DropInPaths"])
}

// dropInKeepKeys are the drop-in settings that leave a DefenseClaw unit's
// identity, sandbox and inputs as installed: unit ordering and text,
// resource limits, restart and timeout tuning, and environment for the host
// (proxies, CA bundles). Any other setting in a drop-in DefenseClaw did not
// write changes who the unit runs as, what it runs or what it can reach.
var dropInKeepKeys = map[string]bool{
	"Description": true, "Documentation": true, "After": true, "Before": true, "Wants": true,
	"Environment": true,
	"Nice":        true, "CPUWeight": true, "CPUQuota": true, "CPUShares": true, "AllowedCPUs": true, "CPUAffinity": true,
	"MemoryMax": true, "MemoryHigh": true, "MemoryLow": true, "MemoryMin": true, "MemoryLimit": true, "MemorySwapMax": true,
	"TasksMax": true, "IOWeight": true, "IOSchedulingClass": true, "IOSchedulingPriority": true,
	"LimitNOFILE": true, "LimitNPROC": true, "LimitCORE": true, "LimitMEMLOCK": true, "OOMScoreAdjust": true,
	"Restart": true, "RestartSec": true, "TimeoutSec": true, "TimeoutStartSec": true, "TimeoutStopSec": true,
	"StartLimitIntervalSec": true, "StartLimitBurst": true,
	"LogLevelMax": true, "LogRateLimitIntervalSec": true, "LogRateLimitBurst": true, "SyslogIdentifier": true,
}

// dropInEnvironmentRefused reports an Environment= variable a drop-in must
// not set: DefenseClaw's own pins (the config, the data directory, the
// deployment mode) and loader variables.
func dropInEnvironmentRefused(name string) bool {
	upper := strings.ToUpper(name)
	return strings.HasPrefix(upper, "DEFENSECLAW_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "GODEBUG")
}

// dropInEnvironmentReset names an Environment= with no assignment: systemd
// then drops every Environment= set before it, the managed pins of the unit
// (DEFENSECLAW_CONFIG, DEFENSECLAW_HOME, the deployment mode) included
// (GAP-1380).
const dropInEnvironmentReset = "an empty Environment=, which clears the unit's DEFENSECLAW_* pins"

// dropInChanges returns the settings of a drop-in that change what the unit
// is (Key, Environment=NAME for a refused variable, or
// dropInEnvironmentReset). It reads the file as systemd does: continuation
// lines joined, and each Environment= value split into words with quotes
// and C escapes decoded. Read as raw text, Environment=DEFENSECLAW\x5fCONFIG=
// or DEFENSECLAW"_"CONFIG= set DEFENSECLAW_CONFIG unseen (GAP-1459).
// EnvironmentFile= and PassEnvironment= are not kept settings, so a drop-in
// with either is named whatever it lists.
func dropInChanges(data []byte) []string {
	seen := map[string]bool{}
	for _, line := range systemdLines(data) {
		if strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !dropInKeepKeys[key] {
			seen[key] = true
			continue
		}
		if key != "Environment" {
			continue
		}
		if value == "" {
			seen[dropInEnvironmentReset] = true
		}
		for _, assignment := range systemdWords(value) {
			// systemd resolves a specifier (%) in a name; refuse one.
			if name, _, ok := strings.Cut(assignment, "="); ok && (dropInEnvironmentRefused(name) || strings.Contains(name, "%")) {
				seen["Environment="+name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// systemdLines are the logical lines of a unit file, trimmed, as systemd's
// parser reads them: a line that ends in an unescaped backslash continues on
// the next with the backslash read as a space, and comment lines (# or ;)
// are skipped, inside a continuation too.
func systemdLines(data []byte) []string {
	var lines []string
	pending := ""
	for _, raw := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if (len(raw)-len(strings.TrimRight(raw, `\`)))%2 == 1 {
			pending += raw[:len(raw)-1] + " "
			continue
		}
		if line := strings.TrimSpace(pending + raw); line != "" {
			lines = append(lines, line)
		}
		pending = ""
	}
	if line := strings.TrimSpace(pending); line != "" {
		lines = append(lines, line)
	}
	return lines
}

// systemdWords splits an Environment= value into its assignments as systemd
// does (extract_first_word with EXTRACT_UNQUOTE and EXTRACT_CUNESCAPE):
// words are separated by whitespace, single and double quotes anywhere in a
// word are removed and keep the text between them in the word, and backslash
// escapes are decoded. An escape systemd rejects is read as its character,
// so a name is never read as less than systemd could make of it.
func systemdWords(value string) []string {
	var words []string
	var word strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\\':
			decoded, n := systemdUnescape(value[i+1:])
			word.WriteString(decoded)
			i += n
			inWord = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, inWord = c, true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

// systemdSimpleEscapes are the one-letter escapes of systemd's cunescape_one.
var systemdSimpleEscapes = map[byte]string{'a': "\a", 'b': "\b", 'f': "\f", 'n': "\n", 'r': "\r", 't': "\t", 'v': "\v", 's': " "}

// systemdUnescape decodes the escape after a backslash at the start of rest
// (systemd's cunescape_one): \a \b \f \n \r \t \v \s, \xNN, \NNN octal,
// \uNNNN and \UNNNNNNNN; any other character (\\, \", \') stands for itself.
// It returns the text and how many bytes of rest it used.
func systemdUnescape(rest string) (string, int) {
	if rest == "" {
		return "", 0
	}
	if decoded, ok := systemdSimpleEscapes[rest[0]]; ok {
		return decoded, 1
	}
	var skip, digits, base int
	switch c := rest[0]; {
	case c == 'x':
		skip, digits, base = 1, 2, 16
	case c == 'u':
		skip, digits, base = 1, 4, 16
	case c == 'U':
		skip, digits, base = 1, 8, 16
	case c >= '0' && c <= '7':
		skip, digits, base = 0, 3, 8
	}
	if end := skip + digits; digits > 0 && len(rest) >= end {
		if n, err := strconv.ParseUint(rest[skip:end], base, 32); err == nil {
			if digits >= 4 {
				return string(rune(n)), end
			}
			if n < 256 {
				return string([]byte{byte(n)}), end
			}
		}
	}
	return rest[:1], 1
}

// unitDropIns reviews the drop-ins of the DefenseClaw units that the
// deployment did not write (GAP-0474). problems are the drop-ins that change
// a unit's identity, sandbox or inputs (User=root, ProtectHome=false, another
// DEFENSECLAW_CONFIG), each named with the settings; overrides are the
// others, which the docs allow for host-specific settings.
func (l *lifecycle) unitDropIns(ctx context.Context, record *Deployment) (problems, overrides []string) {
	env := l.env
	reporter, ok := env.Services.(dropInReporter)
	if !ok {
		return nil, nil
	}
	listed := map[string]bool{}
	for _, unit := range env.Services.Units() {
		for _, path := range reporter.DropInPaths(ctx, unit) {
			if _, ours := record.Files[path]; ours || listed[path] {
				continue
			}
			listed[path] = true
			data, err := readBounded(env.P(path), maxInputBytes)
			if err != nil {
				problems = append(problems, fmt.Sprintf("cannot read the drop-in %s on %s: %v", path, unit.Name, err))
				continue
			}
			if changes := dropInChanges(data); len(changes) > 0 {
				problems = append(problems, fmt.Sprintf("the drop-in %s changes %s (%s), which DefenseClaw does not allow; remove it or those settings, run `systemctl daemon-reload` and `%s`",
					path, unit.Name, strings.Join(changes, ", "), env.lifecycleCommand("repair")))
				continue
			}
			overrides = append(overrides, path)
		}
	}
	return problems, overrides
}

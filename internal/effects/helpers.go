// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// stripWrappers peels known launchers (sudo, env, nohup, timeout, xargs, ...)
// off the front of a command, returning the inner argv, the stripped wrapper
// names, and whether the inner command runs in a foreign context or takes its
// operands from input (review R5, P2).
func (w *walker) stripWrappers(words []Word) (inner []Word, wrappers []string, foreign, fromInput bool) {
	i := 0
	for i < len(words) {
		wd := words[i]
		if !wd.Static {
			break
		}
		name := programBasename(wd.Value, w.o.flavor())
		kind, ok := wrapperPrograms[name]
		if !ok {
			break
		}
		wrappers = append(wrappers, name)
		switch kind {
		case wrapForeign:
			foreign = true
		case wrapInput:
			fromInput = true
		}
		// Skip the wrapper's own options up to the inner program. env VAR=val and
		// env -u NAME: skip assignments and -flags; sudo -u user: skip -flags.
		i++
		for i < len(words) {
			nw := words[i]
			if nw.Static && (strings.HasPrefix(nw.Value, "-") || (name == "env" && strings.Contains(nw.Value, "="))) {
				if name == "env" && nw.Value == "-C" && i+1 < len(words) {
					i++ // skip the dir value too
				}
				i++
				continue
			}
			break
		}
		if name == "ssh" || name == "chroot" {
			// ssh host 'cmd' / chroot dir cmd: skip the host/dir operand.
			if i < len(words) {
				i++
			}
		}
	}
	return words[i:], wrappers, foreign, fromInput
}

// programBasename takes the basename of a program path and folds case for the
// Windows flavor (program names are case-insensitive there).
func programBasename(p string, flavor Flavor) string {
	sep := "/"
	if flavor == FlavorWindows {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	if idx := strings.LastIndex(p, sep); idx >= 0 {
		p = p[idx+1:]
	}
	if flavor == FlavorWindows {
		p = strings.ToLower(p)
		p = strings.TrimSuffix(p, ".exe")
		p = strings.TrimSuffix(p, ".cmd")
		p = strings.TrimSuffix(p, ".bat")
	}
	return p
}

// flagLookup finds a flag in a table row, honouring --flag=value and, for
// PowerShell, case-insensitive parameter names.
func flagLookup(p Program, name string, dialect Dialect) (Flag, bool) {
	key := name
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		key = name[:eq]
	}
	if dialect == DialectPowerShell {
		key = strings.ToLower(key)
	}
	fl, ok := p.Flags[key]
	if ok {
		// a --flag=value form carries its value inline; mark as not needing the
		// next token.
		if strings.IndexByte(name, '=') >= 0 {
			fl.Value = false // value is inline; caller handles via the name itself
		}
	}
	return fl, ok
}

// collectExecArgv gathers the words of a find -exec / xargs program up to a
// terminating ; or + (find) or end.
func collectExecArgv(words []Word) []Word {
	var out []Word
	for _, wd := range words {
		if wd.Static && (wd.Value == ";" || wd.Value == "+" || wd.Value == "\\;") {
			break
		}
		out = append(out, wd)
	}
	return out
}

// uploadPath extracts the local file from a curl upload operand: -F name=@file,
// -T file, --data-binary @file.
func uploadPath(v string) string {
	if at := strings.LastIndex(v, "@"); at >= 0 {
		return v[at+1:]
	}
	if eq := strings.IndexByte(v, '='); eq >= 0 {
		return "" // a form field with no @file is inline data, not a file
	}
	return v
}

// parseURL splits a URL into scheme, host and port without net/url (keeps the
// package dependency-free). Returns empty host for a non-URL.
func parseURL(u string) (scheme, host string, port int) {
	s := u
	if idx := strings.Index(s, "://"); idx >= 0 {
		scheme = s[:idx]
		s = s[idx+3:]
	} else {
		return "", "", 0
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		if n, ok := atoiSafe(s[idx+1:]); ok {
			port = n
			s = s[:idx]
		}
	}
	return scheme, s, port
}

func cap4k(s string) string {
	if len(s) > maxSpellingBytes {
		return s[:maxSpellingBytes]
	}
	return s
}

func cap8k(s string) string {
	if len(s) > maxDataText {
		return s[:maxDataText]
	}
	return s
}

// inferDialect picks a grammar when none is forced: the Options flavor's
// default, with a light syntactic sniff for PowerShell/cmd on Windows.
func inferDialect(call Call, o Options) Dialect {
	if o.flavor() == FlavorWindows {
		c := call.Command
		if looksPowerShell(c) {
			return DialectPowerShell
		}
		return DialectCMD
	}
	return DialectPOSIX
}

func looksPowerShell(c string) bool {
	lc := strings.ToLower(c)
	for _, s := range []string{"-command", "invoke-", "get-", "set-", "new-item", "$env:", "| out-", "-itemtype"} {
		if strings.Contains(lc, s) {
			return true
		}
	}
	return strings.Contains(c, "$") && strings.Contains(c, "-")
}

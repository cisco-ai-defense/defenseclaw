// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// wrapperSpec says how to skip a launcher's own options so the inner program is
// found correctly (review PX-7): which flags consume a value, how many leading
// positionals to skip (timeout DURATION, ssh host, chroot dir), and whether
// NAME=val assignments precede the program (env).
type wrapperSpec struct {
	kind      wrapperKind
	valFlags  map[string]bool
	posSkip   int
	envAssign bool
}

var wrapperSpecs = map[string]wrapperSpec{
	"sudo":    {kind: wrapIdentity, valFlags: set("-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "--user", "--group")},
	"doas":    {kind: wrapIdentity, valFlags: set("-u", "-C")},
	"su":      {kind: wrapIdentity, valFlags: set("-s", "-c", "--shell")},
	"env":     {kind: wrapPlain, valFlags: set("-u", "-C", "--unset", "--chdir"), envAssign: true},
	"nohup":   {kind: wrapPlain},
	"setsid":  {kind: wrapPlain},
	"nice":    {kind: wrapPlain, valFlags: set("-n", "--adjustment")},
	"ionice":  {kind: wrapPlain, valFlags: set("-c", "-n", "-p")},
	"timeout": {kind: wrapPlain, valFlags: set("-s", "-k", "--signal", "--kill-after"), posSkip: 1},
	"stdbuf":  {kind: wrapPlain, valFlags: set("-i", "-o", "-e")},
	"command": {kind: wrapPlain},
	"builtin": {kind: wrapPlain},
	"exec":    {kind: wrapPlain, valFlags: set("-a")},
	"time":    {kind: wrapPlain},
	"xargs":   {kind: wrapInput, valFlags: set("-n", "-I", "-i", "-P", "-a", "-s", "-L", "-d", "-E", "--max-args", "--replace", "--max-procs")},
	"chroot":  {kind: wrapForeign, posSkip: 1},
	"ssh":     {kind: wrapForeign, valFlags: set("-i", "-p", "-o", "-l", "-F", "-L", "-R", "-D", "-b", "-c", "-m", "-O", "-Q", "-w", "-e", "-J", "-W"), posSkip: 1},
	"wsl":     {kind: wrapForeign, valFlags: set("-u", "-d", "--user", "--distribution"), envAssign: false},
}

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// stripWrappers peels known launchers off the front, returning the inner argv,
// the stripped wrapper names, and whether the inner command runs in a foreign
// context or takes its operands from input.
func (w *walker) stripWrappers(words []Word) (inner []Word, wrappers []string, foreign, fromInput bool) {
	i := 0
	for i < len(words) {
		wd := words[i]
		if !wd.Static {
			break
		}
		name := programBasename(wd.Value, w.o.flavor())
		spec, ok := wrapperSpecs[name]
		if !ok {
			break
		}
		wrappers = append(wrappers, name)
		switch spec.kind {
		case wrapForeign:
			foreign = true
		case wrapInput:
			fromInput = true
		}
		i++
		// consume this wrapper's own flags and env assignments.
		for i < len(words) {
			nw := words[i]
			if !nw.Static {
				break
			}
			v := nw.Value
			if v == "--" {
				i++
				break
			}
			if spec.envAssign && strings.Contains(v, "=") && !strings.HasPrefix(v, "-") {
				i++
				continue
			}
			if strings.HasPrefix(v, "-") && v != "-" {
				fn := v
				if eq := strings.IndexByte(v, '='); eq > 0 {
					fn = v[:eq]
					i++
					continue
				}
				i++
				if spec.valFlags[fn] && i < len(words) {
					i++ // consume the flag's value
				}
				continue
			}
			break
		}
		// skip leading positionals (DURATION, host, dir).
		for s := 0; s < spec.posSkip && i < len(words); s++ {
			i++
		}
	}
	return words[i:], wrappers, foreign, fromInput
}

// programBasename takes the basename of a program path and folds case for
// Windows (program names are case-insensitive there).
func programBasename(p string, flavor Flavor) string {
	if flavor == FlavorWindows {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		p = p[idx+1:]
	}
	if flavor == FlavorWindows {
		p = strings.ToLower(p)
		for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1", ".com"} {
			p = strings.TrimSuffix(p, ext)
		}
	}
	return p
}

// flagLookup finds a flag in a table row. For PowerShell it matches case-
// insensitively and by unambiguous parameter prefix (review PS-2).
func flagLookup(p Program, name string, dialect Dialect) (Flag, bool) {
	key := name
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		key = name[:eq]
	}
	if dialect == DialectPowerShell {
		key = strings.ToLower(key)
		if fl, ok := p.Flags[key]; ok {
			return fl, true
		}
		// unambiguous prefix: -dest -> -destination
		var match string
		n := 0
		for fn := range p.Flags {
			if strings.HasPrefix(fn, key) {
				match = fn
				n++
			}
		}
		if n == 1 {
			return p.Flags[match], true
		}
		return Flag{}, false
	}
	fl, ok := p.Flags[key]
	return fl, ok
}

func collectExecArgv(words []Word) []Word {
	var out []Word
	for _, wd := range words {
		if wd.Static && (wd.Value == ";" || wd.Value == "+" || wd.Value == `\;`) {
			break
		}
		out = append(out, wd)
	}
	return out
}

// uploadPath extracts the local file from a curl upload operand: -F name=@file,
// -T file, --data-binary @file. ok is false when the value carries no file
// (inline data). A trailing ;type=... on a -F @file is stripped (review PT-5).
func uploadPath(v string) (string, bool) {
	if at := strings.LastIndex(v, "@"); at >= 0 {
		p := v[at+1:]
		if semi := strings.IndexByte(p, ';'); semi >= 0 {
			p = p[:semi]
		}
		if p == "" {
			return "", false
		}
		return p, true
	}
	if strings.IndexByte(v, '=') >= 0 {
		return "", false // a form field with inline data, not a file
	}
	// -T/--upload-file give a bare path (no @).
	return v, true
}

// parseURL splits a URL with an explicit scheme into scheme, host and port.
func parseURL(u string) (scheme, host string, port int) {
	s := u
	idx := strings.Index(s, "://")
	if idx < 0 {
		return "", "", 0
	}
	scheme = s[:idx]
	s = s[idx+3:]
	host, port = splitHostPort(s)
	return scheme, host, port
}

// urlHost returns the host of a schemeless URL-ish operand (evil.example/x,
// host:8080/y). ok is false when the operand does not look like a host.
func urlHost(s string) (string, bool) {
	if strings.Contains(s, "://") {
		_, h, _ := parseURL(s)
		return h, h != ""
	}
	host, _ := splitHostPort(s)
	if host == "" {
		return "", false
	}
	// a host must contain a dot or a port, and no shell/path oddities.
	if strings.Contains(host, ".") || strings.Contains(s, ":") {
		if !strings.ContainsAny(host, ` \`) {
			return host, true
		}
	}
	return "", false
}

func splitHostPort(s string) (string, int) {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	port := 0
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if n, ok := atoiSafe(s[i+1:]); ok {
			port = n
			s = s[:i]
		}
	}
	return s, port
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

// inferDialect picks a grammar when none is forced.
func inferDialect(call Call, o Options) Dialect {
	if o.flavor() == FlavorWindows {
		if looksPowerShell(call.Command) {
			return DialectPowerShell
		}
		return DialectCMD
	}
	return DialectPOSIX
}

func looksPowerShell(c string) bool {
	lc := strings.ToLower(c)
	for _, s := range []string{"-command", "invoke-", "get-", "set-", "new-item", "remove-item", "$env:", "| out-", "-itemtype", "start-process"} {
		if strings.Contains(lc, s) {
			return true
		}
	}
	return strings.Contains(c, "$") && strings.Contains(c, "-")
}

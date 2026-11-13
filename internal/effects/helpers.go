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
	// shorts lists the single-letter switches the wrapper accepts. Any other
	// short flag may take a value we cannot see, so it is unaccounted (the
	// wrapper allowlist is closed, round 8 G).
	shorts string
}

// The wrapper table is an allowlist: a launcher not listed here is the inner
// program itself and, being unmodeled, is not fully known. A listed wrapper is
// transparent only for the options named here.
var wrapperSpecs = map[string]wrapperSpec{
	"sudo":    {kind: wrapIdentity, valFlags: set("-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "--user", "--group", "--chdir"), shorts: "AbEeHiKklnPSsVvB"},
	"doas":    {kind: wrapIdentity, valFlags: set("-u", "-C"), shorts: "nsL"},
	"env":     {kind: wrapPlain, valFlags: set("-u", "-C", "--unset", "--chdir"), envAssign: true, shorts: "i0v"},
	"nohup":   {kind: wrapPlain},
	"setsid":  {kind: wrapPlain, shorts: "cfw"},
	"nice":    {kind: wrapPlain, valFlags: set("-n", "--adjustment")},
	"ionice":  {kind: wrapPlain, valFlags: set("-c", "-n", "-p"), shorts: "t"},
	"timeout": {kind: wrapPlain, valFlags: set("-s", "-k", "--signal", "--kill-after"), posSkip: 1, shorts: "fpv"},
	"stdbuf":  {kind: wrapPlain, valFlags: set("-i", "-o", "-e")},
	"command": {kind: wrapPlain, shorts: "pvV"},
	"builtin": {kind: wrapPlain},
	"exec":    {kind: wrapPlain, valFlags: set("-a"), shorts: "cl"},
	"time":    {kind: wrapPlain, shorts: "pv"},
	"xargs":   {kind: wrapInput, valFlags: set("-n", "-I", "-i", "-P", "-a", "-s", "-L", "-d", "-E", "--max-args", "--replace", "--max-procs"), shorts: "0rtpxo"},
	"chroot":  {kind: wrapForeign, posSkip: 1},
	"ssh":     {kind: wrapForeign, valFlags: set("-i", "-p", "-o", "-l", "-F", "-L", "-R", "-D", "-b", "-c", "-m", "-O", "-Q", "-w", "-e", "-J", "-W"), posSkip: 1, shorts: "46AaCfGgKkMNnqsTtVvXxYy"},
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
// context or takes its operands from input. It also records on w.spec the
// environment and working-directory changes the wrappers apply to the child
// they start (env -i / -u / NAME=val, sudo's environment reset, sudo -i), so
// nested code is walked with the child's environment, not the shell's
// (round 8 E, G).
func (w *walker) stripWrappers(words []Word) (inner []Word, wrappers []string, foreign, fromInput, unaccounted bool) {
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
		case wrapIdentity:
			// sudo / doas reset the environment (HOME becomes the target user's):
			// nothing the shell knows reaches the child, unless -E keeps it (and
			// even then HOME is not trusted). The flags below refine this.
			w.spec.clear = true
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
				// env NAME=val sets the child's environment; CDPATH also changes how
				// a relative cd inside it resolves -> dynamic (review 6 B, V4).
				eq := strings.IndexByte(v, '=')
				if v[:eq] == "CDPATH" {
					w.cdpathMaybeSet = true
				}
				w.spec.set(v[:eq], v[eq+1:], true)
				i++
				continue
			}
			if strings.HasPrefix(v, "-") && v != "-" {
				fn := v
				inline := ""
				hasInline := false
				if eq := strings.IndexByte(v, '='); eq > 0 {
					fn = v[:eq]
					inline = v[eq+1:]
					hasInline = true
				}
				w.wrapperFlag(name, fn, v, spec, &unaccounted)
				chdirFlag := (name == "env" && (fn == "-C" || fn == "--chdir")) || (name == "sudo" && (fn == "-D" || fn == "--chdir"))
				if hasInline {
					if name == "env" && fn == "--unset" {
						w.spec.set(inline, "", false)
					}
					if chdirFlag {
						w.spec.chdir, w.spec.chdirSet = inline, true
					}
					i++
					continue
				}
				i++
				if spec.valFlags[fn] && i < len(words) {
					if name == "env" && (fn == "-u" || fn == "--unset") && words[i].Static {
						w.spec.set(words[i].Value, "", false)
					}
					if chdirFlag {
						if words[i].Static {
							w.spec.chdir, w.spec.chdirSet = words[i].Value, true
						} else {
							w.spec.cwdDyn = true
						}
					}
					i++ // consume the flag's value
				}
				continue
			}
			if v == "-" && name == "env" {
				w.spec.clear = true // env - is env -i
				i++
				continue
			}
			break
		}
		// skip leading positionals (DURATION, host, dir).
		for s := 0; s < spec.posSkip && i < len(words); s++ {
			i++
		}
	}
	return words[i:], wrappers, foreign, fromInput, unaccounted
}

// wrapperFlag accounts for one wrapper option token (v) with name fn: it marks
// the command unaccounted when the option is outside the wrapper's allowlist
// and applies the options that change the child's environment or directory.
func (w *walker) wrapperFlag(wrapper, fn, v string, spec wrapperSpec, unaccounted *bool) {
	if strings.HasPrefix(fn, "--") {
		if !spec.valFlags[fn] {
			// An unmodeled long wrapper option may change the command's behaviour
			// (cwd, identity, environment): not fully known (review R5-1), except
			// the few switches whose meaning is modeled below.
			switch {
			case wrapper == "env" && fn == "--ignore-environment":
				w.spec.clear = true
			case wrapper == "sudo" && (fn == "--preserve-env" || fn == "--login" || fn == "--set-home" || fn == "--shell" || fn == "--background" || fn == "--non-interactive" || fn == "--reset-timestamp" || fn == "--remove-timestamp" || fn == "--stdin" || fn == "--askpass"):
				w.sudoFlag(fn)
			case wrapper == "xargs" && (fn == "--null" || fn == "--no-run-if-empty" || fn == "--verbose" || fn == "--interactive" || fn == "--exit"):
			case wrapper == "timeout" && (fn == "--foreground" || fn == "--preserve-status" || fn == "--verbose"):
			default:
				*unaccounted = true
			}
		}
		return
	}
	// short option(s)
	body := v[1:]
	if len(body) == 0 {
		return
	}
	if spec.valFlags[v[:2]] && len(v) == 2 {
		return // a valued option; the caller consumes its value
	}
	if wrapper == "env" && v[:2] == "-C" {
		w.spec.chdir, w.spec.chdirSet = v[2:], true // fused -Cdir
		return
	}
	for _, ch := range body {
		if wrapper == "nice" && ch >= '0' && ch <= '9' {
			continue // the legacy `nice -5` adjustment
		}
		if !strings.ContainsRune(spec.shorts, ch) {
			if spec.valFlags["-"+string(ch)] && len(body) == 1 {
				continue
			}
			*unaccounted = true
			continue
		}
		switch {
		case wrapper == "env" && ch == 'i':
			w.spec.clear = true
		case wrapper == "exec" && ch == 'c':
			w.spec.clear = true // exec -c runs the program with an empty environment
		case wrapper == "sudo":
			w.sudoFlag("-" + string(ch))
		}
	}
}

// sudoFlag records the effect of a sudo option on the child it starts.
func (w *walker) sudoFlag(fn string) {
	switch fn {
	case "-E", "--preserve-env":
		w.spec.clear = false
		w.spec.dropHome = true
	case "-i", "--login":
		w.spec.cwdDyn = true
	}
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
	if dialect == DialectCMD && strings.HasPrefix(key, "/") {
		key = strings.ToLower(key) // cmd's own /switches are case-insensitive (curl's -F is not)
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

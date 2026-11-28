// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// wrapperOutput is a file a wrapper itself writes (time -o FILE, the script
// typescript), emitted with the command's own effects.
type wrapperOutput struct {
	word Word
	role Role
}

// stripWrappers peels the wrapper rows of the program table off the front
// (DESIGN D2), returning the inner argv, the stripped wrapper names, and
// whether the inner command runs in a foreign context or takes its operands
// from input. It also records on w.spec the environment and working-folder
// changes the wrappers apply to the child they start (env -i / -u / NAME=val,
// sudo's environment reset, sudo -i, env -C, sudo -D, a login shell through
// exec -a), and on w.wrapOuts the files a wrapper writes itself. A wrapper
// whose child is shell text (script -c, flock -c, watch) hands back the
// child as `sh -c TEXT`, so the shell row reads it like any nested body.
func (w *walker) stripWrappers(words []Word) (inner []Word, wrappers []string, foreign, fromInput, unaccounted bool) {
	w.wrapOuts = w.wrapOuts[:0]
	i := 0
	for i < len(words) {
		wd := words[i]
		if !wd.Static {
			break
		}
		name := programBasename(wd.Value, w.o.flavor())
		row, ok := wrapperTable[name]
		if !ok || !row.applies(words[i+1:]) {
			break
		}
		if row.userOperand {
			p := wrapperParse{w: w, row: row, name: name}
			user := p.options(words, i+1)
			if user < len(words) && words[user].Static && (words[user].Value == "root" || words[user].Value == "0") {
				break // keep the root su form at its existing program-row floor
			}
		}
		start := i
		wrappers = append(wrappers, name)
		switch row.kind {
		case wrapForeign:
			foreign = true
		case wrapInput:
			fromInput = true
		case wrapIdentity:
			// sudo / doas / runuser reset the environment (HOME becomes the target
			// user's): nothing the shell knows reaches the child, unless -E keeps
			// it (and even then HOME is not trusted). The options refine this.
			w.spec.clear = true
		}
		i++
		if row.sub != "" {
			i++ // uv run: the subcommand word
		}
		p := wrapperParse{w: w, row: row, name: name}
		i = p.options(words, i)
		if row.userOperand && i < len(words) {
			if words[i].Static && words[i].Value != "" && !strings.HasPrefix(words[i].Value, "-") {
				p.markForeignUser(words[i])
				i++
				i = p.options(words, i)
			} else if !words[i].Static {
				p.unaccounted = true // an unknown account cannot be graded as a named foreign user
			}
		}
		foreign = foreign || p.foreignUser
		unaccounted = unaccounted || p.unaccounted
		var child []Word
		child, i = p.child(words, i)
		unaccounted = unaccounted || p.unaccounted
		if p.login && i < len(words) && words[i].Static && shellPrograms[programBasename(words[i].Value, w.o.flavor())] {
			w.spec.cwdDyn = true // a login shell reads profile files that may change its folder
		}
		if child != nil {
			if len(child) == 0 {
				// no child we can read (script with no -c, watch with no command):
				// the launcher is the program, unmodeled, so never clean.
				w.wrapOuts = w.wrapOuts[:0]
				return words[start:], wrappers[:len(wrappers)-1], foreign, fromInput, true
			}
			return child, wrappers, foreign, fromInput, unaccounted
		}
		if p.replace != "" {
			words = append(words[:i:i], replacedWords(words[i:], p.replace)...)
		}
	}
	return words[i:], wrappers, foreign, fromInput, unaccounted
}

// wrapperParse reads one wrapper's own words against its row.
type wrapperParse struct {
	w           *walker
	row         Wrapper
	name        string
	unaccounted bool
	login       bool
	appendOut   bool
	foreignUser bool
	shellText   *Word  // the value of a shell-text option (script -c, flock -c)
	execMode    bool   // watch -x: the child words are an argv, not shell text
	replace     string // xargs -I STR: the child words holding STR get a name from input
	outs        []wrapperOutput
}

// options consumes the wrapper's options from words[i:] and returns the index
// of the first word after them. Options end at the first operand: every
// wrapper row reads its child from there (getopt "+" or a builtin).
func (p *wrapperParse) options(words []Word, i int) int {
	row := p.row
	for i < len(words) {
		nw := words[i]
		if !nw.Static {
			// env NAME=$V: the child gets NAME with a value we cannot see; the
			// child word after it is still read (GAP-0972).
			if row.envAssign {
				if n, ok := dynamicAssignName(nw); ok {
					if n == "CDPATH" {
						p.w.cdpathMaybeSet = true
					}
					p.w.spec.set(n, "", false)
					i++
					continue
				}
			}
			break
		}
		v := nw.Value
		if v == "--" {
			return i + 1
		}
		if row.envAssign && strings.Contains(v, "=") && !strings.HasPrefix(v, "-") {
			// env NAME=val sets the child's environment; CDPATH also changes how
			// a relative cd inside it resolves -> dynamic (review 6 B, V4).
			eq := strings.IndexByte(v, '=')
			if v[:eq] == "CDPATH" {
				p.w.cdpathMaybeSet = true
			}
			if row.kind == wrapIdentity {
				// sudo NAME=val: the security policy decides whether the child
				// gets val (env_reset, env_check, SETENV) or the target user's
				// value, so the name is set to a value we cannot see, as for
				// env NAME=$V (rel-1-0-10:GAP-1478).
				p.w.spec.set(v[:eq], "", false)
			} else {
				p.w.spec.set(v[:eq], v[eq+1:], true)
			}
			i++
			continue
		}
		if v == "-" && p.name == "env" {
			p.w.spec.clear = true // env - is env -i
			i++
			continue
		}
		if len(v) < 2 || v[0] != '-' {
			break
		}
		if strings.HasPrefix(v, "--") {
			i = p.long(words, i)
			continue
		}
		i = p.shorts(words, i)
	}
	return i
}

// long reads one --name or --name=value option.
func (p *wrapperParse) long(words []Word, i int) int {
	v := words[i].Value
	fn, inline, hasInline := v, "", false
	if eq := strings.IndexByte(v, '='); eq > 0 {
		fn, inline, hasInline = v[:eq], v[eq+1:], true
	}
	if full, ok := p.row.longName(fn); ok {
		fn = full
	} else {
		// An unlisted long wrapper option may change the command's behaviour
		// (cwd, identity, environment): not fully known (review R5-1).
		p.unaccounted = true
		return i + 1
	}
	if !p.row.isValued(fn) {
		if hasInline && !p.row.optionalLong(fn) {
			p.unaccounted = true // a switch given a value
		}
		p.apply(fn, Word{Value: inline, Static: true}, hasInline)
		return i + 1
	}
	if hasInline {
		p.apply(fn, Word{Value: inline, Static: true}, true)
		return i + 1
	}
	if i+1 < len(words) {
		p.apply(fn, words[i+1], true)
		return i + 2
	}
	p.unaccounted = true // a valued option with no value
	return i + 1
}

// shorts reads one cluster of short options (-abc, -oL, -n5, -u USER).
func (p *wrapperParse) shorts(words []Word, i int) int {
	v := words[i].Value
	body := v[1:]
	for j := 0; j < len(body); j++ {
		ch := body[j]
		if p.name == "nice" && ch >= '0' && ch <= '9' {
			continue // the legacy `nice -5` adjustment
		}
		fn := "-" + string(ch)
		switch {
		case p.row.isValued(fn):
			if j+1 < len(body) {
				p.apply(fn, Word{Value: body[j+1:], Static: true}, true)
				return i + 1
			}
			if i+1 < len(words) {
				p.apply(fn, words[i+1], true)
				return i + 2
			}
			p.unaccounted = true
			return i + 1
		case strings.IndexByte(p.row.optional, ch) >= 0:
			// an optional value is attached only (xargs -iR, nsenter -mFILE).
			p.apply(fn, Word{Value: body[j+1:], Static: true}, j+1 < len(body))
			return i + 1
		case strings.IndexByte(p.row.shorts, ch) >= 0:
			p.apply(fn, Word{}, false)
		default:
			// Any other short option may take a value we cannot see, so it is
			// unaccounted (the wrapper allowlist is closed, round 8 G).
			p.unaccounted = true
		}
	}
	return i + 1
}

// apply records what one option does to the child.
func (p *wrapperParse) apply(fn string, val Word, has bool) {
	row := p.row
	switch {
	case has && hasName(row.userOptions, fn):
		p.markForeignUser(val)
	case has && hasName(row.chdir, fn):
		if val.Static {
			p.w.spec.chdir, p.w.spec.chdirSet = val.Value, true
		} else {
			p.w.spec.cwdDyn = true
		}
	case hasName(row.login, fn):
		p.w.spec.cwdDyn = true
	case hasName(row.clear, fn):
		p.w.spec.clear = true
	case hasName(row.keepEnv, fn):
		p.w.spec.clear = false
		p.w.spec.dropHome = true
	case has && hasName(row.unset, fn):
		if val.Static {
			p.w.spec.set(val.Value, "", false)
		}
	case has && hasName(row.argv0, fn):
		if !val.Static || strings.HasPrefix(val.Value, "-") {
			p.login = true // exec -a -bash: a login shell (GAP-1274)
		}
	case hasName(row.loginShell, fn):
		p.login = true
	case hasName(row.appendOpt, fn):
		p.appendOut = true
	case has && hasName(row.shellOpt, fn):
		vv := val
		p.shellText = &vv
	case hasName(row.execOpt, fn):
		p.execMode = true
	case hasName(row.replaceOpt, fn):
		p.replace = "{}"
		if has && val.Static && val.Value != "" {
			p.replace = val.Value
		} else if has && !val.Static {
			p.replace = "\x00dynamic" // any word may be replaced
		}
	}
	if role, ok := row.outputs[fn]; ok && has {
		p.outs = append(p.outs, wrapperOutput{word: val, role: role})
	}
}

func (p *wrapperParse) markForeignUser(user Word) {
	if !user.Static {
		p.unaccounted = true
		return
	}
	if user.Value != "root" && user.Value != "0" {
		p.foreignUser = true
	}
}

// child returns the child argv when the wrapper builds it (shell text), or nil
// with the index of the child word when the child is the next word.
func (p *wrapperParse) child(words []Word, i int) ([]Word, int) {
	row := p.row
	flushOuts := func() {
		for _, o := range p.outs {
			if o.role == RoleWrite && p.appendOut {
				o.role = RoleAppend
			}
			p.w.wrapOuts = append(p.w.wrapOuts, o)
		}
	}
	// skip leading positionals (DURATION, host, dir, mask, priority, lock file).
	for s := 0; s < row.posSkip && i < len(words); s++ {
		if p.name == "chroot" && s == 0 {
			// chroot NEWROOT starts the command in / of the new root: the real
			// / when NEWROOT is /, else a folder the walk cannot place
			// (rel-1-0-10:GAP-1483: chroot / sh <<E wrote in the caller folder).
			if words[i].Static && cleanPOSIX(words[i].Value) == "/" {
				p.w.spec.chdir, p.w.spec.chdirSet = "/", true
			} else {
				p.w.spec.cwdDyn = true
			}
		}
		i++
	}
	if row.shellAfterSkip && i+1 < len(words) && words[i].Static && (words[i].Value == "-c" || words[i].Value == "--command") {
		vv := words[i+1]
		p.shellText = &vv
		i += 2
		if i < len(words) {
			p.unaccounted = true // flock FILE -c TEXT takes nothing after the text
		}
	}
	if row.operandOut != "" {
		// script [options] [file]: the rest are options or the one file operand
		// (script permutes its options); the child is the -c text.
		var operands []Word
		for i < len(words) {
			if words[i].Static && len(words[i].Value) > 1 && words[i].Value[0] == '-' {
				if strings.HasPrefix(words[i].Value, "--") {
					i = p.long(words, i)
				} else {
					i = p.shorts(words, i)
				}
				continue
			}
			operands = append(operands, words[i])
			i++
		}
		if len(operands) > 1 {
			p.unaccounted = true
		}
		if p.shellText == nil {
			p.unaccounted = true // an interactive shell: no child we can read
		}
		out := Word{Value: row.operandOut, Static: true}
		if len(operands) > 0 {
			out = operands[0]
		}
		p.outs = append(p.outs, wrapperOutput{word: out, role: RoleWrite})
		flushOuts()
		if p.shellText == nil {
			return []Word{}, len(words)
		}
		return shellChild(*p.shellText), len(words)
	}
	flushOuts()
	if p.shellText != nil {
		return shellChild(*p.shellText), len(words)
	}
	if row.joinShell && !p.execMode {
		// watch CMD ARGS: the words are joined with spaces and run by sh -c.
		rest := words[i:]
		if len(rest) == 0 {
			if row.kind == wrapForeign {
				return nil, i // ssh HOST: an interactive login, no child word
			}
			return []Word{}, len(words)
		}
		parts := make([]string, 0, len(rest))
		static := true
		for _, r := range rest {
			if !r.Static {
				static = false
				break
			}
			parts = append(parts, r.Value)
		}
		code := Word{Static: static, Reason: ReasonDynamicExpansion}
		if static {
			code = Word{Value: strings.Join(parts, " "), Static: true}
		}
		return shellChild(code), len(words)
	}
	return nil, i
}

// replacedWords marks the child words that hold the replace string of xargs -I
// as dynamic: their value comes from input. The program word stays, and so
// does the text of a shell child's -c: the shell row reads that body, where
// the name is data (the redirections it names stay read).
func replacedWords(in []Word, repl string) []Word {
	out := make([]Word, len(in))
	copy(out, in)
	shell := len(in) > 0 && in[0].Static && shellPrograms[programBasename(in[0].Value, FlavorPOSIX)]
	for k := 1; k < len(out); k++ {
		if shell && out[k-1].Static && out[k-1].Value == "-c" {
			continue
		}
		if repl == "\x00dynamic" || out[k].Static && strings.Contains(out[k].Value, repl) {
			out[k] = Word{Reason: ReasonDynamicExpansion, Span: out[k].Span}
		}
	}
	return out
}

// shellChild is the argv `sh -c TEXT` a wrapper runs its shell text with.
func shellChild(text Word) []Word {
	return []Word{{Value: "sh", Static: true}, {Value: "-c", Static: true}, text}
}

// dynamicAssignName returns NAME for a word NAME=<expansion> whose name part
// is a literal (env FOO=$V).
func dynamicAssignName(wd Word) (string, bool) {
	if len(wd.Segs) == 0 || wd.Segs[0].Var != "" || wd.Segs[0].Quoted {
		return "", false
	}
	lit := wd.Segs[0].Lit
	eq := strings.IndexByte(lit, '=')
	if eq <= 0 || !plainIdent(lit[:eq]) {
		return "", false
	}
	return lit[:eq], true
}

func hasName(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
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
	_, fl, ok := flagResolve(p, key)
	return fl, ok
}

// flagResolve finds a POSIX flag in a row: the exact name, or for a GNU tool a
// long option it is an unambiguous prefix of (getopt_long), returned with its
// full name. The prefix must be unambiguous among all the tool's long options,
// not only the row's (a prefix of two is an error in the tool).
func flagResolve(p Program, key string) (string, Flag, bool) {
	if fl, ok := p.Flags[key]; ok {
		return key, fl, true
	}
	if len(p.Longs) == 0 || !strings.HasPrefix(key, "--") {
		return key, Flag{}, false
	}
	full, ok := resolveLong(key, p.Longs)
	if !ok {
		return key, Flag{}, false
	}
	fl, ok := p.Flags[full]
	return full, fl, ok
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

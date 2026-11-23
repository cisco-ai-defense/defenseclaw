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

package actionfacts

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// rgFilter is which files and folders ripgrep 14.1 searches under a folder
// it walks (substrate-1:GAP-0683): its override globs (--glob, --iglob),
// its file types (-t, -T, --type-add) and its hidden rule, applied in the
// walk (credentialPathWalk) entry by entry the way rg's walker applies them
// (the ignore crate's Ignore::matched), so a credentials file counts only
// if real rg would search it:
//   - an override glob that matches decides, the last one first: an
//     include glob searches the file or enters the folder, hidden or not; a
//     "!" glob skips it. With any include glob, a file no glob matches is
//     skipped; a folder no glob matches is still entered (unless hidden);
//   - else a file type: the last selected (-t) or excluded (-T) type whose
//     globs match the file name decides; with any -t, a file no selected
//     type matches is skipped. Types never decide a folder;
//   - else a dot-named file or folder is skipped unless hidden is on.
//
// .gitignore and .ignore rules are not modelled: a file they skip counts.
// grep -r has no rgFilter (credentialWalkFilter).
type rgFilter struct {
	hidden   bool
	globs    []rgGlob // the -g globs, then the --iglob globs, as rg adds them
	includes int      // the globs with no "!"
	types    []rgTypeSelection
	selected bool // a -t selection: a file no selected type matches is skipped
	cwd      string
}

// rgFilterAll is the filter of an rg this model is unsure of (count when
// unsure): every file is read, hidden or not. It is shared read-only.
var rgFilterAll = &rgFilter{hidden: true}

// rgGlob is one override glob, compiled as rg compiles it (rgOverrideGlob).
// A nil re is a glob this model does not read exactly (count when unsure):
// an include matches every path, a "!" glob none.
type rgGlob struct {
	re      *regexp.Regexp
	exclude bool // "!glob": a match skips the path
	onlyDir bool // "glob/": matches folders only
}

func (g rgGlob) matches(p string) bool {
	if g.re == nil {
		return !g.exclude
	}
	return g.re.MatchString(rgLatin1(p))
}

// rgTypeSelection is one -t (select) or -T (exclude) of a file type: the
// --type-add globs of the type and the credentials file names its
// built-in globs match (rgBuiltinTypeProbeNames).
type rgTypeSelection struct {
	exclude bool
	globs   []rgGlob
	names   map[string]bool
}

func (s rgTypeSelection) matches(name string) bool {
	if s.names[name] {
		return true
	}
	for _, g := range s.globs {
		if g.re == nil && !s.exclude || g.re != nil && g.re.MatchString(rgLatin1(name)) {
			return true
		}
	}
	return false
}

// rgType is one file type while rg's type changes are read: the globs
// --type-add gave it and the credentials file names its built-in globs
// match.
type rgType struct {
	globs []rgGlob
	names map[string]bool
}

// override is rg's Override::matched for the path p as rg names it: 1 an
// include glob matches, -1 a "!" glob matches (or, for a file, no glob
// matches and there are include globs), 0 none decides.
func (f *rgFilter) override(p string, dir bool) int {
	if len(f.globs) == 0 {
		return 0
	}
	p = f.strip(p)
	for i := len(f.globs) - 1; i >= 0; i-- {
		g := f.globs[i]
		if g.onlyDir && !dir || !g.matches(p) {
			continue
		}
		if g.exclude {
			return -1
		}
		return 1
	}
	if f.includes > 0 && !dir {
		return -1
	}
	return 0
}

// enters reports a folder rg enters; p is its path as rg names it (the
// folder rg was given, then each name below it), name its own name.
func (f *rgFilter) enters(p, name string) bool {
	if f == nil {
		return true
	}
	switch f.override(p, true) {
	case 1:
		return true
	case -1:
		return false
	}
	return f.hidden || !strings.HasPrefix(name, ".")
}

// reads reports a file rg searches, as enters.
func (f *rgFilter) reads(p, name string) bool {
	if f == nil {
		return true
	}
	switch f.override(p, false) {
	case 1:
		return true
	case -1:
		return false
	}
	for i := len(f.types) - 1; i >= 0; i-- {
		if f.types[i].matches(name) {
			return !f.types[i].exclude
		}
	}
	if f.selected {
		return false
	}
	return f.hidden || !strings.HasPrefix(name, ".")
}

// admits reports a probe path under the folder rg names parent: every
// folder on the way is entered and the file is read.
func (f *rgFilter) admits(parent string, segments []string) bool {
	if f == nil {
		return true
	}
	p := parent
	for i, segment := range segments {
		p = rgJoin(p, segment)
		if i < len(segments)-1 && !f.enters(p, segment) || i == len(segments)-1 && !f.reads(p, segment) {
			return false
		}
	}
	return true
}

// strip is the path an override glob is matched against: the walker's
// path with a leading "./" dropped (Ignore::matched), then again and with
// rg's working folder dropped from its start, byte by byte
// (Gitignore::strip, whose root is rg's working folder: the physical one,
// rgPhysicalFolder).
func (f *rgFilter) strip(p string) string {
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "./")
	if f.cwd != "" && f.cwd != "." && strings.Contains(p, "/") {
		if rest, ok := strings.CutPrefix(p, f.cwd); ok {
			p = strings.TrimPrefix(rest, "/")
		}
	}
	return p
}

// rgPhysicalFolder is rg's working folder for the folder it runs in
// (rgWorkingFolder): rg takes it from getcwd, with every symbolic link
// resolved, while the path it walks keeps the folder as the command names
// it. A folder that cannot be resolved stays as given.
func rgPhysicalFolder(cwd string) string {
	if cwd == "" {
		return cwd
	}
	if physical, err := filepath.EvalSymlinks(filepath.FromSlash(cwd)); err == nil {
		return filepath.ToSlash(physical)
	}
	return cwd
}

// rgWorkingFolder is the folder an rg command runs in, the root its
// override globs match from (substrate-1:GAP-0684): the hook's folder when
// no cd, pushd or popd of the call moves it (the working folder tracking,
// working_folder.go), else the one folder the moves reach, physical (every
// link resolved, as rg's getcwd gives it). It is "" (not known exactly:
// every glob is then unsure, rgSearchFilterOf) when
//   - the hook gives no folder;
//   - the command may run in more than one folder (`cd P; rg`, where the
//     cd may have failed) or in an unresolved one (a variable, a command
//     substitution, `cd -`, popd, a function that shadows cd, a loop);
//   - a move goes to the home (~, a bare cd: the call may set HOME) or to a
//     bare relative name (`cd sub`: a CDPATH, set by the call or inherited,
//     may send it elsewhere);
//   - a ".." step reads differently with and without symbolic links (cd -L
//     and cd -P), the folder is not there, or the lookups are spent;
//   - a PowerShell or CMD call moves (those moves are not resolved here);
//   - the command runs inside one (a wrapper, a nested shell) whose folder
//     moved while its own did not.
func (r *credentialPathResolver) rgWorkingFolder(command CommandFact) string {
	cwd := filepath.ToSlash(r.cwd)
	if cwd == "" {
		return ""
	}
	if command.Dialect != DialectPOSIX {
		if windowsWorkFolders(r.commands)[command.ID].moved() {
			return ""
		}
		return cwd
	}
	folders := command.workFolders
	if !folders.moved() {
		if !r.outerCommandsStay(command) {
			return ""
		}
		return cwd
	}
	if len(folders) != 1 || !path.IsAbs(cwd) {
		return ""
	}
	raw, dotdot := cwd, false
	for _, step := range folders[0].steps {
		switch {
		case strings.HasPrefix(step, "/"):
			raw = step
		case step == "." || step == ".." || strings.HasPrefix(step, "./") || strings.HasPrefix(step, "../"):
			raw += "/" + step
		default:
			return ""
		}
		dotdot = dotdot || slices.Contains(strings.Split(step, "/"), "..")
	}
	logical, ok := resolveWorkFolder(cwd, "", folders[0])
	if !ok || !r.lookups.Take() {
		return ""
	}
	physical, err := filepath.EvalSymlinks(filepath.FromSlash(logical))
	if err != nil {
		return ""
	}
	if dotdot {
		// cd -P takes each ".." from the physical folder, cd -L from the
		// path as written: the folder is known only when both agree.
		if !r.lookups.Take() {
			return ""
		}
		if other, err := filepath.EvalSymlinks(filepath.FromSlash(raw)); err != nil || other != physical {
			return ""
		}
	}
	return filepath.ToSlash(physical)
}

// outerCommandsStay reports that no command command runs inside moved
// the folder. Bounded: a chain of outer commands deeper than 32 is unsure.
func (r *credentialPathResolver) outerCommandsStay(command CommandFact) bool {
	parent := command.ParentCommandID
	for depth := 0; parent != 0; depth++ {
		if depth == 32 {
			return false
		}
		index := slices.IndexFunc(r.commands, func(c CommandFact) bool { return c.ID == parent })
		if index < 0 || r.commands[index].workFolders.moved() {
			return false
		}
		parent = r.commands[index].ParentCommandID
	}
	return true
}

// rgJoin is Rust's Path::join of a folder and a name: no "/" is added
// after a folder that ends in one.
func rgJoin(folder, name string) string {
	if folder == "" || strings.HasSuffix(folder, "/") {
		return folder + name
	}
	return folder + "/" + name
}

// rgOverrideGlob compiles one --glob or --iglob value the way rg's
// OverrideBuilder adds it (ignore 0.4 GitignoreBuilder::add_line, then
// globset 0.4.14 with literal_separator and backslash_escape). ok is false
// for a value rg adds no glob for: "" and a "#" comment.
func rgOverrideGlob(line string, fold bool) (g rgGlob, ok bool) {
	if strings.HasPrefix(line, "#") {
		return g, false
	}
	if !strings.HasSuffix(line, "\\ ") {
		line = strings.TrimRightFunc(line, unicode.IsSpace)
	}
	if line == "" {
		return g, false
	}
	absolute := false
	if strings.HasPrefix(line, "\\!") || strings.HasPrefix(line, "\\#") {
		line = line[1:]
		absolute = strings.HasPrefix(line, "/")
	} else {
		if strings.HasPrefix(line, "!") {
			g.exclude = true
			line = line[1:]
		}
		if strings.HasPrefix(line, "/") {
			line = line[1:]
			absolute = true
		}
	}
	if strings.HasSuffix(line, "/") {
		g.onlyDir = true
		line = strings.TrimSuffix(line[:len(line)-1], "\\")
	}
	actual := line
	if !absolute && !strings.Contains(line, "/") && !strings.HasPrefix(actual, "**/") && actual != "**" {
		actual = "**/" + actual
	}
	if strings.HasSuffix(actual, "/**") {
		actual += "/*"
	}
	g.re = rgGlobRegexp(actual, fold)
	return g, true
}

// rgTypeGlob compiles one --type-add glob (matched against a file name).
func rgTypeGlob(glob string) rgGlob {
	return rgGlob{re: rgGlobRegexp(glob, false)}
}

// rgGlobToken is one token of a glob, as globset parses it.
type rgGlobToken struct {
	kind byte // 'l' literal, '?', '*', 'P' **/ prefix, 'S' /** suffix, 'Z' /**/, '[' class, '{' alternates
	char rune
	neg  bool
	set  [][2]rune
	alts [][]rgGlobToken
}

// rgGlobRegexp is globset 0.4.14's regex for glob (Glob::to_regex_with,
// literal_separator and backslash_escape on), over rgLatin1 text: rg
// matches bytes, (?-u), so a non-ASCII character is its UTF-8 bytes. It is
// nil where this model is unsure: a glob globset refuses (rg then refuses
// the call), a class with a non-ASCII character, or a regex that does not
// compile.
func rgGlobRegexp(glob string, fold bool) *regexp.Regexp {
	tokens, ok := rgParseGlob(glob)
	if !ok {
		return nil
	}
	var b strings.Builder
	b.WriteString("^")
	if len(tokens) == 1 && tokens[0].kind == 'P' {
		b.WriteString("(?:.*)")
	} else if !rgGlobTokensRegexp(&b, tokens, fold) {
		return nil
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

// rgParseGlob is globset 0.4.14's Parser.
func rgParseGlob(glob string) ([]rgGlobToken, bool) {
	chars := []rune(glob)
	stack := [][]rgGlobToken{nil}
	push := func(t rgGlobToken) { stack[len(stack)-1] = append(stack[len(stack)-1], t) }
	var prev rune = -1
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if i > 0 {
			prev = chars[i-1]
		}
		peek := func(k int) (rune, bool) {
			if i+k < len(chars) {
				return chars[i+k], true
			}
			return 0, false
		}
		switch c {
		case '?':
			push(rgGlobToken{kind: '?'})
		case '*':
			if next, ok := peek(1); !ok || next != '*' {
				push(rgGlobToken{kind: '*'})
				continue
			}
			i++ // the second '*'
			if len(stack[len(stack)-1]) == 0 {
				if next, ok := peek(1); ok && next != '/' {
					push(rgGlobToken{kind: '*'})
					push(rgGlobToken{kind: '*'})
				} else {
					push(rgGlobToken{kind: 'P'})
					if ok {
						i++ // the '/'
					}
				}
				continue
			}
			if prev != '/' && (len(stack) <= 1 || prev != ',' && prev != '{') {
				push(rgGlobToken{kind: '*'})
				push(rgGlobToken{kind: '*'})
				continue
			}
			suffix := false
			switch next, ok := peek(1); {
			case !ok:
				suffix = true
			case (next == ',' || next == '}') && len(stack) >= 2:
				suffix = true
			case next == '/':
				i++
			default:
				push(rgGlobToken{kind: '*'})
				push(rgGlobToken{kind: '*'})
				continue
			}
			// The token before is the "/", or a **/ prefix or /** suffix
			// that this ** joins.
			top := stack[len(stack)-1]
			last := top[len(top)-1]
			stack[len(stack)-1] = top[:len(top)-1]
			switch {
			case last.kind == 'P' || last.kind == 'S':
				push(last)
			case suffix:
				push(rgGlobToken{kind: 'S'})
			default:
				push(rgGlobToken{kind: 'Z'})
			}
		case '[':
			t := rgGlobToken{kind: '['}
			if next, ok := peek(1); ok && (next == '!' || next == '^') {
				t.neg = true
				i++
			}
			first, inRange, closed := true, false, false
			for i++; i < len(chars); i++ {
				c := chars[i]
				switch {
				case c == ']' && !first:
					closed = true
				case c == '-' && !first && inRange:
					last := &t.set[len(t.set)-1]
					if last[1] = '-'; last[1] < last[0] {
						return nil, false
					}
					inRange = false
				case c == '-' && !first:
					inRange = true
				case inRange:
					last := &t.set[len(t.set)-1]
					if last[1] = c; last[1] < last[0] {
						return nil, false
					}
					inRange = false
				default:
					t.set = append(t.set, [2]rune{c, c})
				}
				if closed {
					break
				}
				first = false
			}
			if !closed {
				return nil, false
			}
			if inRange {
				t.set = append(t.set, [2]rune{'-', '-'})
			}
			push(t)
		case '{':
			if len(stack) > 1 {
				return nil, false
			}
			stack = append(stack, nil)
		case '}':
			var alts [][]rgGlobToken
			for len(stack) >= 2 {
				alts = append(alts, stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			push(rgGlobToken{kind: '{', alts: alts})
		case ',':
			if len(stack) <= 1 {
				push(rgGlobToken{kind: 'l', char: ','})
			} else {
				stack = append(stack, nil)
			}
		case '\\':
			if i+1 >= len(chars) {
				return nil, false
			}
			i++
			push(rgGlobToken{kind: 'l', char: chars[i]})
		default:
			push(rgGlobToken{kind: 'l', char: c})
		}
	}
	if len(stack) != 1 {
		return nil, false
	}
	return stack[0], true
}

// rgGlobTokensRegexp writes globset's tokens_to_regex for tokens, with
// ASCII case folding when fold is set (rg's (?-u)(?i)).
func rgGlobTokensRegexp(b *strings.Builder, tokens []rgGlobToken, fold bool) bool {
	for _, t := range tokens {
		switch t.kind {
		case 'l':
			for _, c := range []byte(string(t.char)) {
				if fold && c < 0x80 && unicode.IsLetter(rune(c)) {
					b.WriteString("[" + rgByte(rune(unicode.ToLower(rune(c)))) + rgByte(unicode.ToUpper(rune(c))) + "]")
				} else {
					b.WriteString(rgByte(rune(c)))
				}
			}
		case '?':
			b.WriteString("[^/]")
		case '*':
			b.WriteString("[^/]*")
		case 'P':
			b.WriteString("(?:/?|.*/)")
		case 'S':
			b.WriteString("/.*")
		case 'Z':
			b.WriteString("(?:/|/.*/)")
		case '[':
			var in [256]bool
			for _, r := range t.set {
				if r[0] >= 0x80 || r[1] >= 0x80 {
					return false
				}
				for c := r[0]; c <= r[1]; c++ {
					in[c] = true
					if fold && unicode.IsLetter(c) {
						in[unicode.ToLower(c)], in[unicode.ToUpper(c)] = true, true
					}
				}
			}
			b.WriteString("[")
			any := false
			for c := 0; c < 256; c++ {
				if in[c] != t.neg {
					b.WriteString(rgByte(rune(c)))
					any = true
				}
			}
			if !any {
				return false
			}
			b.WriteString("]")
		case '{':
			var parts []string
			for _, alt := range t.alts {
				var part strings.Builder
				if !rgGlobTokensRegexp(&part, alt, fold) {
					return false
				}
				if part.Len() > 0 {
					parts = append(parts, part.String())
				}
			}
			if len(parts) > 0 {
				b.WriteString("(?:" + strings.Join(parts, "|") + ")")
			}
		}
	}
	return true
}

// rgByte is one byte as a regexp literal over rgLatin1 text.
func rgByte(c rune) string {
	return `\x{` + strconv.FormatInt(int64(c), 16) + `}`
}

// rgLatin1 is s with each byte as the rune of that number, so Go's regexp
// matches it byte by byte, as rg's (?-u) regex does.
func rgLatin1(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	runes := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		runes[i] = rune(s[i])
	}
	return string(runes)
}

// rgBuiltinTypeProbeNames is, for each built-in file type of ripgrep
// 14.1.0 (rg --type-list) whose globs match a credentials file name (the
// last segment of a credentials probe, the only names the walk counts),
// those names. Every other built-in type matches none. Recorded with real
// rg by TestGAP0683RgBuiltinTypesLive, which fails when it drifts.
var rgBuiltinTypeProbeNames = map[string][]string{
	"json": {".credentials.json", "accesstokens.json", "application_default_credentials.json", "apps.json", "auth.json", "azureprofile.json", "config.json", "credentials.tfrc.json", "hosts.json", "kaggle.json", "keys.json", "msal_token_cacheprobe.json", "oauth_creds.json", "probe.json"},
	"toml": {"auth.toml", "credentials.toml"},
	"xml":  {"credentials.xml", "settings-security.xml"},
	"yaml": {"hosts.yml"},
}

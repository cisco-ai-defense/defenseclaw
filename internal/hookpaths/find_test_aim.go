// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"regexp"
	"strings"
)

// findTest is one find test on the entries a walk finds: -name and -iname
// match the base name with a glob, -path, -ipath, -wholename and
// -iwholename the whole path, and -regex and -iregex the whole path with a
// regular expression of the -regextype in force.
type findTest struct {
	pattern            string
	whole, regex, fold bool
	// re is the compiled -regex, nil for one this reader does not read.
	re *regexp.Regexp
}

// newFindTest reads a find test option and its value; ok is false for a word
// that is no such test.
func newFindTest(option, pattern, regexType string) (test findTest, ok bool) {
	switch option {
	case "-name", "-iname":
	case "-path", "-ipath", "-wholename", "-iwholename":
		test.whole = true
	case "-regex", "-iregex":
		test.whole, test.regex = true, true
	default:
		return test, false
	}
	test.pattern, test.fold = pattern, strings.HasPrefix(option, "-i")
	if test.regex {
		test.re = findRegexp(pattern, regexType, test.fold)
	}
	return test, true
}

// matches reports whether the test matches text; known is false for a regex
// this reader does not read.
func (t findTest) matches(text string) (matched, known bool) {
	if !t.regex {
		return registrationGlobMatch(t.pattern, text, t.fold), true
	}
	if t.re == nil {
		return false, false
	}
	return t.re.MatchString(text), true
}

// aimsAt reports a test aimed at the protected file target below a walk root
// (root as the call spells it, absRoot resolved). A test that matches the
// file but not a decoy of it, the same name with its stem swapped for a
// sentinel (zzsentinel.json for settings.json) and, for a whole-path test,
// in a sentinel folder below the root, is aimed at it: settings.json,
// settings.jso[n], settings.*, -path '*/.claude/*' and -regex
// '.*/settings\.json' are aimed at .claude/settings.json, while *, *.json,
// -path '*' and -regex '.*\.json' match the decoy too and are generic
// filters (rel-1-0-10:GAP-1572). A test whose pattern spells the name
// literally is aimed, and so is a regex this reader does not read (the
// parent reading). An aimed test judges the call on the file whether or not
// it exists when the hook runs, since an earlier part of the chain or another
// process may create it before the walk (rel-1-0-10:GAP-1555); a generic one
// reaches only the files the walk finds. The names are those of the
// protected set itself: no list of hook file names is kept here.
func (t findTest) aimsAt(root, absRoot, target string) bool {
	base := filepath.Base(target)
	pattern, name := strings.ReplaceAll(t.pattern, `\`, ""), base
	if t.fold {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	if strings.Contains(pattern, name) {
		return true
	}
	decoy := findDecoyName(base)
	texts, decoys := []string{base}, []string{decoy}
	if t.whole {
		rel, err := filepath.Rel(absRoot, target)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
		texts, decoys = nil, nil
		for _, start := range []string{root, absRoot} {
			texts = append(texts, findWalkPath(start, rel))
			decoys = append(decoys, findWalkPath(start, filepath.Join("zzsentinel", decoy)))
		}
	}
	aimed := false
	for _, text := range texts {
		matched, known := t.matches(text)
		if !known {
			return true
		}
		aimed = aimed || matched
	}
	if !aimed {
		return false
	}
	for _, text := range decoys {
		if matched, _ := t.matches(text); matched {
			return false
		}
	}
	return true
}

// findDecoyName is base with its stem swapped for a sentinel, a leading dot
// and the extension kept: zzsentinel.json for settings.json,
// .zzsentinel for .claude.
func findDecoyName(base string) string {
	ext := filepath.Ext(base)
	if ext == base {
		ext = ""
	}
	if strings.HasPrefix(base, ".") {
		return ".zzsentinel" + ext
	}
	return "zzsentinel" + ext
}

// findWalkPath spells a path below a walk root as find hands it to its
// tests: the root as written, one slash, then the path below it.
func findWalkPath(root, rel string) string {
	root = filepath.ToSlash(root)
	if rel == "." {
		return root
	}
	if !strings.HasSuffix(root, "/") {
		root += "/"
	}
	return root + filepath.ToSlash(rel)
}

// findRegexp compiles a find regex of regexType (empty: the default, the
// emacs syntax) to match a whole path, case folded when fold. It returns nil
// for a type or a construct this reader does not read.
func findRegexp(pattern, regexType string, fold bool) *regexp.Regexp {
	emacs := false
	switch regexType {
	case "", "emacs", "findutils-default":
		emacs = true
	case "posix-extended", "posix-egrep", "egrep":
	default:
		return nil
	}
	expr, ok := findRegexpSyntax(pattern, emacs)
	if !ok {
		return nil
	}
	if fold {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil
	}
	return re
}

// findRegexpSyntax writes a find regex as an anchored Go expression. In the
// emacs syntax \( \) \| group and alternate and ( ) | { } are plain; in the
// extended one they are operators and the escaped forms are plain. A
// backslash inside a bracket is plain in both. ok is false for a back
// reference, an escape this reader does not know or an open bracket.
func findRegexpSyntax(pattern string, emacs bool) (expr string, ok bool) {
	var out strings.Builder
	out.WriteString(`^(?:`)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\':
			if i+1 >= len(pattern) {
				return "", false
			}
			i++
			next := pattern[i]
			switch {
			case emacs && strings.IndexByte("()|", next) >= 0:
				out.WriteByte(next)
			case strings.IndexByte("wWbB", next) >= 0:
				out.WriteByte('\\')
				out.WriteByte(next)
			case next == '`':
				out.WriteString(`\A`)
			case next == '\'':
				out.WriteString(`\z`)
			case next < 0x80 && !isASCIIAlnum(next):
				out.WriteString(regexp.QuoteMeta(string(next)))
			default:
				return "", false
			}
		case c == '[':
			end := findBracketEnd(pattern, i)
			if end < 0 {
				return "", false
			}
			out.WriteString(strings.ReplaceAll(pattern[i:end+1], `\`, `\\`))
			i = end
		case emacs && strings.IndexByte("(){}|", c) >= 0:
			out.WriteString(regexp.QuoteMeta(string(c)))
		default:
			out.WriteByte(c)
		}
	}
	out.WriteString(`)$`)
	return out.String(), true
}

// findBracketEnd is the index of the ] that closes the bracket expression
// opening at pattern[open], or -1: a ] first (after an optional ^) is a
// member, and [:class:], [.coll.] and [=equiv=] are read whole.
func findBracketEnd(pattern string, open int) int {
	i := open + 1
	if i < len(pattern) && pattern[i] == '^' {
		i++
	}
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	for ; i < len(pattern); i++ {
		switch {
		case pattern[i] == ']':
			return i
		case pattern[i] == '[' && i+1 < len(pattern) && strings.IndexByte(":.=", pattern[i+1]) >= 0:
			end := strings.Index(pattern[i+2:], string(pattern[i+1])+"]")
			if end < 0 {
				return -1
			}
			i += 2 + end + 1
		}
	}
	return -1
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

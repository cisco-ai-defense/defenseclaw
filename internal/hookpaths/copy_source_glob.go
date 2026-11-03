// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// CopySourceGlobFactPrefix carries the hook user's reading of a plain cp
// call with a pattern source: the destination and its matching children that
// may redirect a write. The managed gateway cannot list that project folder.
const CopySourceGlobFactPrefix = "\x00copy-source-glob:"

// Bounds of the copy source reading (rel-1-0-6:GAP-0396). A reading past
// them is not proved; the destination is still judged, see copyChildScan.
const (
	maxCopySourceChildren = 32   // destination children one fact may carry
	maxCopySourceReads    = 16   // source directory reads or destination pages
	maxCopySourceNames    = 4096 // names per read, or matching destination links
	// The old reader could read 16 source directories and one destination,
	// with one extra name per read to detect overflow. Reuse that total work
	// ceiling when a destination needs more than one page.
	maxCopySourceEntries = (maxCopySourceReads + 1) * (maxCopySourceNames + 1)
)

func copySourceGlobFactKey(call *syntax.CallExpr, dir string) string {
	return CopySourceGlobFactPrefix + strconv.FormatUint(uint64(call.Pos().Offset()), 10) + ":" + dir
}

// copySourceWord is one source argv word of a plain copy after brace
// expansion: a fixed name, or a pathname pattern bash expands.
type copySourceWord struct {
	text    string // fixed text, or the pattern with a leading ~/ expanded
	pattern bool
}

// copyCallReading is a plain copy call: cp SOURCE... DEST with no option, no
// assignment and a fixed destination. Every source is a fixed word or a
// plain pathname pattern; any other word leaves the call unread.
type copyCallReading struct {
	sources     []copySourceWord
	destination string
	patterns    bool
}

func readCopyCall(call *syntax.CallExpr, home string) (copyCallReading, bool) {
	var reading copyCallReading
	if call == nil || len(call.Assigns) != 0 || len(call.Args) < 3 {
		return reading, false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" {
		return reading, false
	}
	destination, fixed := StaticWord(call.Args[len(call.Args)-1], home)
	if !fixed || destination == "" || strings.HasPrefix(destination, "-") ||
		strings.ContainsAny(destination, "*?[]{}$`\x00\r\n") {
		return reading, false
	}
	reading.destination = destination
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	for _, arg := range call.Args[1 : len(call.Args)-1] {
		for _, word := range copyBraceWords(arg) {
			if word == nil {
				return reading, false
			}
			source, ok := copySourceOf(word, home, env)
			if !ok || source.text == "" || strings.HasPrefix(source.text, "-") {
				return reading, false
			}
			reading.patterns = reading.patterns || source.pattern
			reading.sources = append(reading.sources, source)
			if len(reading.sources) > maxCopySourceChildren {
				return reading, false
			}
		}
	}
	return reading, len(reading.sources) != 0
}

// copyBraceWords is the argv words bash makes of word by brace expansion
// alone, or word itself. A brace range past the source bound is refused
// before it is expanded (GAP-0568).
func copyBraceWords(word *syntax.Word) []*syntax.Word {
	braced := *word
	if !syntax.SplitBraces(&braced) {
		return []*syntax.Word{word}
	}
	if shellparse.MinBraceFields(word) > maxCopySourceChildren {
		return []*syntax.Word{nil}
	}
	return expand.Braces(&braced)
}

// copySourceOf reads one brace-free source word: fixed text, or unquoted
// literal text holding a pattern character. A parameter, a substitution, an
// extended pattern, an escape or quoted text joined to a pattern is not read.
func copySourceOf(word *syntax.Word, home string, env expand.Environ) (copySourceWord, bool) {
	if text, fixed := staticShellWord(word, env, home != ""); fixed {
		return copySourceWord{text: text}, true
	}
	var b strings.Builder
	for _, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, "\\{}") {
			return copySourceWord{}, false
		}
		b.WriteString(lit.Value)
	}
	text := b.String()
	if !strings.ContainsAny(text, "*?[") {
		return copySourceWord{}, false
	}
	if strings.HasPrefix(text, "~") {
		if home == "" || text != "~" && !strings.HasPrefix(text, "~/") {
			return copySourceWord{}, false
		}
		text = strings.TrimRight(home, "/") + text[1:]
	}
	return copySourceWord{text: text, pattern: true}, true
}

// copySourceGlobDestinations reads a plain copy call with at least one
// pattern source (cp *.md build/, cp src/*/*.md out/, cp a[!2].md dst): the
// destination and matching link or hardlink children, since cp writes
// DEST/NAME through an existing link at that name. The hook client
// expands each pattern as the user; a managed gateway reads the client's
// fact. proved is false when a pattern could not be expanded within the
// bounds; the destination and its matching link or hardlink children are
// then listed. If those children cannot be checked within the bounds,
// unknown keeps the protected-target decision.
func copySourceGlobDestinations(call *syntax.CallExpr, dir, home string, facts map[string]string, record bool) (paths []string, proved, ok, unknown bool) {
	if !filepath.IsAbs(dir) {
		return nil, false, false, false
	}
	reading, ok := readCopyCall(call, home)
	if !ok || !reading.patterns {
		return nil, false, false, false
	}
	destination := OperandPath(reading.destination, dir)
	key := copySourceGlobFactKey(call, dir)
	if !record && facts != nil {
		encoded := facts[key]
		if encoded == "" {
			return nil, false, false, false
		}
		decoded, ok := decodeCopySourceGlobFact(encoded)
		if !ok || decoded[0] != destination {
			return nil, false, false, false
		}
		for _, path := range decoded[1:] {
			if name, child := copyChildName(destination, path); !child || strings.HasPrefix(name, "-") {
				return nil, false, false, false
			}
		}
		switch {
		case strings.HasPrefix(encoded, copySourceUnprovedChildrenMark):
			return decoded[1:], false, true, false
		case strings.HasPrefix(encoded, copySourceUnprovedMark):
			return decoded, false, true, false
		}
		return decoded, true, true, false
	}
	if actionGlobViewHidden(dir, home) {
		return nil, false, false, false
	}
	userView := actionProcessOwnsHome(home)
	names := map[string]bool{}
	var unproved []string // basename patterns of sources not expanded
	reads := 0
	entriesRead := 0
	for _, source := range reading.sources {
		if !source.pattern {
			addCopyChildName(names, filepath.Base(source.text))
			continue
		}
		matches, complete := expandCopySourcePattern(source.text, dir, userView, &reads, &entriesRead)
		if !complete {
			unproved = append(unproved, filepath.Base(source.text))
			continue
		}
		for _, match := range matches {
			if strings.HasPrefix(match.word, "-") {
				// An expanded option changes what cp writes.
				return nil, false, false, false
			}
			addCopyChildName(names, filepath.Base(match.path))
		}
	}
	directory := copyDestinationMayBeDirectory(destination)
	var children []string
	includeDestination := true
	if len(unproved) == 0 && len(names) <= maxCopySourceChildren {
		if directory {
			var scanned bool
			children, scanned = copyNamedLinkChildren(destination, names, home)
			if !scanned {
				return nil, false, true, true
			}
		}
	} else if directory {
		// The names are not proved. Bash may write any child an unproved
		// pattern names, and the copy's other words leave the destination
		// an opaque copy scope, so only the destination's existing links
		// such a pattern (or a fixed final name) may name are judged; a
		// destination that is itself a link is judged as well.
		// A source listing can be complete even when it names more children
		// than the fact can carry. Probe those exact child names instead of
		// listing a destination that may be past its entry bound.
		var links []string
		var scanned bool
		if len(unproved) == 0 {
			links, scanned = copyNamedLinkChildren(destination, names, home)
		} else {
			links, scanned = copyLinkChildren(destination, unproved, names, reading.sources, dir, home, userView, &entriesRead)
		}
		if !scanned {
			return nil, false, true, true
		}
		children = links
		info, err := pathLstat(destination)
		includeDestination = err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
	}
	if len(children) > maxCopySourceChildren {
		return nil, false, true, true
	}
	slices.Sort(children)
	paths = append([]string{destination}, children...)
	proved = len(unproved) == 0 && len(names) <= maxCopySourceChildren
	if record && facts != nil {
		if encoded, err := json.Marshal(paths); err == nil {
			mark := ""
			switch {
			case !proved && !includeDestination:
				mark = copySourceUnprovedChildrenMark
			case !proved:
				mark = copySourceUnprovedMark
			}
			facts[key] = mark + string(encoded)
		}
	}
	if !includeDestination {
		return paths[1:], proved, true, false
	}
	return paths, proved, true, false
}

// copyLiteralDestinations reads a plain copy of fixed sources (cp src/a.md
// build/, cp {a,b}.md out/): the destination and DEST/NAME for each source
// NAME. No listing is needed; a child path that is not under a directory
// does not resolve to a protected file.
//
// A managed gateway cannot see whether the destination is a directory: it
// keeps the children the hook client described, which lists them only for
// a directory.
func copyLiteralDestinations(call *syntax.CallExpr, dir, home string, facts map[string]string) []string {
	if !filepath.IsAbs(dir) {
		return nil
	}
	reading, ok := readCopyCall(call, home)
	if !ok || reading.patterns {
		return nil
	}
	destination := OperandPath(reading.destination, dir)
	names := map[string]bool{}
	for _, source := range reading.sources {
		addCopyChildName(names, filepath.Base(source.text))
	}
	paths := []string{destination}
	if facts == nil && !copyDestinationMayBeDirectory(destination) {
		return paths
	}
	for name := range names {
		child := copyChild(destination, name)
		if _, described := facts[child]; facts == nil || described {
			paths = append(paths, child)
		}
	}
	slices.Sort(paths[1:])
	return paths
}

// copyChild is the path cp writes for name in destination. It keeps the
// destination's spelling (OperandPath keeps a dot-dot for the link walk).
func copyChild(destination, name string) string {
	return strings.TrimRight(destination, string(filepath.Separator)) + string(filepath.Separator) + name
}

func copyChildName(destination, path string) (string, bool) {
	prefix := strings.TrimRight(destination, string(filepath.Separator)) + string(filepath.Separator)
	name, child := strings.CutPrefix(path, prefix)
	return name, child && name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00")
}

// copyDestinationMayBeDirectory reports a destination cp may write children
// in: an existing directory or a link to one, or one this process cannot
// tell. A missing name or a file is written itself.
func copyDestinationMayBeDirectory(destination string) bool {
	info, err := pathStat(destination)
	if err == nil {
		return info.IsDir()
	}
	return !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)
}

func addCopyChildName(names map[string]bool, name string) {
	if name != "" && name != "." && name != ".." && name != string(filepath.Separator) &&
		!strings.ContainsAny(name, "/\\\x00") {
		names[name] = true
	}
}

type copySourceMatch struct {
	path string // the matched file
	word string // the argv word bash passes
}

// expandCopySourcePattern lists the files a source pattern names, as the
// user's shell does. Names compare without case and include leading-dot
// names, since shell startup files may set nocaseglob or dotglob: that can
// only add children to judge. A pattern a component cannot translate, a
// directory that cannot be listed, or a listing past the bounds leaves the
// expansion unproved.
func expandCopySourcePattern(pattern, dir string, userView bool, reads, entriesRead *int) ([]copySourceMatch, bool) {
	separator := string(filepath.Separator)
	start, word := dir, ""
	rest := pattern
	if strings.HasPrefix(pattern, "/") {
		if runtime.GOOS == "windows" {
			return nil, false
		}
		start, rest, word = separator, strings.TrimLeft(pattern, "/"), "/"
	}
	current := []copySourceMatch{{path: start, word: word}}
	components := strings.Split(rest, "/")
	for _, component := range components {
		if component == "" {
			continue
		}
		join := func(m copySourceMatch, name string) copySourceMatch {
			text := m.word
			if text != "" && !strings.HasSuffix(text, "/") {
				text += "/"
			}
			return copySourceMatch{path: m.path + separator + name, word: text + name}
		}
		if !strings.ContainsAny(component, "*?[") {
			for j := range current {
				current[j] = join(current[j], component)
			}
			continue
		}
		matcher, ok := bashGlobComponent(component)
		if !ok {
			return nil, false
		}
		var next []copySourceMatch
		for _, m := range current {
			if *reads++; *reads > maxCopySourceReads {
				return nil, false
			}
			names, complete := readCopyDirNames(m.path, userView)
			*entriesRead += len(names)
			if *entriesRead > maxCopySourceEntries {
				return nil, false
			}
			if !complete {
				return nil, false
			}
			for _, name := range names {
				if name == "." || name == ".." || !copyGlobNameMatch(matcher, name) {
					continue
				}
				next = append(next, join(m, name))
				if len(next) > maxCopySourceNames {
					return nil, false
				}
			}
		}
		if len(next) == 0 {
			// Bash passes an unmatched pattern as itself; cp then reads
			// no such file and writes nothing.
			return nil, true
		}
		current = next
	}
	return current, true
}

// readCopyDirNames lists one directory a pattern walks. A name that does not
// exist or is not a directory has no entries, as for the shell; so has a
// directory the user's own process cannot list.
func readCopyDirNames(path string, userView bool) ([]string, bool) {
	directory, err := pathOpen(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) ||
			errors.Is(err, fs.ErrPermission) && userView {
			return nil, true
		}
		return nil, false
	}
	defer directory.Close()
	names, err := directory.Readdirnames(maxCopySourceNames + 1)
	if err != nil && err != io.EOF {
		if errors.Is(err, syscall.ENOTDIR) {
			return nil, true
		}
		return nil, false
	}
	return names, len(names) <= maxCopySourceNames
}

// copyNamedLinkChildren checks exact source basenames without reading the
// destination directory, including when the source set exceeds the smaller
// child-fact bound.
func copyNamedLinkChildren(destination string, names map[string]bool, home string) ([]string, bool) {
	var links []string
	for name := range names {
		path := copyChild(destination, name)
		info, err := pathLstat(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return nil, false
		}
		if copyPotentialLink(path, info) {
			links = append(links, path)
		}
	}
	return copyBoundedLinkFacts(links, home)
}

// A fact can carry only a small number of children. When there are more
// links, the client checks all of them and retains a protected child, if
// present; ordinary links need no gateway path fact.
func copyBoundedLinkFacts(links []string, home string) ([]string, bool) {
	if len(links) <= maxCopySourceChildren {
		return links, true
	}
	memo := NewTargetMemo()
	protected := memo.protectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for _, path := range links {
		resolved, ok := memo.resolveWriteTarget(path)
		if !ok {
			return nil, false
		}
		if protected.has(resolved) || samePathName(resolved, ssh) {
			return []string{path}, true
		}
		mapped, identified := protected.target(resolved)
		if !identified {
			return nil, false
		}
		if protected.has(mapped) {
			return []string{path}, true
		}
	}
	return nil, true
}

func copyPotentialLink(path string, info os.FileInfo) bool {
	return info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 ||
		info.Mode().IsRegular() && linkCount(path, info) > 1
}

// copyLinkChildren lists links, hardlinks and Windows junctions in destination
// that one of patterns may name: the children an unproved source expansion
// may write through. A destination that cannot be read within the bounds
// is not scanned; one that does not exist or is not a directory has none.
func copyLinkChildren(destination string, patterns []string, exact map[string]bool, sources []copySourceWord, dir, home string, userView bool, entriesRead *int) ([]string, bool) {
	matchers := make([]copyGlobMatcher, 0, len(patterns))
	for _, pattern := range patterns {
		matcher, ok := bashGlobComponent(pattern)
		if !ok {
			// Even when a class cannot be translated, each bracket names
			// one character. Keep the surrounding literals and extension;
			// widening the whole basename to * includes disjoint links.
			shape, shapeOK := copyGlobShape(pattern)
			matcher, ok = copyGlobMatcher{pattern: shape}, shapeOK
			if !ok {
				matcher = copyGlobMatcher{pattern: "*"}
			}
		}
		matchers = append(matchers, matcher)
	}
	directory, err := pathOpen(destination)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return nil, true
		}
		return nil, false
	}
	defer directory.Close()
	var links []string
	// Each page is bounded, and only matching link entries count as
	// candidate children. This lets ordinary files precede a link in a
	// large destination without discarding that link.
	candidates := 0
	probes := 0
	for page := 0; page < maxCopySourceReads; page++ {
		remaining := maxCopySourceEntries - *entriesRead
		if remaining <= 0 {
			return nil, false
		}
		pageSize := min(maxCopySourceNames, remaining)
		entries, err := directory.ReadDir(pageSize)
		*entriesRead += len(entries)
		if err != nil && err != io.EOF {
			return nil, errors.Is(err, syscall.ENOTDIR)
		}
		for _, entry := range entries {
			name := entry.Name()
			matched := exact[name]
			if !matched {
				for _, matcher := range matchers {
					if copyGlobNameMatch(matcher, name) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
			path := copyChild(destination, name)
			info, err := entry.Info()
			if err != nil {
				return nil, false
			}
			if copyPotentialLink(path, info) {
				candidates++
				if candidates > maxCopySourceNames {
					return nil, false
				}
				mayWrite, proved := true, true
				if !exact[name] {
					mayWrite, proved = copySourceMayWriteName(sources, dir, name, userView, &probes, entriesRead)
					if *entriesRead > maxCopySourceEntries {
						return nil, false
					}
				}
				if !proved || mayWrite {
					links = append(links, path)
				}
			}
		}
		if len(entries) < pageSize || err == io.EOF {
			return copyBoundedLinkFacts(links, home)
		}
	}
	return nil, false
}

// A basename shape can include a destination link that no source file has.
// For a particular link name, only the glob's parent components need listing;
// its final component becomes an exact filesystem probe. An incomplete probe
// keeps the link in the protected-target reading.
func copySourceMayWriteName(sources []copySourceWord, dir, name string, userView bool, probes, entriesRead *int) (bool, bool) {
	for _, source := range sources {
		if !source.pattern {
			if filepath.Base(source.text) == name {
				return true, true
			}
			continue
		}
		base := filepath.Base(source.text)
		matcher, ok := bashGlobComponent(base)
		if !ok {
			shape, shaped := copyGlobShape(base)
			if !shaped || copyGlobNameMatch(copyGlobMatcher{pattern: shape}, name) {
				return true, false
			}
			continue
		}
		if !copyGlobNameMatch(matcher, name) {
			continue
		}
		prefix := strings.TrimSuffix(source.text, base)
		parents := []copySourceMatch{{path: dir}}
		if prefix != "" {
			reads := 0
			parents, ok = expandCopySourcePattern(strings.TrimSuffix(prefix, "/"), dir, userView, &reads, entriesRead)
			if !ok {
				return true, false
			}
		}
		for _, parent := range parents {
			*probes++
			*entriesRead++
			if *probes > maxCopySourceNames || *entriesRead > maxCopySourceEntries {
				return true, false
			}
			_, err := pathLstat(parent.path + string(filepath.Separator) + name)
			if err == nil {
				return true, true
			}
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				return true, false
			}
		}
	}
	return false, true
}

type copyGlobMatcher struct {
	pattern string
	unicode *regexp.Regexp
	folded  *regexp.Regexp
}

// bashGlobComponent translates one bash pattern component to the
// filepath.Match syntax: [!x] is [^x], and the POSIX classes
// the reader knows become ranges. An escape, another class, an unterminated
// bracket or a bracket body filepath.Match may read otherwise is not
// translated.
func bashGlobComponent(component string) (copyGlobMatcher, bool) {
	if strings.Contains(component, "[:punct:]") && copyUnicodeGlobLocale() {
		pattern, ok := bashGlobRegexp(component)
		if !ok {
			return copyGlobMatcher{}, false
		}
		folded, ok := bashGlobRegexp(strings.ToLower(component))
		if !ok {
			return copyGlobMatcher{}, false
		}
		exactRE, err := regexp.Compile(pattern)
		if err != nil {
			return copyGlobMatcher{}, false
		}
		foldedRE, err := regexp.Compile(folded)
		if err != nil {
			return copyGlobMatcher{}, false
		}
		return copyGlobMatcher{unicode: exactRE, folded: foldedRE}, true
	}
	var b strings.Builder
	for i := 0; i < len(component); i++ {
		c := component[i]
		switch c {
		case '\\', ']':
			return copyGlobMatcher{}, false
		case '[':
			j := i + 1
			if j < len(component) && (component[j] == '!' || component[j] == '^') {
				j++
			}
			for j < len(component) && component[j] != ']' {
				if strings.HasPrefix(component[j:], "[:") {
					k := strings.Index(component[j+2:], ":]")
					if k < 0 {
						return copyGlobMatcher{}, false
					}
					j += 2 + k + 2
					continue
				}
				j++
			}
			if j >= len(component) {
				return copyGlobMatcher{}, false
			}
			translated, ok := bashBracketBody(component[i+1:j], false)
			if !ok {
				return copyGlobMatcher{}, false
			}
			b.WriteString("[" + translated + "]")
			i = j
		default:
			b.WriteByte(c)
		}
	}
	return copyGlobMatcher{pattern: b.String()}, true
}

func copyUnicodeGlobLocale() bool {
	locale := os.Getenv("LC_ALL")
	if locale == "" {
		locale = os.Getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	return locale != "" && locale != "C" && locale != "POSIX"
}

// Bash's punctuation class includes non-ASCII punctuation and symbols in
// UTF-8 locales. filepath.Match has only literal rune ranges, so use a
// Unicode class matcher for patterns containing that class.
func bashGlobRegexp(component string) (string, bool) {
	var b strings.Builder
	b.WriteString("(?s)^")
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '\\', ']':
			return "", false
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '[':
			j := i + 1
			if j < len(component) && (component[j] == '!' || component[j] == '^') {
				j++
			}
			for j < len(component) && component[j] != ']' {
				if strings.HasPrefix(component[j:], "[:") {
					k := strings.Index(component[j+2:], ":]")
					if k < 0 {
						return "", false
					}
					j += 2 + k + 2
					continue
				}
				j++
			}
			if j >= len(component) {
				return "", false
			}
			body, ok := bashBracketBody(component[i+1:j], true)
			if !ok {
				return "", false
			}
			b.WriteString("[" + body + "]")
			i = j
		case '.', '+', '(', ')', '{', '}', '|', '$', '^':
			b.WriteByte('\\')
			b.WriteByte(component[i])
		default:
			b.WriteByte(component[i])
		}
	}
	b.WriteByte('$')
	return b.String(), true
}

// copyGlobShape preserves the width of a bracket the exact reader cannot
// translate, including a POSIX class. It only narrows an unproved link scan;
// the source expansion itself remains unproved.
func copyGlobShape(component string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '\\', ']':
			return "", false
		case '[':
			j := i + 1
			for j < len(component) && component[j] != ']' {
				if strings.HasPrefix(component[j:], "[:") {
					end := strings.Index(component[j+2:], ":]")
					if end < 0 {
						return "", false
					}
					j += 2 + end + 2
					continue
				}
				j++
			}
			if j == len(component) {
				return "", false
			}
			b.WriteByte('?')
			i = j
		default:
			b.WriteByte(component[i])
		}
	}
	return b.String(), true
}

var posixGlobClasses = map[string]string{
	"digit": "0-9", "lower": "a-z", "upper": "A-Z", "alpha": "a-zA-Z",
	"alnum": "0-9a-zA-Z", "xdigit": "0-9a-fA-F", "space": " \t", "blank": " \t",
	"punct": "!-/:-@[-`{-~",
}

func bashBracketBody(body string, unicodePunct bool) (string, bool) {
	var b strings.Builder
	if strings.HasPrefix(body, "!") || strings.HasPrefix(body, "^") {
		b.WriteByte('^')
		body = body[1:]
	}
	if body == "" || strings.HasPrefix(body, "-") || strings.HasSuffix(body, "-") {
		return "", false
	}
	for body != "" {
		if strings.HasPrefix(body, "[:") {
			end := strings.Index(body, ":]")
			if end < 0 {
				return "", false
			}
			class, ok := posixGlobClasses[body[2:end]]
			if !ok {
				return "", false
			}
			if unicodePunct && body[2:end] == "punct" {
				class = `\p{P}\p{S}\p{M}\p{Cf}\p{Co}\p{No}\x{00A0}\x{2007}\x{202F}\x{2FFC}\x{2FFD}\x{2FFE}\x{2FFF}\x{31EF}`
			}
			b.WriteString(class)
			body = body[end+2:]
			continue
		}
		if strings.ContainsAny(body[:1], "[]^") {
			return "", false
		}
		b.WriteByte(body[0])
		body = body[1:]
	}
	return b.String(), true
}

// copyGlobNameMatch accepts both the ordinary case-sensitive Bash match and
// the nocaseglob match. Folding alone is unsound for negated brackets: [!A]
// matches a when nocaseglob is off. A dot name matches as with dotglob.
func copyGlobNameMatch(matcher copyGlobMatcher, name string) bool {
	if matcher.unicode != nil {
		return matcher.unicode.MatchString(name) || matcher.folded.MatchString(strings.ToLower(name))
	}
	matched, err := filepath.Match(matcher.pattern, name)
	if err != nil || matched {
		return err == nil && matched
	}
	matched, err = filepath.Match(strings.ToLower(matcher.pattern), strings.ToLower(name))
	return err == nil && matched
}

func copyTextGlobName(name string) bool {
	return len(name) >= len(".txt") && strings.EqualFold(name[len(name)-len(".txt"):], ".txt")
}

// The fact of a reading whose source names were not all proved starts with
// a mark; the gateway reads the rest of the call as the client did:
//   - "!": the gateway judges the destination and the listed links;
//   - "?": the destination is a directory that is not a link, and only the
//     listed link children are judged.
const (
	copySourceUnprovedMark         = "!"
	copySourceUnprovedChildrenMark = "?"
)

func decodeCopySourceGlobFact(encoded string) ([]string, bool) {
	encoded = strings.TrimPrefix(strings.TrimPrefix(encoded, copySourceUnprovedMark), copySourceUnprovedChildrenMark)
	var paths []string
	if json.Unmarshal([]byte(encoded), &paths) != nil || len(paths) < 1 || len(paths) > maxCopySourceChildren+1 {
		return nil, false
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || len(path) > MaxWriteTargetPathBytes || strings.IndexByte(path, 0) >= 0 {
			return nil, false
		}
	}
	return paths, true
}

// CopySourceGlobDestinations returns the bounded write paths of a sole plain
// copy call: the destination and the destination children it may write
// through, for pattern sources (copySourceGlobDestinations) and for fixed
// sources (copyLiteralDestinations), rel-1-0-6:GAP-0396.
func CopySourceGlobDestinations(command, cwd, home string, facts map[string]string) []string {
	paths, _ := CopySourceGlobDestinationsAndUnknown(command, cwd, home, facts)
	return paths
}

// CopySourceGlobDestinationsAndUnknown also reports an expansion whose
// destination children cannot be judged within the reader's bounds.
func CopySourceGlobDestinationsAndUnknown(command, cwd, home string, facts map[string]string) ([]string, bool) {
	if !strings.Contains(command, "cp") || strings.HasPrefix(strings.TrimSpace(command), "for ") {
		return nil, false
	}
	file, ok := parseShell(command)
	if !ok {
		return nil, false
	}
	return copySourceGlobDestinationsWithParsed(command, cwd, home, file, facts, false)
}

// copySourceGlobDestinationsWithParsed lets the hook client reuse its first
// bounded source reading when it later walks links in the same command.
func copySourceGlobDestinationsWithParsed(command, cwd, home string, file *syntax.File, facts map[string]string, record bool) ([]string, bool) {
	if !strings.Contains(command, "cp") || strings.HasPrefix(strings.TrimSpace(command), "for ") ||
		file == nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return nil, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return nil, false
	}
	literalFacts := facts
	if record {
		literalFacts = nil
	}
	if paths := copyLiteralDestinations(call, cwd, home, literalFacts); paths != nil {
		return paths, false
	}
	paths, _, ok, unknown := copySourceGlobDestinations(call, cwd, home, facts, record)
	if !ok {
		return nil, false
	}
	return paths, unknown
}

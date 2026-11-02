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
// call with a pattern source: the destination and every destination child
// the call may write. The managed gateway cannot list that project folder.
const CopySourceGlobFactPrefix = "\x00copy-source-glob:"

// Bounds of the copy source reading (rel-1-0-6:GAP-0396). A reading past
// them is not proved; the destination is still judged, see copyChildScan.
const (
	maxCopySourceChildren = 32   // destination children one call may name
	maxCopySourceReads    = 16   // directories one call's patterns may list
	maxCopySourceNames    = 4096 // names read from one directory
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
// destination and each destination child the copy may write, since cp
// writes DEST/NAME through an existing link at that name. The hook client
// expands each pattern as the user; a managed gateway reads the client's
// fact. proved is false when a pattern could not be expanded within the
// bounds; the destination and its matching link children are then still
// listed, so an unproved expansion never drops the protected-target check.
func copySourceGlobDestinations(call *syntax.CallExpr, dir, home string, facts map[string]string, record bool) (paths []string, proved, ok bool) {
	if !filepath.IsAbs(dir) {
		return nil, false, false
	}
	reading, ok := readCopyCall(call, home)
	if !ok || !reading.patterns {
		return nil, false, false
	}
	destination := OperandPath(reading.destination, dir)
	key := copySourceGlobFactKey(call, dir)
	if !record && facts != nil {
		encoded := facts[key]
		if encoded == "" {
			return nil, false, false
		}
		decoded, ok := decodeCopySourceGlobFact(encoded)
		if !ok || decoded[0] != destination {
			return nil, false, false
		}
		for _, path := range decoded[1:] {
			if name, child := copyChildName(destination, path); !child || strings.HasPrefix(name, "-") {
				return nil, false, false
			}
		}
		switch {
		case strings.HasPrefix(encoded, copySourceUnprovedChildrenMark):
			return decoded[1:], false, true
		case strings.HasPrefix(encoded, copySourceUnprovedMark):
			return decoded, false, true
		}
		return decoded, true, true
	}
	if actionGlobViewHidden(dir, home) {
		return nil, false, false
	}
	userView := actionProcessOwnsHome(home)
	names := map[string]bool{}
	var unproved []string // basename patterns of sources not expanded
	reads := 0
	for _, source := range reading.sources {
		if !source.pattern {
			addCopyChildName(names, filepath.Base(source.text))
			continue
		}
		matches, complete := expandCopySourcePattern(source.text, dir, userView, &reads)
		if !complete {
			unproved = append(unproved, filepath.Base(source.text))
			continue
		}
		for _, match := range matches {
			if strings.HasPrefix(match.word, "-") {
				// An expanded option changes what cp writes.
				return nil, false, false
			}
			addCopyChildName(names, filepath.Base(match.path))
		}
	}
	directory := copyDestinationMayBeDirectory(destination)
	var children []string
	includeDestination := true
	if len(unproved) == 0 && len(names) <= maxCopySourceChildren {
		if directory {
			for name := range names {
				children = append(children, copyChild(destination, name))
			}
		}
	} else if directory {
		// The names are not proved. Bash may write any child an unproved
		// pattern names, and the copy's other words leave the destination
		// an opaque copy scope, so only the destination's existing links
		// such a pattern (or a fixed final name) may name are judged; a
		// destination that is itself a link is judged as well.
		patterns := []string{}
		for _, base := range unproved {
			patterns = append(patterns, base)
		}
		if len(names) > maxCopySourceChildren {
			patterns = append(patterns, "*")
		} else {
			for name := range names {
				patterns = append(patterns, name)
			}
		}
		links, scanned := copyLinkChildren(destination, patterns)
		if !scanned {
			return nil, false, false
		}
		children = links
		info, err := pathLstat(destination)
		includeDestination = err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
	}
	if len(children) > maxCopySourceChildren {
		return nil, false, false
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
		return paths[1:], proved, true
	}
	return paths, proved, true
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
func expandCopySourcePattern(pattern, dir string, userView bool, reads *int) ([]copySourceMatch, bool) {
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
	for i, component := range components {
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
		last := i == len(components)-1
		var next []copySourceMatch
		for _, m := range current {
			if *reads++; *reads > maxCopySourceReads {
				return nil, false
			}
			names, complete := readCopyDirNames(m.path, userView)
			if !complete {
				return nil, false
			}
			for _, name := range names {
				if name == "." || name == ".." || !copyGlobNameMatch(matcher, name) {
					continue
				}
				next = append(next, join(m, name))
				if len(next) > maxCopySourceChildren && last {
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

// copyLinkChildren lists the links (and Windows junctions) in destination
// that one of patterns may name: the children an unproved source expansion
// may write through. A destination that cannot be read within the bounds
// is not scanned; one that does not exist or is not a directory has none.
func copyLinkChildren(destination string, patterns []string) ([]string, bool) {
	matchers := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		matcher, ok := bashGlobComponent(pattern)
		if !ok {
			matcher = "*"
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
	entries, err := directory.ReadDir(maxCopySourceNames + 1)
	if err != nil && err != io.EOF {
		return nil, errors.Is(err, syscall.ENOTDIR)
	}
	if len(entries) > maxCopySourceNames {
		return nil, false
	}
	var links []string
	for _, entry := range entries {
		if entry.Type()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			continue
		}
		name := entry.Name()
		for _, matcher := range matchers {
			if copyGlobNameMatch(matcher, name) {
				links = append(links, copyChild(destination, name))
				break
			}
		}
	}
	return links, true
}

// bashGlobComponent translates one bash pattern component to the
// filepath.Match syntax, in lower case: [!x] is [^x], and the POSIX classes
// the reader knows become ranges. An escape, another class, an unterminated
// bracket or a bracket body filepath.Match may read otherwise is not
// translated.
func bashGlobComponent(component string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(component); i++ {
		c := component[i]
		switch c {
		case '\\', ']':
			return "", false
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
			translated, ok := bashBracketBody(component[i+1 : j])
			if !ok {
				return "", false
			}
			b.WriteString("[" + translated + "]")
			i = j
		default:
			b.WriteByte(c)
		}
	}
	return strings.ToLower(b.String()), true
}

var posixGlobClasses = map[string]string{
	"digit": "0-9", "lower": "a-z", "upper": "A-Z", "alpha": "a-zA-Z",
	"alnum": "0-9a-zA-Z", "xdigit": "0-9a-fA-F", "space": " \t", "blank": " \t",
}

func bashBracketBody(body string) (string, bool) {
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

// copyGlobNameMatch matches a translated (lower-case) component without
// case. A dot name matches as with dotglob.
func copyGlobNameMatch(matcher, name string) bool {
	matched, err := filepath.Match(matcher, strings.ToLower(name))
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
	if !strings.Contains(command, "cp") || strings.HasPrefix(strings.TrimSpace(command), "for ") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return nil
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	if paths := copyLiteralDestinations(call, cwd, home, facts); paths != nil {
		return paths
	}
	paths, _, ok := copySourceGlobDestinations(call, cwd, home, facts, false)
	if !ok {
		return nil
	}
	return paths
}

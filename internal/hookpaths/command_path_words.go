// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"math"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// CommandPathWord is one static word of a POSIX shell command that may name
// a path: an argument of a simple command (the value of a --name=VALUE
// option), or the target of a file redirect, also inside the static body of
// an eval or of a shell's -c. Text is the word as the command spells it (its
// source bytes), Value its static value (quotes taken out, a leading ~/ or
// $HOME expanded with the home given).
type CommandPathWord struct {
	Text, Value string
	// FollowsLink is set where the command opens the file the word names,
	// so a link that is the word's last component is followed (cat, cp,
	// a redirect, cd); clear where it acts on the name itself (rm, mv, ln,
	// ls, stat, readlink, find, test, a cp or tar that keeps links).
	FollowsLink bool
	// Program is set for the program word of a simple command, and for the
	// program a static prefix wrapper there runs.
	Program bool
	// Unplaced is set for a word whose place the file system as it is
	// before the command runs does not give: a word after an earlier
	// statement that changes the working folder (cd, pushd, popd), runs
	// code this reading does not see (source, a dynamic program or body),
	// or moves, links or removes a path the word lies under (mv a keylink
	// && cat keylink reads the moved file); a change inside a loop counts
	// from the loop's start. A word in a function body runs when the
	// function is first called: a change after the body that ends before
	// that call counts for it too (f() { cat keylink; }; cd /tmp; f), and
	// its own statement, a later statement of the body and a change after
	// the call do not (f() { cp /tmp/x keylink; }; f; cd /tmp). A word that
	// its own call reads in another folder or root (env -C, tar -C, chroot,
	// ssh) is unplaced too.
	Unplaced   bool
	start, end int  // the byte offsets of Text in the command
	quote      byte // 0 at the top level; ' or " inside a quoted body
}

// commandPathScan collects the path words of a command, the statements that
// change where later words lie, the byte ranges of its loops, its function
// definitions and the calls that may run them.
type commandPathScan struct {
	words     []CommandPathWord
	changes   []commandPathChange
	loops     [][2]int
	functions []commandPathFunction
	calls     []commandPathCall
	// bodies indexes the function bodies (functionBodies).
	bodies *commandPathBodies
}

// commandPathFunction is a function definition: its name and the byte range
// of its body.
type commandPathFunction struct {
	name string
	body [2]int
}

// commandPathCall is a simple command at byte start that may run a function
// of the command: its program word is the function's name, or (name "") a
// word this reading cannot name (a dynamic program, eval, source).
type commandPathCall struct {
	name  string
	start int
}

// commandPathChange is a statement ending at byte end that changes where the
// words after it lie: every one when all is set, else the words under one of
// paths (the static operands of the call, as written).
type commandPathChange struct {
	end   int
	all   bool
	paths []string
}

// maxCommandPathBodyDepth is how deep CommandPathWords reads eval and -c
// bodies inside each other: the depth the action analysis reads nested shell
// strings to (actionfacts maxNestedShellStrings).
const maxCommandPathBodyDepth = 4

// CommandPathWords returns the static path words of a POSIX shell command
// in the order they appear. A word with an expansion, a pattern, a ~user or
// no value, and an option word, are not path words. Every word of the
// command is read: a caller that walks the words in the file system bounds
// its work by the distinct words (LocalCommandWordPlaces).
func CommandPathWords(command, home string) []CommandPathWord {
	var scan commandPathScan
	commandPathWordsIn(command, 0, 0, 0, home, &scan)
	words := scan.words
	slices.SortFunc(words, func(a, b CommandPathWord) int { return a.start - b.start })
	for index := range scan.changes {
		change := &scan.changes[index]
		// A change inside a loop runs before the loop's words in the next
		// round: it counts from the start of the outermost loop it is in.
		end := change.end
		for _, loop := range scan.loops {
			if loop[0] < end && end <= loop[1] {
				change.end = min(change.end, loop[0])
			}
		}
	}
	firstCalls := scan.functionFirstCalls()
	for index := range words {
		word := &words[index]
		// A function body runs when the function is first called: a change
		// after the body that ends before that call moves its words too
		// (rel-1-0-10:GAP-1286). The word's own statement, a later statement
		// of the body and a change after the call do not (rel-1-0-10:GAP-1308).
		body, calledAt := [2]int{}, -1
		if function := scan.functionAt(word.start); function >= 0 {
			body, calledAt = scan.functions[function].body, firstCalls[function]
			if calledAt < 0 {
				// No call is seen: every change after the body counts.
				calledAt = math.MaxInt
			}
		}
		for _, change := range scan.changes {
			if word.Unplaced {
				break
			}
			if change.end > word.start && (change.end <= body[1] || change.end > calledAt) {
				continue
			}
			if change.all {
				word.Unplaced = true
				break
			}
			for _, changed := range change.paths {
				if commandPathUnder(word.Value, changed) {
					word.Unplaced = true
					break
				}
			}
		}
	}
	return words
}

// functionAt is the index of the innermost function whose body holds byte
// at, or -1: of the bodies that hold it, the one that starts last, and of
// those the first defined. The bodies are indexed once (functionBodies);
// every word and call asks, and reading every body for each made a script
// of 550 small functions cost the actor's hook milliseconds (substrate-1
// GAP-1153).
func (scan *commandPathScan) functionAt(at int) int {
	bodies := scan.functionBodies()
	if !bodies.nested {
		return scan.functionAtEach(at)
	}
	// The last body that starts at or before at; a body that holds at is
	// that one or one that holds it.
	position, _ := slices.BinarySearch(bodies.starts, at+1)
	position--
	for position >= 0 && at >= scan.functions[bodies.order[position]].body[1] {
		position = bodies.parent[position]
	}
	if position < 0 {
		return -1
	}
	found := bodies.order[position]
	start := scan.functions[found].body[0]
	for holder := bodies.parent[position]; holder >= 0 && scan.functions[bodies.order[holder]].body[0] == start; holder = bodies.parent[holder] {
		found = min(found, bodies.order[holder])
	}
	return found
}

// functionAtEach is functionAt read from every body, for bodies that
// overlap without one holding the other.
func (scan *commandPathScan) functionAtEach(at int) int {
	found := -1
	for index, function := range scan.functions {
		if function.body[0] <= at && at < function.body[1] &&
			(found < 0 || function.body[0] > scan.functions[found].body[0]) {
			found = index
		}
	}
	return found
}

// commandPathBodies indexes the function bodies of a scan for functionAt.
type commandPathBodies struct {
	// count is how many functions the index holds.
	count int
	// order lists the functions by body start, then longest body first,
	// then first defined; starts holds their starts and parent, for each,
	// the position in order of the body that holds it (-1 for none).
	order, starts, parent []int
	// nested is set when every two bodies lie apart or one holds the other.
	nested bool
}

// functionBodies is the index of the scan's function bodies, made again
// when a function was added since.
func (scan *commandPathScan) functionBodies() *commandPathBodies {
	if scan.bodies != nil && scan.bodies.count == len(scan.functions) {
		return scan.bodies
	}
	bodies := &commandPathBodies{count: len(scan.functions), nested: true}
	bodies.order = make([]int, len(scan.functions))
	for index := range bodies.order {
		bodies.order[index] = index
	}
	slices.SortFunc(bodies.order, func(a, b int) int {
		x, y := scan.functions[a].body, scan.functions[b].body
		switch {
		case x[0] != y[0]:
			return x[0] - y[0]
		case x[1] != y[1]:
			return y[1] - x[1]
		}
		return a - b
	})
	bodies.starts = make([]int, len(bodies.order))
	bodies.parent = make([]int, len(bodies.order))
	var open []int
	for position, function := range bodies.order {
		body := scan.functions[function].body
		bodies.starts[position] = body[0]
		for len(open) > 0 && scan.functions[bodies.order[open[len(open)-1]]].body[1] <= body[0] {
			open = open[:len(open)-1]
		}
		bodies.parent[position] = -1
		if len(open) > 0 {
			if body[1] > scan.functions[bodies.order[open[len(open)-1]]].body[1] {
				bodies.nested = false
				break
			}
			bodies.parent[position] = open[len(open)-1]
		}
		open = append(open, position)
	}
	scan.bodies = bodies
	return bodies
}

// functionFirstCalls returns, for each function of the scan, the byte offset
// of the first call after its body that runs it, or -1 when none is seen: a
// call by its name, else (when there is none) a call this reading cannot
// name. A call inside another function's body runs when that function is
// first called; a function that reaches itself adds no call.
//
// A call outside every body counts at its own start, so the least such
// start past a body is found in the sorted starts of the calls of that name.
// A call inside a body is read through that function's first call, in the
// order the calls were seen, as before: which function a read reaches while
// another is being read decides what a cycle answers. Scanning every call
// for every function made a script of 550 small functions and as many
// dynamic calls cost the actor's hook 5 ms here (substrate-1 GAP-1153).
func (scan *commandPathScan) functionFirstCalls() []int {
	outer := make([]int, len(scan.calls))
	for index, call := range scan.calls {
		outer[index] = scan.functionAt(call.start)
	}
	// The calls of each name ("" for a call this reading cannot name): the
	// sorted starts of those outside every body and, in the order seen, the
	// indexes of those inside one.
	type nameCalls struct {
		top    []int
		nested []int
	}
	byName := map[string]*nameCalls{}
	for index, call := range scan.calls {
		calls := byName[call.name]
		if calls == nil {
			calls = &nameCalls{}
			byName[call.name] = calls
		}
		if outer[index] >= 0 {
			calls.nested = append(calls.nested, index)
		} else {
			calls.top = append(calls.top, call.start)
		}
	}
	for _, calls := range byName {
		slices.Sort(calls.top)
	}
	// earliest is the least of two offsets, -1 for none.
	earliest := func(a, b int) int {
		if a < 0 || b >= 0 && b < a {
			return b
		}
		return a
	}
	// topAfter is the least start of a call outside every body at or after
	// end, -1 for none.
	topAfter := func(calls *nameCalls, end int) int {
		if calls == nil {
			return -1
		}
		if at, _ := slices.BinarySearch(calls.top, end); at < len(calls.top) {
			return calls.top[at]
		}
		return -1
	}
	first := make([]int, len(scan.functions))
	const (
		unread = iota
		reading
		read
	)
	state := make([]int, len(scan.functions))
	var firstCall func(function int) int
	firstCall = func(function int) int {
		switch state[function] {
		case reading:
			return -1
		case read:
			return first[function]
		}
		state[function] = reading
		name, end := scan.functions[function].name, scan.functions[function].body[1]
		unnamedCalls := byName[""]
		var namedCalls *nameCalls
		if name != "" {
			namedCalls = byName[name]
		}
		named, unnamed := topAfter(namedCalls, end), topAfter(unnamedCalls, end)
		// The calls inside a body, by name or unnamed, in the order seen.
		var namedNested, unnamedNested []int
		if namedCalls != nil {
			namedNested = namedCalls.nested
		}
		if unnamedCalls != nil {
			unnamedNested = unnamedCalls.nested
		}
		for len(namedNested) > 0 || len(unnamedNested) > 0 {
			var index int
			if len(unnamedNested) == 0 || len(namedNested) > 0 && namedNested[0] < unnamedNested[0] {
				index, namedNested = namedNested[0], namedNested[1:]
			} else {
				index, unnamedNested = unnamedNested[0], unnamedNested[1:]
			}
			start := firstCall(outer[index])
			if start < 0 || start < end {
				continue
			}
			if scan.calls[index].name == "" {
				unnamed = earliest(unnamed, start)
			} else {
				named = earliest(named, start)
			}
		}
		if named < 0 {
			named = unnamed
		}
		first[function], state[function] = named, read
		return named
	}
	for function := range scan.functions {
		firstCall(function)
	}
	return first
}

// commandPathUnder reports a word value that lies under the changed path
// (the path itself or a name in it) as far as the spellings tell without a
// folder: two absolute or two plain relative spellings by their components,
// else by whether the changed path's last name is one of the word's names.
// A change it cannot tell apart from the word counts.
func commandPathUnder(word, changed string) bool {
	wordParts, changedParts := commandPathParts(word), commandPathParts(changed)
	if len(changedParts) == 0 {
		return true
	}
	if strings.HasPrefix(word, "/") == strings.HasPrefix(changed, "/") &&
		!slices.Contains(wordParts, "..") && !slices.Contains(changedParts, "..") {
		return len(changedParts) <= len(wordParts) && slices.Equal(changedParts, wordParts[:len(changedParts)])
	}
	return slices.Contains(wordParts, changedParts[len(changedParts)-1])
}

func commandPathParts(value string) []string {
	var parts []string
	for _, part := range strings.Split(path.Clean(value), "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	return parts
}

func commandPathWordsIn(text string, base int, quote byte, depth int, home string, scan *commandPathScan) {
	file, ok := shellparse.Parse(text)
	if !ok {
		return
	}
	add := func(word *syntax.Word, follows, program, unplaced bool) {
		if word == nil {
			return
		}
		value, static := StaticWord(word, home)
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if !static || value == "" || end > len(text) || start >= end {
			return
		}
		if strings.HasPrefix(value, "--") {
			// --name=VALUE: only a plain literal maps its value's bytes to
			// the source one to one.
			name, rest, found := strings.Cut(value, "=")
			if _, plain := plainLiteralWord(word); !plain || !found || rest == "" {
				return
			}
			start += len(name) + 1
			value = rest
		} else if strings.HasPrefix(value, "-") {
			return
		}
		if strings.HasPrefix(value, "~") || strings.ContainsAny(value, "\x00\r\n") {
			return
		}
		scan.words = append(scan.words, CommandPathWord{
			Text: text[start:end], Value: value, FollowsLink: follows, Program: program, Unplaced: unplaced,
			start: base + start, end: base + end, quote: quote,
		})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.ForClause, *syntax.WhileClause:
			scan.loops = append(scan.loops, [2]int{base + int(node.Pos().Offset()), base + int(node.End().Offset())})
		case *syntax.FuncDecl:
			if node.Body != nil {
				name := ""
				if node.Name != nil {
					name = node.Name.Value
				}
				scan.functions = append(scan.functions, commandPathFunction{name: name,
					body: [2]int{base + int(node.Body.Pos().Offset()), base + int(node.Body.End().Offset())}})
			}
		case *syntax.Stmt:
			for _, redirect := range node.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrInOut, syntax.RdrClob,
					syntax.RdrAll, syntax.AppAll:
					add(redirect.Word, true, false, false)
				}
			}
		case *syntax.CallExpr:
			program := ""
			if len(node.Args) > 0 {
				if value, static := StaticWord(node.Args[0], home); static {
					program = programBase(value)
				}
			}
			// The program a static prefix wrapper runs (sudo /bin/sh -c,
			// nice /usr/bin/python3) is a program word too, and it is the
			// program whose operands follow their links or not (command rm
			// key-link removes the link).
			values, static := make([]string, len(node.Args)), make([]bool, len(node.Args))
			for index, arg := range node.Args {
				values[index], static[index] = StaticWord(arg, home)
			}
			if len(node.Args) > 0 {
				start := base + int(node.Args[0].Pos().Offset())
				switch {
				case !static[0] || values[0] == "eval" || values[0] == "source" || values[0] == ".":
					scan.calls = append(scan.calls, commandPathCall{start: start})
				case values[0] != "" && !strings.Contains(values[0], "/"):
					scan.calls = append(scan.calls, commandPathCall{name: values[0], start: start})
				}
			}
			run, wrapped := actionfacts.StaticPrefixWrapperChild(values, static)
			child := 0
			if wrapped {
				child = run.Index
			}
			child = builtinChild(values, static, child)
			follows := commandFollowsOperandLinks(program, node.Args, home)
			replaced := commandReplacedOperand(program, node.Args, home)
			written := commandWrittenThroughOperand(program, node.Args, home)
			if child > 0 && child < len(node.Args) {
				childProgram := ""
				if static[child] {
					childProgram = programBase(values[child])
				}
				follows = commandFollowsOperandLinks(childProgram, node.Args[child:], home)
				if replaced = commandReplacedOperand(childProgram, node.Args[child:], home); replaced > 0 {
					replaced += child
				}
				if written = commandWrittenThroughOperand(childProgram, node.Args[child:], home); written > 0 {
					written += child
				}
			}
			change, elsewhere := commandCallPathChange(values, static, run, wrapped, node.Args, home)
			for index, arg := range node.Args {
				add(arg, index == 0 || index == written || follows && index != replaced, index == 0 || index == child,
					index >= elsewhere)
			}
			if change.all || len(change.paths) != 0 {
				change.end = base + int(node.End().Offset())
				scan.changes = append(scan.changes, change)
			}
			if depth < maxCommandPathBodyDepth {
				for _, body := range staticCommandBodies(program, node.Args) {
					commandPathWordsIn(body.text, base+body.offset, body.quote, depth+1, home, scan)
				}
			}
		}
		return true
	})
}

// commandCallPathChange reads one simple command (values and static as for
// StaticPrefixWrapperChild) for what it changes for the words after it
// (commandPathChange; end is left to the caller), and returns the index of
// its first argument that the call itself reads in another folder or root
// (len(args) when none).
func commandCallPathChange(values []string, static []bool, run actionfacts.PrefixWrapperRun, wrapped bool,
	args []*syntax.Word, home string) (commandPathChange, int) {
	elsewhere := len(values)
	at := 0
	if wrapped {
		at = run.Index
		if run.Dir != "" || run.DirUnknown {
			elsewhere = at
		}
	}
	at = builtinChild(values, static, at)
	if at >= len(values) {
		return commandPathChange{}, elsewhere
	}
	if !static[at] {
		// A dynamic program may do anything.
		return commandPathChange{all: true}, elsewhere
	}
	for _, wrapper := range values[:at] {
		if commandRunsElsewhere(programBase(wrapper)) {
			elsewhere = min(elsewhere, at)
		}
	}
	operands := func() commandPathChange {
		var change commandPathChange
		options := true
		for index := at + 1; index < len(values); index++ {
			value := values[index]
			switch {
			case !static[index]:
				return commandPathChange{all: true}
			case options && value == "--":
				options = false
			case options && strings.HasPrefix(value, "-"):
				if name, rest, found := strings.Cut(value, "="); found && strings.HasPrefix(name, "--") && rest != "" {
					change.paths = append(change.paths, rest)
				}
			case value != "":
				change.paths = append(change.paths, value)
			}
		}
		if len(change.paths) == 0 {
			// No static operand: the call has none to change, or it
			// takes them from where this reading cannot see.
			change.all = true
		}
		return change
	}
	hasOption := func(names ...string) bool {
		for _, value := range values[at+1:] {
			for _, name := range names {
				if value == name || strings.HasPrefix(name, "--") && strings.HasPrefix(value, name+"=") {
					return true
				}
			}
		}
		return false
	}
	program := programBase(values[at])
	switch program {
	case "cd", "pushd", "popd", "chdir":
		if len(values) == at+2 && static[at+1] {
			switch path.Clean(values[at+1]) {
			case ".", "/proc/self/cwd":
				// The folder it was in.
				return commandPathChange{}, elsewhere
			}
		}
		return commandPathChange{all: true}, elsewhere
	case "source", ".":
		return commandPathChange{all: true}, elsewhere
	case "eval":
		if at != 0 || len(staticCommandBodies(program, args)) != len(args)-1 {
			return commandPathChange{all: true}, elsewhere
		}
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		for index := at + 1; index+1 < len(values); index++ {
			if flag := values[index]; static[index] && strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") &&
				strings.Contains(flag, "c") {
				// The body's own statements are read where it is static.
				if at != 0 || len(staticCommandBodies(program, args)) == 0 {
					return commandPathChange{all: true}, elsewhere
				}
				break
			}
		}
	case "mv", "gmv", "ln", "gln", "rm", "grm", "unlink", "rmdir", "link", "rename", "cp", "gcp",
		"install", "ginstall", "shred":
		return operands(), elsewhere
	case "tar", "gtar", "bsdtar", "make", "gmake":
		if hasOption("-C", "--directory") {
			elsewhere = min(elsewhere, at+1)
		}
		if program == "tar" || program == "gtar" || program == "bsdtar" {
			return commandPathChange{all: true}, elsewhere
		}
	case "git":
		if hasOption("-C") {
			elsewhere = min(elsewhere, at+1)
		}
		if !gitReadOnlyCall(values[at+1:], static[at+1:]) {
			return commandPathChange{all: true}, elsewhere
		}
	case "find":
		if hasOption("-delete", "-exec", "-execdir", "-ok", "-okdir") {
			return commandPathChange{all: true}, elsewhere
		}
	case "unzip", "cpio", "rsync", "7z", "7za", "ar", "patch", "pax", "ditto", "xargs", "parallel", "busybox":
		return commandPathChange{all: true}, elsewhere
	case "env", "sudo", "doas", "runuser", "su":
		if !wrapped {
			// A wrapper call this reading does not unwrap may run its
			// child anywhere.
			return commandPathChange{all: true}, min(elsewhere, at+1)
		}
	}
	if commandRunsElsewhere(program) {
		elsewhere = min(elsewhere, at+1)
	}
	return commandPathChange{}, elsewhere
}

// builtinChild skips the builtin words at index at of a simple command
// (values and static as for StaticPrefixWrapperChild): builtin NAME runs the
// shell builtin NAME, so builtin cd is cd (rel-1-0-10:GAP-1286). A builtin
// with no word after it is left as the program.
func builtinChild(values []string, static []bool, at int) int {
	for at+1 < len(values) && static[at] && programBase(values[at]) == "builtin" {
		at++
	}
	return at
}

// commandRunsElsewhere reports a program that runs the words after it in
// another root, namespace or host, where this file system gives no place.
func commandRunsElsewhere(program string) bool {
	switch program {
	case "chroot", "nsenter", "unshare", "bwrap", "firejail", "proot", "systemd-nspawn", "ssh", "docker",
		"podman", "kubectl", "lxc-attach", "vagrant":
		return true
	}
	return false
}

// gitReadOnlyCall reports a git call (its arguments after git) whose
// subcommand leaves the work tree's files and links as they are.
func gitReadOnlyCall(values []string, static []bool) bool {
	for index := 0; index < len(values); index++ {
		value := values[index]
		switch {
		case !static[index]:
			return false
		case value == "-C" || value == "-c" || value == "--git-dir" || value == "--work-tree" || value == "--namespace":
			index++
		case strings.HasPrefix(value, "-"):
		default:
			switch value {
			case "status", "log", "diff", "show", "grep", "ls-files", "ls-tree", "rev-parse", "blame", "describe",
				"branch", "remote", "fetch", "config", "cat-file", "shortlog", "tag", "version", "help", "add",
				"commit", "push", "reflog", "rev-list", "for-each-ref", "show-ref", "whatchanged", "count-objects":
				return true
			}
			return false
		}
	}
	return true
}

// commandFollowsOperandLinks reports a program that opens the files its
// operands name, so a link that is an operand is followed; false for one
// that acts on the link itself.
func commandFollowsOperandLinks(program string, args []*syntax.Word, home string) bool {
	switch program {
	case "sed", "gsed":
		// sed -i writes a new file in place of the name: a link there is
		// replaced and its target left alone, unless --follow-symlinks
		// (sedFollowsInPlaceLinks). Without -i sed only reads.
		if !commandHasFlag(args, home, 'i', "--in-place") && !commandHasLongPrefix(args, home, "--in-place=") {
			return true
		}
		words := make([]string, 0, len(args))
		for _, arg := range args {
			value, _ := StaticWord(arg, home)
			words = append(words, value)
		}
		return sedFollowsInPlaceLinks(words)
	case "rm", "unlink", "mv", "ln", "ls", "stat", "lstat", "readlink", "find", "test", "[", "file",
		"rsync", "git", "lsattr":
		return false
	case "chown", "chgrp", "touch":
		return !commandHasFlag(args, home, 'h', "--no-dereference")
	case "cp", "gcp":
		return !commandHasFlag(args, home, 'P', "--no-dereference") && !commandHasFlag(args, home, 'd', "") &&
			!commandHasFlag(args, home, 'a', "--archive") && !commandHasFlag(args, home, 'R', "--recursive") &&
			!commandHasFlag(args, home, 'r', "") ||
			commandHasFlag(args, home, 'L', "--dereference") || commandHasFlag(args, home, 'H', "")
	case "tar", "zip":
		return commandHasFlag(args, home, 'h', "--dereference")
	}
	return true
}

// commandWrittenThroughOperand is the index in args (args[0] the program) of
// the operand a program writes through its link in every mode, or -1. cp's
// -a/-P/-d/-R/-r keep links among the sources, but the destination is opened
// for writing through an existing link (GNU cp writes the file it reaches),
// so a destination link to a protected file gets the plain form's verdict
// (rel-1-0-10:GAP-1287). The destination is the -t/--target-directory value
// when given, else the last operand. --remove-destination, -s and -l make a
// new entry in place of the name and leave a link there alone.
func commandWrittenThroughOperand(program string, args []*syntax.Word, home string) int {
	switch program {
	case "cp", "gcp":
	default:
		return -1
	}
	if commandHasFlag(args, home, 's', "--symbolic-link") || commandHasFlag(args, home, 'l', "--link") ||
		commandHasFlag(args, home, 0, "--remove-destination") {
		return -1
	}
	last := -1
	for index := 1; index < len(args); index++ {
		value, static := StaticWord(args[index], home)
		switch {
		case !static:
			last = -1
		case value == "--":
			for index++; index < len(args); index++ {
				last = index
			}
		case value == "-t" || value == "--target-directory":
			if index+1 < len(args) {
				return index + 1
			}
			return -1
		case strings.HasPrefix(value, "--target-directory="):
			return index
		case len(value) > 1 && value[0] == '-' && value[1] != '-' && strings.IndexByte(value[1:], 't') >= 0:
			// A bundle ending in t takes the next word (-at DIR); -tDIR
			// carries it in the word.
			if value[len(value)-1] == 't' {
				if index+1 < len(args) {
					return index + 1
				}
				return -1
			}
			return index
		case strings.HasPrefix(value, "-") && value != "-":
		default:
			last = index
		}
	}
	return last
}

// commandReplacedOperand is the index in args (args[0] the program) of the
// operand a program replaces as a name and does not open through its link,
// or -1. GNU install writes the destination file as a new file in
// place of the name: a link there is replaced and the file it reaches is
// left alone, while its source operands are read through their links
// (rel-1-0-10:GAP-1286). With -d every operand is a folder to make, and
// with -t the folder is the option's value: no operand is replaced.
func commandReplacedOperand(program string, args []*syntax.Word, home string) int {
	switch program {
	case "install", "ginstall":
	default:
		return -1
	}
	if len(args) < 3 || commandHasFlag(args, home, 'd', "--directory") ||
		commandHasFlag(args, home, 't', "--target-directory") || commandHasLongPrefix(args, home, "--target-directory=") {
		return -1
	}
	last := len(args) - 1
	value, static := StaticWord(args[last], home)
	if !static || value == "" || strings.HasPrefix(value, "-") {
		return -1
	}
	return last
}

// commandHasFlag reports a short flag in a bundle (-rP) or the long option.
func commandHasFlag(args []*syntax.Word, home string, short byte, long string) bool {
	for _, arg := range args[min(1, len(args)):] {
		value, static := StaticWord(arg, home)
		switch {
		case !static:
			continue
		case value == "--":
			return false
		case long != "" && value == long:
			return true
		case len(value) > 1 && value[0] == '-' && value[1] != '-' && strings.IndexByte(value[1:], short) >= 0:
			return true
		}
	}
	return false
}

// commandHasLongPrefix reports a long option written with its value
// (--in-place=.bak).
func commandHasLongPrefix(args []*syntax.Word, home, prefix string) bool {
	for _, arg := range args[min(1, len(args)):] {
		value, static := StaticWord(arg, home)
		switch {
		case !static:
			continue
		case value == "--":
			return false
		case strings.HasPrefix(value, prefix):
			return true
		}
	}
	return false
}

type staticCommandBody struct {
	text   string
	offset int
	quote  byte
}

// staticCommandBodies returns the bodies an eval runs, or a shell runs after
// -c, that the source spells as one single-quoted or plain double-quoted
// string: their bytes are the body's bytes, so a word of the body has a
// place in the command.
func staticCommandBodies(program string, args []*syntax.Word) []staticCommandBody {
	var candidates []*syntax.Word
	switch program {
	case "eval":
		candidates = args[1:]
	case "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox":
		for index := 1; index+1 < len(args); index++ {
			flag, plain := plainLiteralWord(args[index])
			if plain && strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && strings.Contains(flag, "c") {
				candidates = args[index+1 : index+2]
				break
			}
		}
	}
	var bodies []staticCommandBody
	for _, word := range candidates {
		if word == nil || len(word.Parts) != 1 {
			continue
		}
		switch part := word.Parts[0].(type) {
		case *syntax.SglQuoted:
			if !part.Dollar {
				bodies = append(bodies, staticCommandBody{text: part.Value, offset: int(part.Pos().Offset()) + 1, quote: '\''})
			}
		case *syntax.DblQuoted:
			if part.Dollar || len(part.Parts) != 1 {
				continue
			}
			if lit, ok := part.Parts[0].(*syntax.Lit); ok && !strings.ContainsAny(lit.Value, "\\$`") {
				bodies = append(bodies, staticCommandBody{text: lit.Value, offset: int(part.Pos().Offset()) + 1, quote: '"'})
			}
		}
	}
	return bodies
}

// CommandWordPlace is where a command word's path lies in the file system
// it runs in: Followed with every link followed, the last component too;
// Entry with its folders followed and its last name kept. Either is empty
// when it is the place the word spells.
type CommandWordPlace struct {
	Followed, Entry string
}

// LinkResolvedCommand returns command with each word CommandPathWords finds
// whose Text has a place in places spelled as that place (Followed where the
// command follows the word's link, else Entry): the command as the shell runs
// it once the file system has resolved its links. An unplaced word (its
// place may differ when the shell reaches it), a place that the word's
// quoting cannot carry as it is, and a word inside a word already replaced,
// are left as written. changed is false when no word was replaced.
func LinkResolvedCommand(command, home string, places map[string]CommandWordPlace) (string, bool) {
	if len(places) == 0 {
		return command, false
	}
	var out strings.Builder
	at, changed := 0, false
	for _, word := range CommandPathWords(command, home) {
		place, found := places[word.Text]
		if !found || word.Unplaced || word.start < at {
			continue
		}
		target := place.Entry
		if word.FollowsLink {
			target = place.Followed
		}
		if !path.IsAbs(target) || path.Clean(target) != target {
			continue
		}
		spelled, ok := shellPathSpelling(target, word.quote)
		if !ok {
			continue
		}
		out.WriteString(command[at:word.start])
		out.WriteString(spelled)
		at, changed = word.end, true
	}
	if !changed {
		return command, false
	}
	out.WriteString(command[at:])
	return out.String(), true
}

// shellPathSpelling spells an absolute path as one shell word: as it is when
// it holds only plain path bytes, else single-quoted at the top level. Inside
// a quoted body only the plain spelling keeps both readings the same.
func shellPathSpelling(target string, quote byte) (string, bool) {
	plain := true
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == '/', c == '-', c == ',', c == ':', c == '@', c == '%', c == '+':
		default:
			plain = false
		}
	}
	switch {
	case plain:
		return target, true
	case quote != 0 || strings.ContainsAny(target, "\x00\r\n"):
		return "", false
	}
	return "'" + strings.ReplaceAll(target, "'", `'\''`) + "'", true
}

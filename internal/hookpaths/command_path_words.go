// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"slices"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"

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
	start, end  int  // the byte offsets of Text in the command
	quote       byte // 0 at the top level; ' or " inside a quoted body
}

const (
	// maxCommandPathWords bounds the words read from one command.
	maxCommandPathWords = 64
	// maxCommandPathBodyDepth bounds the eval and -c bodies read inside
	// each other.
	maxCommandPathBodyDepth = 2
)

// CommandPathWords returns the static path words of a POSIX shell command
// in the order they appear, at most 64. A word with an expansion, a pattern,
// a ~user or no value, and an option word, are not path words.
func CommandPathWords(command, home string) []CommandPathWord {
	var words []CommandPathWord
	commandPathWordsIn(command, 0, 0, 0, home, &words)
	slices.SortFunc(words, func(a, b CommandPathWord) int { return a.start - b.start })
	return words
}

func commandPathWordsIn(text string, base int, quote byte, depth int, home string, words *[]CommandPathWord) {
	file, ok := shellparse.Parse(text)
	if !ok {
		return
	}
	add := func(word *syntax.Word, follows bool) {
		if len(*words) >= maxCommandPathWords || word == nil {
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
		*words = append(*words, CommandPathWord{
			Text: text[start:end], Value: value, FollowsLink: follows,
			start: base + start, end: base + end, quote: quote,
		})
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if len(*words) >= maxCommandPathWords {
			return false
		}
		switch node := node.(type) {
		case *syntax.Stmt:
			for _, redirect := range node.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.RdrIn, syntax.RdrInOut, syntax.RdrClob,
					syntax.RdrAll, syntax.AppAll:
					add(redirect.Word, true)
				}
			}
		case *syntax.CallExpr:
			program := ""
			if len(node.Args) > 0 {
				if value, static := StaticWord(node.Args[0], home); static {
					program = programBase(value)
				}
			}
			follows := commandFollowsOperandLinks(program, node.Args, home)
			for index, arg := range node.Args {
				add(arg, index == 0 || follows)
			}
			if depth < maxCommandPathBodyDepth {
				for _, body := range staticCommandBodies(program, node.Args) {
					commandPathWordsIn(body.text, base+body.offset, body.quote, depth+1, home, words)
				}
			}
		}
		return true
	})
}

// commandPathPrograms is how CommandPathWords reads a program's words, one
// spec string parsed once (separate literals would each add forms to the
// package's literal sweep, TestGAP0749BoundedSweepReadsEveryFormAndStaysInBudget):
// program=kind, where kind is
//   - name: acts on the link itself, never follows an operand link;
//   - h: follows unless -h or --no-dereference;
//   - copy: follows unless it keeps links (-P, -d, -a, -R, -r or their long
//     names), or when -L or -H asks for it;
//   - archive: follows only with -h or --dereference;
//   - eval: runs its arguments as a command body;
//   - shell: runs the body after -c.
//
// Any other program opens the files its operands name.
const commandPathPrograms = "rm=name unlink=name mv=name ln=name ls=name stat=name lstat=name readlink=name " +
	"find=name test=name [=name file=name rsync=name git=name lsattr=name chown=h chgrp=h touch=h " +
	"cp=copy gcp=copy tar=archive zip=archive eval=eval sh=shell bash=shell dash=shell zsh=shell ksh=shell " +
	"ash=shell busybox=shell"

// commandPathFlags are the flags each kind reads, as short:long pairs (an
// empty long has none): the flags that keep links, then those that follow.
const (
	commandPathNoFollowH    = "h:no-dereference"
	commandPathCopyKeeps    = "P:no-dereference d: a:archive R:recursive r:"
	commandPathCopyFollows  = "L:dereference H:"
	commandPathArchiveFlags = "h:dereference"
)

var commandPathKinds = sync.OnceValue(func() map[string]string {
	kinds := map[string]string{}
	for _, entry := range strings.Fields(commandPathPrograms) {
		program, kind, _ := strings.Cut(entry, "=")
		kinds[program] = kind
	}
	return kinds
})

// commandFollowsOperandLinks reports a program that opens the files its
// operands name, so a link that is an operand is followed; false for one
// that acts on the link itself.
func commandFollowsOperandLinks(program string, args []*syntax.Word, home string) bool {
	switch commandPathKinds()[program] {
	case "name":
		return false
	case "h":
		return !commandHasAnyFlag(args, home, commandPathNoFollowH)
	case "copy":
		return !commandHasAnyFlag(args, home, commandPathCopyKeeps) || commandHasAnyFlag(args, home, commandPathCopyFollows)
	case "archive":
		return commandHasAnyFlag(args, home, commandPathArchiveFlags)
	}
	return true
}

// commandHasAnyFlag reports one of the short:long flags of spec, a short one
// in a bundle (-rP) too, among the options before a `--`.
func commandHasAnyFlag(args []*syntax.Word, home, spec string) bool {
	for _, pair := range strings.Fields(spec) {
		short, long, _ := strings.Cut(pair, ":")
		for _, arg := range args[min(1, len(args)):] {
			value, static := StaticWord(arg, home)
			if !static {
				continue
			}
			if value == "--" {
				break
			}
			if long != "" && strings.HasPrefix(value, "--") && value[2:] == long ||
				len(value) > 1 && value[0] == '-' && value[1] != '-' && strings.Contains(value[1:], short) {
				return true
			}
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
	switch commandPathKinds()[program] {
	case "eval":
		candidates = args[1:]
	case "shell":
		for index := 1; index+1 < len(args); index++ {
			flag, plain := plainLiteralWord(args[index])
			if plain && strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && strings.IndexByte(flag, 'c') >= 0 {
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
// it once the file system has resolved its links. A place that the word's
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
		if !found || word.start < at {
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

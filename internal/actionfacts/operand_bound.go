// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// MaxOperandsPerCall is the most operands (and redirection targets) of one
// hook call, over all its statements, that the readers resolve with the file
// system (GAP-0943). Every operand costs a few reads of the file
// system, about a millisecond on a Windows host, so a call of thousands of
// operands kept the hook past its answer window while the gateway was up.
// Past this bound the call is unresolved and the policy tier decides (a
// visible alert in the default and permissive tiers, the evaluation-limit
// block in the strict tier). The bound limits the resolution work only: every
// word of the call is still matched as text.
const MaxOperandsPerCall = 1024

// BoundOperands reads command lexically (quotes, statement separators,
// heredoc bodies, no file system) and reports over when the call has more
// than MaxOperandsPerCall operands and redirection targets in all. reduced is
// then the command without the operands and redirections past that bound
// that droppable calls plain: droppable must hold only for a word that cannot
// name a protected file or link by itself, so that every other word, the
// program of each statement, the options and the first MaxOperandsPerCall
// operands stay, however many there are. When over is false reduced is
// command itself.
func BoundOperands(command string, droppable func(word string) bool) (reduced string, over bool) {
	// A call over the bound has more than MaxOperandsPerCall words of at
	// least a byte and a separator each.
	if len(command) < 2*MaxOperandsPerCall {
		return command, false
	}
	b := operandBounder{command: command, droppable: droppable, first: true}
	b.run()
	if !b.over {
		return command, false
	}
	return b.out.String(), true
}

type operandBounder struct {
	command   string
	droppable func(word string) bool
	out       strings.Builder
	n         int  // operands and redirection targets met
	over      bool // n passed MaxOperandsPerCall
	first     bool // the next word starts a statement
	heredocs  []heredocMark
}

// heredocMark is a here-document whose body starts at the next line.
type heredocMark struct {
	delimiter string
	tabs      bool // <<- ignores the tabs in front of the delimiter line
}

func (b *operandBounder) run() {
	command, n := b.command, len(b.command)
	for i := 0; i < n; {
		c := command[i]
		switch {
		case c == 0x20 || c == 0x09 || c == 0x0d:
			b.out.WriteByte(c)
			i++
			continue
		case statementSeparator(command, i):
			b.first = true
			b.out.WriteByte(c)
			i++
			if c == 0x0a && len(b.heredocs) > 0 {
				i = b.copyHeredocBodies(i)
			}
			continue
		}
		end := b.wordAt(i)
		word := command[i:end]
		switch {
		case hereDocWord(word):
			i = b.heredoc(word, end)
		case redirectWord(word):
			i = b.redirect(word, end)
		case b.first && assignmentWord(word):
			b.out.WriteString(word)
			i = end
		case b.first:
			b.first = false
			b.out.WriteString(word)
			i = end
		case len(word) > 1 && word[0] == 0x2d:
			// An option is no operand, and it may carry a path.
			b.out.WriteString(word)
			i = end
		default:
			b.operand(word)
			i = end
		}
	}
}

// operand counts word and writes it unless it is past the bound and plain.
func (b *operandBounder) operand(word string) {
	if b.countedTarget(word) {
		b.out.WriteString(word)
	}
}

// redirect handles the redirection word at command[i:end] (wordAt cuts a
// word at the next redirection written against it, so a word holds one). A
// file redirection counts its target as an operand and, past the bound with a
// plain target, is left out whole (the operator and the target together). A
// descriptor copy or close, a here-string and /dev names are no file operands.
// Bash writes the file of >&word and 1>&word when word is not a descriptor
// number or "-" (GAP-2143), so those two operators are file redirections
// then and descriptor copies otherwise.
func (b *operandBounder) redirect(word string, end int) int {
	command := b.command
	op, target := redirectParts(word)
	switch {
	case op == "<<<" || strings.HasPrefix(target, "/dev/"):
		b.out.WriteString(word)
		if target == "" && op == "<<<" {
			end = b.copyNextWord(end)
		}
	case strings.HasSuffix(op, "&") && !fileDuplicate(op, target):
		// A descriptor copy; a copy written with a blank takes its
		// descriptor from the next word.
		b.out.WriteString(word)
		if target == "" {
			end = b.copyNextWord(end)
		}
	case target != "":
		if b.countedTarget(target) {
			b.out.WriteString(word)
		}
	default:
		// The target is the next word.
		j := end
		for j < len(command) && (command[j] == 0x20 || command[j] == 0x09 || command[j] == 0x0d) {
			j++
		}
		if j >= len(command) || statementSeparator(command, j) {
			b.out.WriteString(word)
			return end
		}
		tend := b.wordAt(j)
		next := command[j:tend]
		if strings.HasPrefix(next, "/dev/") || redirectWord(next) {
			b.out.WriteString(word)
			return end
		}
		if strings.HasSuffix(op, "&") && !fileDuplicate(op, next) {
			b.out.WriteString(word)
			b.out.WriteString(command[end:tend])
			return tend
		}
		if b.countedTarget(next) {
			b.out.WriteString(word)
			b.out.WriteString(command[end:j])
			b.out.WriteString(next)
		}
		end = tend
	}
	return end
}

// fileDuplicate reports a >&word or 1>&word redirection (op with its
// descriptor) whose word is, or may be, a file name; an empty target is the
// next word, which the caller reads. A descriptor number, "-" and a word
// that expands without naming a folder stay descriptor copies, as the
// readers of the write targets decide it.
func fileDuplicate(op, target string) bool {
	if !strings.HasSuffix(op, ">&") {
		return false
	}
	if fd := strings.TrimSuffix(op, ">&"); fd != "" && fd != "1" {
		return false
	}
	switch {
	case target == "":
		return true
	case target == "-" || strings.Trim(target, "0123456789") == "":
		return false
	}
	return strings.ContainsAny(target, "/\\") || !strings.ContainsAny(target, "$`")
}

// countedTarget counts a file operand or target and reports whether it stays:
// a plain name past the bound does not.
func (b *operandBounder) countedTarget(target string) bool {
	b.n++
	if b.n > MaxOperandsPerCall {
		b.over = true
		return !b.droppable(target)
	}
	return true
}

// copyNextWord copies the blanks and the word after command[:end] as they
// are and returns the end of that word.
func (b *operandBounder) copyNextWord(end int) int {
	command := b.command
	j := end
	for j < len(command) && (command[j] == 0x20 || command[j] == 0x09 || command[j] == 0x0d) {
		j++
	}
	if j >= len(command) || statementSeparator(command, j) {
		return end
	}
	tend := b.wordAt(j)
	b.out.WriteString(command[end:tend])
	return tend
}

// heredoc writes a here-document operator (and its delimiter word when it
// is a word of its own) and notes the body that follows the line. The body
// is data for the program or a script for a shell, and it is no operand list.
func (b *operandBounder) heredoc(word string, end int) int {
	b.out.WriteString(word)
	rest := strings.TrimLeft(word, "0123456789")[2:]
	mark := heredocMark{}
	if strings.HasPrefix(rest, "-") {
		mark.tabs = true
		rest = rest[1:]
	}
	if rest == "" {
		next := b.copyNextWord(end)
		rest = strings.TrimSpace(b.command[end:next])
		end = next
	}
	mark.delimiter = strings.NewReplacer("\x27", "", "\"", "", "\\", "").Replace(rest)
	b.heredocs = append(b.heredocs, mark)
	return end
}

// copyHeredocBodies copies the bodies of the here-documents that started on
// the line before i, each through its delimiter line, and returns the index
// after them.
func (b *operandBounder) copyHeredocBodies(i int) int {
	command, n := b.command, len(b.command)
	for _, mark := range b.heredocs {
		for i < n {
			le := strings.IndexByte(command[i:], 0x0a)
			if le < 0 {
				le = n
			} else {
				le += i + 1
			}
			line := strings.TrimRight(command[i:le], "\r\n")
			b.out.WriteString(command[i:le])
			i = le
			if mark.tabs {
				line = strings.TrimLeft(line, "\t")
			}
			if line == mark.delimiter {
				break
			}
		}
	}
	b.heredocs = nil
	return i
}

// hereDocWord reports the operator of a here-document, not a here-string.
func hereDocWord(word string) bool {
	rest := strings.TrimLeft(word, "0123456789")
	return strings.HasPrefix(rest, "<<") && !strings.HasPrefix(rest, "<<<")
}

// assignmentWord reports NAME=value.
func assignmentWord(word string) bool {
	eq := strings.IndexByte(word, 0x3d)
	if eq <= 0 {
		return false
	}
	for k := 0; k < eq; k++ {
		c := word[k]
		digit := c >= 0x30 && c <= 0x39
		if c != 0x5f && (c < 0x41 || c > 0x5a) && (c < 0x61 || c > 0x7a) && (k == 0 || !digit) {
			return false
		}
	}
	return true
}

// redirectParts splits a redirection piece into its operator (an optional
// descriptor and the operator characters) and the target written with it.
func redirectParts(piece string) (op, target string) {
	rest := strings.TrimLeft(piece, "0123456789")
	rest = strings.TrimLeft(rest, "<>&|")
	return piece[:len(piece)-len(rest)], rest
}

// statementSeparator reports a byte of command that ends a statement: a
// line break, a semicolon, a pipe, a parenthesis, or a background ampersand
// (not the one of a redirection such as 2>&1 or &>).
func statementSeparator(command string, i int) bool {
	switch command[i] {
	case 0x0a, 0x3b, 0x7c, 0x28, 0x29:
		return true
	case 0x26:
		return (i == 0 || command[i-1] != 0x3e && command[i-1] != 0x3c) &&
			(i+1 >= len(command) || command[i+1] != 0x3e)
	}
	return false
}

// wordEnd is the end of the word that starts at i: it runs to the next blank
// or statement separator outside quotes; a backslash or backtick escapes the
// next byte.
func wordEnd(command string, i int) int {
	n := len(command)
	var quote byte
	for j := i; j < n; j++ {
		c := command[j]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == 0x5c && quote == 0x22 && j+1 < n:
				j++
			}
		case c == 0x27 || c == 0x22:
			quote = c
		case (c == 0x5c || c == 0x60) && j+1 < n && command[j+1] != 0x0a:
			j++
		case c == 0x20 || c == 0x09 || c == 0x0d || statementSeparator(command, j):
			if j > i {
				return j
			}
		}
	}
	return n
}

// wordAt is the end of the word at i, cut where a redirection operator
// written against it begins: the shell reads echo x>f>g as the words echo and
// x and the redirections >f and >g, so each target counts on its own
// (GAP-0943).
func (b *operandBounder) wordAt(i int) int {
	end := wordEnd(b.command, i)
	if k := attachedRedirect(b.command[i:end]); k > 0 {
		return i + k
	}
	return end
}

// attachedRedirect is the index in word of the first redirection operator
// that is written against a word before it (>, <, &>, outside quotes and
// escapes), or 0 when there is none. A file descriptor number in front of an
// operator, and the target after one, belong to that redirection: 2>&1 and
// >f are one redirection each, >f>g are two.
func attachedRedirect(word string) int {
	var quote byte
	for j := 0; j < len(word); j++ {
		c := word[j]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == 0x5c && quote == 0x22 && j+1 < len(word):
				j++
			}
		case c == 0x27 || c == 0x22:
			quote = c
		case (c == 0x5c || c == 0x60) && j+1 < len(word):
			j++
		case c == 0x3e || c == 0x3c:
			k := j
			if k > 0 && word[k-1] == 0x26 {
				k--
			}
			if k > 0 && strings.Trim(word[:k], "0123456789") != "" {
				return k
			}
			// The operator starts the word, or follows a descriptor number:
			// step over its characters, the target comes next.
			for j+1 < len(word) && strings.IndexByte("<>&|", word[j+1]) >= 0 {
				j++
			}
		}
	}
	return 0
}

// redirectWord reports a word that starts a redirection: an optional file
// descriptor and one of the redirection operators.
func redirectWord(word string) bool {
	rest := strings.TrimLeft(word, "0123456789")
	return strings.HasPrefix(rest, ">") || strings.HasPrefix(rest, "<") || strings.HasPrefix(rest, "&>")
}

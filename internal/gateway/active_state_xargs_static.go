// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// maxXargsStaticItems bounds the input items a static xargs twin spells out.
const maxXargsStaticItems = 64

// The static xargs twin (rel-1-0-5 GAP-0052, pod check30) computes the
// bytes a printf, echo or here-string writes to xargs, splits them the way
// xargs does (blanks and quotes by default, lines under -I, the -0/-d byte),
// and spells the call xargs makes with each item as a single-quoted literal.
// It is used when every word is fixed (literal, quoted, ~ and plain $HOME);
// otherwise the word twin (xargsCallTwin) is used as before.

// xargsHomeFixed reports a command that names HOME only as a plain $HOME
// or ${HOME} expansion, so ~ and $HOME are the active home.
func xargsHomeFixed(command string) bool {
	rest := strings.NewReplacer("${HOME}", "", "$HOME", "").Replace(command)
	return !strings.Contains(rest, "HOME")
}

// xargsPlainHome reports $HOME or ${HOME} with no operator.
func xargsPlainHome(parameter *syntax.ParamExp) bool {
	return parameter.Param != nil && parameter.Param.Value == "HOME" &&
		parameter.Flags == nil && !parameter.Excl && !parameter.Length &&
		!parameter.Width && !parameter.IsSet && parameter.NestedParam == nil &&
		parameter.Index == nil && len(parameter.Modifiers) == 0 &&
		parameter.Slice == nil && parameter.Repl == nil &&
		parameter.Names == 0 && parameter.Exp == nil
}

// xargsStaticValue is the one argument the shell makes of word when it is
// fixed: literal and quoted text, a leading ~ or ~/ and plain $HOME or
// ${HOME} (home). False for any other expansion, a glob or a brace list.
func xargsStaticValue(word *syntax.Word, home string) (string, bool) {
	if word == nil || !strings.HasPrefix(home, "/") || strings.ContainsAny(home, " \t\n*?[") {
		return "", false
	}
	var text strings.Builder
	for index, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			value := typed.Value
			if index == 0 && strings.HasPrefix(value, "~") {
				if value != "~" && !strings.HasPrefix(value, "~/") {
					return "", false
				}
				text.WriteString(home)
				value = value[1:]
			}
			if strings.Contains(value, "{") && (strings.Contains(value, ",") || strings.Contains(value, "..")) {
				return "", false
			}
			for at := 0; at < len(value); at++ {
				char := value[at : at+1]
				if char == "\\" {
					if at+1 < len(value) {
						at++
						text.WriteByte(value[at])
					}
					continue
				}
				if strings.Contains("*?[", char) {
					return "", false
				}
				text.WriteString(char)
			}
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", false
			}
			text.WriteString(typed.Value)
		case *syntax.DblQuoted:
			if typed.Dollar {
				return "", false
			}
			for _, inner := range typed.Parts {
				switch quoted := inner.(type) {
				case *syntax.Lit:
					text.WriteString(xargsDoubleQuotedText(quoted.Value))
				case *syntax.ParamExp:
					if !xargsPlainHome(quoted) {
						return "", false
					}
					text.WriteString(home)
				default:
					return "", false
				}
			}
		case *syntax.ParamExp:
			if !xargsPlainHome(typed) {
				return "", false
			}
			text.WriteString(home)
		default:
			return "", false
		}
	}
	return text.String(), true
}

// xargsDoubleQuotedText is the text of a literal inside double quotes: a
// backslash quotes only $, `, ", \ and a newline.
func xargsDoubleQuotedText(value string) string {
	var text strings.Builder
	for at := 0; at < len(value); at++ {
		if value[at:at+1] == "\\" && at+1 < len(value) && strings.Contains("$`\"\\\n", value[at+1:at+2]) {
			at++
			if value[at:at+1] != "\n" {
				text.WriteByte(value[at])
			}
			continue
		}
		text.WriteByte(value[at])
	}
	return text.String()
}

// staticPrintedText is the output of a printf or echo call whose words are
// all fixed.
func staticPrintedText(call *syntax.CallExpr, home string) (string, bool) {
	if len(call.Assigns) != 0 || len(call.Args) < 2 {
		return "", false
	}
	values := make([]string, 0, len(call.Args)-1)
	for _, arg := range call.Args[1:] {
		value, ok := xargsStaticValue(arg, home)
		if !ok {
			return "", false
		}
		values = append(values, value)
	}
	switch call.Args[0].Lit() {
	case "printf":
		return printfStaticOutput(values)
	case "echo":
		return echoStaticOutput(values)
	}
	return "", false
}

// printfStaticOutput is what printf FORMAT ARGS prints when FORMAT uses
// only %s, %% and the common escapes; the format is reused while ARGS
// remain, as printf does.
func printfStaticOutput(values []string) (string, bool) {
	if len(values) > 0 && values[0] == "--" {
		values = values[1:]
	}
	if len(values) == 0 || strings.HasPrefix(values[0], "-") {
		return "", false
	}
	format, args := values[0], values[1:]
	var out strings.Builder
	next := 0
	for {
		conversions := 0
		for at := 0; at < len(format); at++ {
			switch format[at : at+1] {
			case "\\":
				decoded, width, ok := xargsEscape(format[at+1:], false)
				if !ok {
					return "", false
				}
				out.WriteString(decoded)
				at += width
			case "%":
				if at+1 >= len(format) {
					return "", false
				}
				switch format[at+1 : at+2] {
				case "%":
					out.WriteString("%")
				case "s":
					if next < len(args) {
						out.WriteString(args[next])
					}
					next++
					conversions++
				case "b":
					// %b prints its argument with the echo -e escapes
					// interpreted; \c stops all output (pod check31).
					if next < len(args) {
						decoded, stop, ok := printfBArgument(args[next])
						if !ok {
							return "", false
						}
						out.WriteString(decoded)
						if stop {
							return out.String(), true
						}
					}
					next++
					conversions++
				default:
					return "", false
				}
				at++
			default:
				out.WriteByte(format[at])
			}
			if out.Len() > maxHereStringTwinBytes {
				return "", false
			}
		}
		if conversions == 0 || next >= len(args) {
			return out.String(), true
		}
	}
}

// printfBArgument is a printf %b argument with its escapes decoded (\0NNN
// octal, as echo -e); stop is true at \c.
func printfBArgument(value string) (string, bool, bool) {
	var out strings.Builder
	for at := 0; at < len(value); at++ {
		if value[at] != '\\' {
			out.WriteByte(value[at])
			continue
		}
		if at+1 < len(value) && value[at+1] == 'c' {
			return out.String(), true, true
		}
		decoded, width, ok := xargsEscape(value[at+1:], true)
		if !ok {
			return "", false, false
		}
		out.WriteString(decoded)
		at += width
	}
	return out.String(), false, true
}

// echoStaticOutput is what echo [-neE] WORDS prints.
func echoStaticOutput(values []string) (string, bool) {
	interpret, newline := false, true
	index := 0
	for ; index < len(values); index++ {
		value := values[index]
		if len(value) < 2 || value[:1] != "-" || strings.Trim(value[1:], "neE") != "" {
			break
		}
		for _, flag := range value[1:] {
			switch string(flag) {
			case "n":
				newline = false
			case "e":
				interpret = true
			case "E":
				interpret = false
			}
		}
	}
	text := strings.Join(values[index:], " ")
	if interpret {
		var out strings.Builder
		for at := 0; at < len(text); at++ {
			if text[at:at+1] != "\\" {
				out.WriteByte(text[at])
				continue
			}
			if at+1 < len(text) && text[at+1:at+2] == "c" {
				return out.String(), true
			}
			decoded, width, ok := xargsEscape(text[at+1:], true)
			if !ok {
				return "", false
			}
			out.WriteString(decoded)
			at += width
		}
		text = out.String()
	}
	if newline {
		text += "\n"
	}
	return text, true
}

var xargsSimpleEscapes = map[string]string{
	"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "\"": "\"",
}

// xargsEscape decodes the backslash escape whose text follows the
// backslash in rest: the decoded text and how many bytes of rest it used.
// echo -e writes an octal escape as \0NNN, printf as \NNN; \x, \u and \e
// are refused, and echo prints any other escape as written.
func xargsEscape(rest string, echo bool) (string, int, bool) {
	if rest == "" {
		return "\\", 0, true
	}
	head := rest[:1]
	if decoded, ok := xargsSimpleEscapes[head]; ok {
		return decoded, 1, true
	}
	if strings.Contains("01234567", head) && (!echo || head == "0") {
		start, limit := 0, 3
		if echo {
			start, limit = 1, 4
		}
		end := start
		for end < len(rest) && end < limit && strings.Contains("01234567", rest[end:end+1]) {
			end++
		}
		if end == start {
			return "\x00", end, true
		}
		code, err := strconv.ParseUint(rest[start:end], 8, 16)
		if err != nil || code > 255 {
			return "", 0, false
		}
		return string([]byte{byte(code)}), end, true
	}
	if strings.Contains("xuUeE", head) || !echo {
		return "", 0, false
	}
	return "\\" + head, 1, true
}

// xargsStaticOptions is how an xargs call reads its input.
type xargsStaticOptions struct {
	// delimiter is the one input separator (-0, -d); empty means blanks and
	// newlines with quote and backslash processing.
	delimiter string
	// lines: under -I an item is a whole input line.
	lines   bool
	replace string
}

// parseXargsStaticOptions reads the options of an xargs call: the input
// mode and the index of the program word. False for an option it does not
// know or one that reads another input (-a).
func parseXargsStaticOptions(call *syntax.CallExpr) (xargsStaticOptions, int, bool) {
	var options xargsStaticOptions
	if len(call.Assigns) != 0 || len(call.Args) < 2 || call.Args[0].Lit() != "xargs" {
		return options, 0, false
	}
	nextValue := func(index *int) (string, bool) {
		*index++
		if *index >= len(call.Args) {
			return "", false
		}
		return staticWordText(call.Args[*index])
	}
	index := 1
	for ; index < len(call.Args); index++ {
		option, ok := staticWordText(call.Args[index])
		if !ok {
			return options, 0, false
		}
		if option == "--" {
			index++
			break
		}
		if !strings.HasPrefix(option, "-") || option == "-" {
			break
		}
		if strings.HasPrefix(option, "--") {
			name, value, hasValue := strings.Cut(option[2:], "=")
			switch name {
			case "null":
				options.delimiter = "\x00"
			case "no-run-if-empty", "verbose", "exit", "interactive", "open-tty":
			case "max-args", "max-procs", "max-chars", "delimiter", "process-slot-var":
				if !hasValue {
					if value, ok = nextValue(&index); !ok {
						return options, 0, false
					}
				}
				if name == "delimiter" {
					if options.delimiter, ok = xargsDelimiter(value); !ok {
						return options, 0, false
					}
				}
			case "max-lines", "eof":
			case "replace":
				options.replace, options.lines = "{}", true
				if hasValue {
					options.replace = value
				}
			default:
				return options, 0, false
			}
			continue
		}
		for at := 1; at < len(option); at++ {
			flag := option[at : at+1]
			switch {
			case strings.Contains("0rtxpo", flag):
				if flag == "0" {
					options.delimiter = "\x00"
				}
			case strings.Contains("nPsLIdE", flag):
				value := option[at+1:]
				if value == "" {
					if value, ok = nextValue(&index); !ok {
						return options, 0, false
					}
				}
				switch flag {
				case "I":
					options.replace, options.lines = value, true
				case "d":
					if options.delimiter, ok = xargsDelimiter(value); !ok {
						return options, 0, false
					}
				}
				at = len(option)
			case strings.Contains("lie", flag):
				if flag == "i" {
					options.replace, options.lines = "{}", true
					if value := option[at+1:]; value != "" {
						options.replace = value
					}
				}
				at = len(option)
			default:
				return options, 0, false
			}
		}
	}
	if index >= len(call.Args) || options.lines && options.replace == "" {
		return options, 0, false
	}
	return options, index, true
}

// xargsDelimiter decodes an xargs -d value: one character or one escape.
func xargsDelimiter(value string) (string, bool) {
	if len(value) == 1 {
		return value, true
	}
	if len(value) < 2 || value[:1] != "\\" {
		return "", false
	}
	if strings.HasPrefix(value, "\\x") {
		code, err := strconv.ParseUint(value[2:], 16, 8)
		return string([]byte{byte(code)}), err == nil
	}
	decoded, width, ok := xargsEscape(value[1:], false)
	return decoded, ok && width == len(value)-1 && len(decoded) == 1
}

// xargsStaticItems splits the xargs input the way xargs does.
func xargsStaticItems(input string, options xargsStaticOptions) ([]string, bool) {
	if options.delimiter != "" {
		items := strings.Split(input, options.delimiter)
		if items[len(items)-1] == "" {
			items = items[:len(items)-1]
		}
		return items, true
	}
	var items []string
	var item strings.Builder
	have, quote := false, ""
	for at := 0; at < len(input); at++ {
		char := input[at : at+1]
		switch {
		case quote != "":
			if char == "\n" {
				return nil, false
			}
			if char == quote {
				quote = ""
				continue
			}
			item.WriteString(char)
		case char == "\\":
			if at+1 < len(input) {
				at++
				item.WriteByte(input[at])
				have = true
			}
		case char == "\x27" || char == "\"":
			quote, have = char, true
		case char == "\n" || !options.lines && (char == " " || char == "\t"):
			if have {
				items = append(items, item.String())
			}
			item.Reset()
			have = false
		case options.lines && !have && (char == " " || char == "\t"):
		default:
			item.WriteString(char)
			have = true
		}
	}
	if quote != "" {
		return nil, false
	}
	if have {
		items = append(items, item.String())
	}
	return items, true
}

// xargsQuotedWord is a shell word whose value is text.
func xargsQuotedWord(text string) *syntax.Word {
	word := &syntax.Word{}
	for index, piece := range strings.Split(text, "\x27") {
		if index > 0 {
			word.Parts = append(word.Parts, &syntax.Lit{Value: "\\\x27"})
		}
		if piece != "" {
			word.Parts = append(word.Parts, &syntax.SglQuoted{Value: piece})
		}
	}
	if len(word.Parts) == 0 {
		word.Parts = append(word.Parts, &syntax.SglQuoted{})
	}
	return word
}

// xargsStaticCallTwin is the call (or the calls, under -I) xargs makes
// with the static input: PROG ARGS... ITEMS, or one PROG call per item with
// the replace string substituted in every argument that holds it (a quoted
// "{}" and an sh -c script included).
func xargsStaticCallTwin(call *syntax.CallExpr, input, home string) (syntax.Command, bool) {
	options, index, ok := parseXargsStaticOptions(call)
	if !ok {
		return nil, false
	}
	items, ok := xargsStaticItems(input, options)
	if !ok || len(items) == 0 || len(items) > maxXargsStaticItems {
		return nil, false
	}
	for _, item := range items {
		if strings.Contains(item, "\x00") {
			return nil, false
		}
	}
	if options.replace == "" {
		args := append(make([]*syntax.Word, 0, len(call.Args)-index+len(items)), call.Args[index:]...)
		for _, item := range items {
			args = append(args, xargsQuotedWord(item))
		}
		return &syntax.CallExpr{Args: args}, true
	}
	calls := make([]*syntax.Stmt, 0, len(items))
	for _, item := range items {
		args := make([]*syntax.Word, 0, len(call.Args)-index)
		for _, arg := range call.Args[index:] {
			value, static := xargsStaticValue(arg, home)
			if !static {
				var source strings.Builder
				if err := syntax.NewPrinter().Print(&source, arg); err != nil ||
					strings.Contains(source.String(), options.replace) {
					return nil, false
				}
				args = append(args, arg)
				continue
			}
			if !strings.Contains(value, options.replace) {
				args = append(args, arg)
				continue
			}
			args = append(args, xargsQuotedWord(strings.ReplaceAll(value, options.replace, item)))
		}
		calls = append(calls, &syntax.Stmt{Cmd: &syntax.CallExpr{Args: args}})
	}
	if len(calls) == 1 {
		return calls[0].Cmd, true
	}
	return &syntax.Block{Stmts: calls}, true
}

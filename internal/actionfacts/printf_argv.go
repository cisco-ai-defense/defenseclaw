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

import "strings"

// StaticOutputSegment is a byte-exact output run surrounded by either a known
// stream boundary or opaque transformed bytes.
type StaticOutputSegment struct {
	Value      string
	LeftExact  bool
	RightExact bool
}

// StaticPOSIXPrintfFormatStdoutSegments returns maximal contiguous stdout
// segments whose bytes are fixed by a direct, format-only POSIX printf. It
// accepts the portable format intersection shared by trusted system printf
// implementations. Bare conversions with deterministic missing-operand output
// are folded into the exact run; other validated conversions form opaque
// segment boundaries.
func StaticPOSIXPrintfFormatStdoutSegments(command CommandFact) []StaticOutputSegment {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		!command.ArgvComplete || command.ParentCommandID != 0 ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 ||
		command.Program != "printf" || len(command.Argv) < 2 ||
		command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "printf") ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[index] {
			return nil
		}
	}

	var format string
	switch len(command.Argv) {
	case 2:
		format = command.Argv[1]
		if strings.HasPrefix(format, "-") {
			return nil
		}
	case 3:
		if command.Argv[1] != "--" {
			return nil
		}
		format = command.Argv[2]
	default:
		return nil
	}
	return staticPOSIXPrintfFormatStdoutSegments(format)
}

func staticPOSIXPrintfFormatStdoutSegments(format string) []StaticOutputSegment {
	segments := make([]StaticOutputSegment, 0, 2)
	var literal strings.Builder
	literalLeftExact := true
	projectedBytes := 0
	flushLiteral := func(rightExact bool) {
		if literal.Len() == 0 {
			return
		}
		segments = append(segments, StaticOutputSegment{
			Value:      literal.String(),
			LeftExact:  literalLeftExact,
			RightExact: rightExact,
		})
		literal.Reset()
	}
	writeLiteralByte := func(value byte) bool {
		projectedBytes++
		if projectedBytes > maxScalarBytes {
			return false
		}
		literal.WriteByte(value)
		return true
	}

	for index := 0; index < len(format); index++ {
		switch format[index] {
		case '%':
			if index+1 < len(format) && format[index+1] == '%' {
				if !writeLiteralByte('%') {
					return nil
				}
				index++
				continue
			}
			conversion, ok := parseStaticPOSIXPrintfConversion(format, index+1)
			if !ok {
				return nil
			}
			if conversion.exact {
				for valueIndex := 0; valueIndex < len(conversion.exactValue); valueIndex++ {
					if !writeLiteralByte(conversion.exactValue[valueIndex]) {
						return nil
					}
				}
				index = conversion.end - 1
				continue
			}
			flushLiteral(false)
			literalLeftExact = false
			projectedBytes += conversion.projectedBytes
			if projectedBytes > maxScalarBytes {
				return nil
			}
			index = conversion.end - 1
		case '\\':
			value, end, ok := decodeStaticPOSIXPrintfEscape(format, index+1)
			if !ok || !writeLiteralByte(value) {
				return nil
			}
			index = end - 1
		default:
			if !writeLiteralByte(format[index]) {
				return nil
			}
		}
	}
	flushLiteral(true)
	return segments
}

type staticPOSIXPrintfConversion struct {
	end            int
	projectedBytes int
	exact          bool
	exactValue     string
}

func parseStaticPOSIXPrintfConversion(
	format string,
	index int,
) (staticPOSIXPrintfConversion, bool) {
	if index >= len(format) {
		return staticPOSIXPrintfConversion{}, false
	}

	var flagsSet, plus, space, alternate, zero bool
	for index < len(format) {
		switch format[index] {
		case '-':
		case '+':
			plus = true
		case ' ':
			space = true
		case '#':
			alternate = true
		case '0':
			zero = true
		default:
			goto width
		}
		flagsSet = true
		index++
	}

width:
	widthValue, widthSet, next, ok := staticPOSIXPrintfDecimal(format, index)
	if !ok {
		return staticPOSIXPrintfConversion{}, false
	}
	index = next

	precisionValue := 0
	precisionSet := false
	if index < len(format) && format[index] == '.' {
		precisionSet = true
		index++
		precisionValue, _, index, ok = staticPOSIXPrintfDecimal(format, index)
		if !ok {
			return staticPOSIXPrintfConversion{}, false
		}
	}
	if index >= len(format) {
		return staticPOSIXPrintfConversion{}, false
	}

	conversion := format[index]
	switch conversion {
	case 'b', 'c', 'd', 'i', 'o', 's', 'u', 'x', 'X':
	default:
		return staticPOSIXPrintfConversion{}, false
	}
	if (plus || space) && conversion != 'd' && conversion != 'i' ||
		alternate && conversion != 'o' && conversion != 'x' && conversion != 'X' ||
		zero && conversion != 'd' && conversion != 'i' && conversion != 'o' &&
			conversion != 'u' && conversion != 'x' && conversion != 'X' ||
		precisionSet && conversion == 'c' ||
		precisionSet && precisionValue == 0 && (conversion == 'x' || conversion == 'X') {
		return staticPOSIXPrintfConversion{}, false
	}

	projected := 0
	if widthSet {
		projected = widthValue
	}
	switch conversion {
	case 'b', 's':
		// A missing string operand is empty, so only field padding contributes.
	case 'c':
		projected = max(projected, 1)
	default:
		digits := 1
		if precisionSet {
			digits = max(digits, precisionValue)
		}
		// Sign and alternate-form prefixes contribute no more than two bytes.
		projected = max(projected, digits+2)
	}
	parsed := staticPOSIXPrintfConversion{
		end:            index + 1,
		projectedBytes: projected,
	}
	if !flagsSet && !widthSet && !precisionSet {
		switch conversion {
		case 'b', 's':
			parsed.exact = true
		case 'd', 'o', 'u', 'x', 'X':
			parsed.exact = true
			parsed.exactValue = "0"
		}
	}
	return parsed, true
}

func staticPOSIXPrintfDecimal(
	format string,
	index int,
) (value int, present bool, end int, ok bool) {
	end = index
	for end < len(format) && format[end] >= '0' && format[end] <= '9' {
		present = true
		digit := int(format[end] - '0')
		if value > (maxScalarBytes-digit)/10 {
			return 0, false, index, false
		}
		value = value*10 + digit
		end++
	}
	return value, present, end, true
}

func decodeStaticPOSIXPrintfEscape(
	format string,
	index int,
) (value byte, end int, ok bool) {
	if index >= len(format) {
		return 0, index, false
	}
	switch format[index] {
	case '\\':
		return '\\', index + 1, true
	case 'a':
		return '\a', index + 1, true
	case 'b':
		return '\b', index + 1, true
	case 'f':
		return '\f', index + 1, true
	case 'n':
		return '\n', index + 1, true
	case 'r':
		return '\r', index + 1, true
	case 't':
		return '\t', index + 1, true
	case 'v':
		return '\v', index + 1, true
	}
	if format[index] < '0' || format[index] > '7' {
		return 0, index, false
	}

	octal := int(format[index] - '0')
	end = index + 1
	for digits := 1; digits < 3 && end < len(format); digits++ {
		next := format[end]
		if next < '0' || next > '7' {
			break
		}
		octal = octal*8 + int(next-'0')
		end++
	}
	if octal > 0xff {
		return 0, index, false
	}
	return byte(octal), end, true
}

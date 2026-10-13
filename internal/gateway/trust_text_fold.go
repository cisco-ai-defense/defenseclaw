// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// trustPatternText folds common script look-alikes only for the TRUST rule
// pass. The original content remains available to all other detectors.
func trustPatternText(value string) string {
	if strings.IndexFunc(value, func(r rune) bool { return r >= utf8.RuneSelf }) < 0 {
		return value
	}
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || r == '\u00ad' || r == '\u034f' ||
			r >= '\ufe00' && r <= '\ufe0f' {
			return -1
		}
		switch r {
		case 'а', 'α':
			return 'a'
		case 'А', 'Α':
			return 'A'
		case 'е', 'ε':
			return 'e'
		case 'Е', 'Ε':
			return 'E'
		case 'о', 'ο':
			return 'o'
		case 'О', 'Ο':
			return 'O'
		case 'р', 'ρ':
			return 'p'
		case 'Р', 'Ρ':
			return 'P'
		case 'с', 'ϲ':
			return 'c'
		case 'С', 'Ϲ':
			return 'C'
		case 'х', 'χ':
			return 'x'
		case 'Х', 'Χ':
			return 'X'
		case 'у', 'υ':
			return 'y'
		case 'У', 'Υ':
			return 'Y'
		case 'і', 'ι':
			return 'i'
		case 'І', 'Ι':
			return 'I'
		case 'ј':
			return 'j'
		case 'Ј':
			return 'J'
		case 'к', 'κ':
			return 'k'
		case 'К', 'Κ':
			return 'K'
		case 'м', 'μ':
			return 'm'
		case 'М', 'Μ':
			return 'M'
		case 'н', 'η':
			return 'h'
		case 'Н', 'Η':
			return 'H'
		case 'т', 'τ':
			return 't'
		case 'Т', 'Τ':
			return 'T'
		case 'в', 'β':
			return 'b'
		case 'В', 'Β':
			return 'B'
		case 'ν':
			return 'v'
		case 'Ν':
			return 'N'
		case 'Ζ':
			return 'Z'
		case 'ζ':
			return 'z'
		default:
			return r
		}
	}, norm.NFKC.String(value))
}

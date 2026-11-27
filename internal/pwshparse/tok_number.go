// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0
//
// Portions of this package are a Go port of the PowerShell parser from
// https://github.com/PowerShell/PowerShell (MIT, Copyright (c) Microsoft
// Corporation); see THIRD_PARTY_LICENSES.txt.

package pwshparse

import (
	"math"
	"math/big"
	"strconv"
	"strings"
)

type numberFormat uint8

const (
	nfDecimal numberFormat = iota
	nfHex
	nfBinary
)

type suffixFlags uint8

const (
	sfNone          suffixFlags = 0x0
	sfUnsigned      suffixFlags = 0x1
	sfSignedByte    suffixFlags = 0x2
	sfUnsignedByte  suffixFlags = 0x3
	sfShort         suffixFlags = 0x4
	sfUnsignedShort suffixFlags = 0x5
	sfLong          suffixFlags = 0x8
	sfUnsignedLong  suffixFlags = 0x9
	sfDecimal       suffixFlags = 0x10
	sfBigInteger    suffixFlags = 0x20
)

func (t *tokenizer) scanHexDigits(sb *sbuf) {
	c := t.peekChar()
	for isHexDigit(c) {
		t.skipChar()
		sb.add(c)
		c = t.peekChar()
	}
}

func (t *tokenizer) scanDecimalDigits(sb *sbuf) int {
	n := 0
	c := t.peekChar()
	for isDecimalDigit(c) {
		n++
		t.skipChar()
		sb.add(c)
		c = t.peekChar()
	}
	return n
}

func (t *tokenizer) scanBinaryDigits(sb *sbuf) {
	c := t.peekChar()
	for isBinaryDigit(c) {
		t.skipChar()
		sb.add(c)
		c = t.peekChar()
	}
}

func (t *tokenizer) scanExponent(sb *sbuf, signIndex *int, notNumber *bool) {
	c := t.peekChar()
	if c == '+' || isDash(c) {
		t.skipChar()
		*signIndex = sb.length()
		sb.add(c)
	}
	if t.scanDecimalDigits(sb) == 0 {
		*notNumber = true
	}
}

func (t *tokenizer) scanNumberAfterDot(sb *sbuf, signIndex *int, notNumber *bool) {
	t.scanDecimalDigits(sb)
	c := t.peekChar()
	if c == 'e' || c == 'E' {
		t.skipChar()
		sb.add(c)
		t.scanExponent(sb, signIndex, notNumber)
	}
}

var (
	bigOne = big.NewInt(1)
)

func inRange(v *big.Int, lo, hi *big.Int) bool { return v.Cmp(lo) >= 0 && v.Cmp(hi) <= 0 }

func bigPow2(n uint) *big.Int { return new(big.Int).Lsh(bigOne, n) }

// tryCastInt reports whether v fits the integer type and returns its name.
func tryCastInt(v *big.Int, name string) bool {
	var lo, hi *big.Int
	switch name {
	case "System.SByte":
		lo, hi = big.NewInt(-128), big.NewInt(127)
	case "System.Byte":
		lo, hi = big.NewInt(0), big.NewInt(255)
	case "System.Int16":
		lo, hi = big.NewInt(-32768), big.NewInt(32767)
	case "System.UInt16":
		lo, hi = big.NewInt(0), big.NewInt(65535)
	case "System.Int32":
		lo, hi = big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32)
	case "System.UInt32":
		lo, hi = big.NewInt(0), big.NewInt(math.MaxUint32)
	case "System.Int64":
		lo, hi = big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64)
	case "System.UInt64":
		lo = big.NewInt(0)
		hi = new(big.Int).Sub(bigPow2(64), bigOne)
	}
	return inRange(v, lo, hi)
}

func intNum(v *big.Int, name string) *NumberValue {
	return &NumberValue{Type: name, Text: v.String()}
}

// decimalMax is System.Decimal.MaxValue's magnitude (2^96-1).
var decimalMax = new(big.Int).Sub(bigPow2(96), bigOne)

func decimalNum(v *big.Int, scale int) *NumberValue {
	s := new(big.Int).Abs(v).String()
	neg := v.Sign() < 0
	if scale > 0 {
		for len(s) <= scale {
			s = "0" + s
		}
		s = s[:len(s)-scale] + "." + s[len(s)-scale:]
	}
	if neg {
		s = "-" + s
	}
	return &NumberValue{Type: "System.Decimal", Text: s}
}

// parseDecimal parses [sign]digits[.digits][e[sign]digits] as System.Decimal.
func parseDecimal(s string) (*big.Int, int, bool) {
	neg := false
	if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	exp := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(strings.TrimPrefix(s[i+1:], "+"))
		if err != nil {
			return nil, 0, false
		}
		exp = e
		s = s[:i]
	}
	scale := 0
	if i := strings.IndexByte(s, '.'); i >= 0 {
		scale = len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, 0, false
	}
	scale -= exp
	if v.Sign() == 0 {
		// zero stays zero whatever the exponent (the scale is clipped to 0..28 like .NET)
		return v, min(max(scale, 0), 28), true
	}
	if scale < 0 {
		if -scale > 29 {
			return nil, 0, false // a non-zero value times 10^30 or more overflows decimal
		}
		v.Mul(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(-scale)), nil))
		scale = 0
	}
	if scale > 28 {
		// .NET rounds to 28 places; keep this path simple and exact for common input.
		d := scale - 28
		if d >= len(s) {
			v.SetInt64(0) // fewer digits than the dropped places: rounds to zero (and bounds the work)
		} else {
			v.Quo(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(d)), nil))
		}
		scale = 28
	}
	if v.CmpAbs(decimalMax) > 0 {
		return nil, 0, false
	}
	if neg {
		v.Neg(v)
	}
	return v, scale, true
}

// formatDouble renders a float64 like .NET Core's Double.ToString().
func formatDouble(f float64) string {
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0"
		}
		return "0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expS, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expS)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if exp >= 17 || exp <= -5 {
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign = "-"
			exp = -exp
		}
		es := strconv.Itoa(exp)
		if len(es) < 2 {
			es = "0" + es
		}
		out += "E" + sign + es
	} else if exp >= 0 {
		if len(digits) <= exp+1 {
			out = digits + strings.Repeat("0", exp+1-len(digits))
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	} else {
		out = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		out = "-" + out
	}
	return out
}

func doubleAsBigInt(d float64) *big.Int {
	r := math.RoundToEven(d)
	bf := new(big.Float).SetFloat64(r)
	bi, _ := bf.Int(nil)
	return bi
}

// tryGetNumberValue ports Tokenizer.TryGetNumberValue.
func tryGetNumberValue(strNum string, format numberFormat, suffix suffixFlags, real bool, multiplier int64) (*NumberValue, bool) {
	if real {
		if suffix == sfDecimal {
			v, scale, ok := parseDecimal(strNum)
			if !ok {
				return nil, false
			}
			v.Mul(v, big.NewInt(multiplier))
			if v.CmpAbs(decimalMax) > 0 {
				return nil, false
			}
			return decimalNum(v, scale), true
		}
		d, err := strconv.ParseFloat(strNum, 64)
		if err != nil {
			if ne, ok := err.(*strconv.NumError); !ok || ne.Err != strconv.ErrRange {
				return nil, false
			}
		}
		if d == 0 && strNum[0] == '-' {
			d = math.Copysign(0, -1)
		}
		d *= float64(multiplier)
		bi := func() *big.Int {
			if math.IsInf(d, 0) || math.IsNaN(d) {
				return nil
			}
			return doubleAsBigInt(d)
		}
		switch suffix {
		case sfNone:
			return &NumberValue{Type: "System.Double", Text: formatDouble(d)}, true
		case sfSignedByte:
			if b := bi(); b != nil && tryCastInt(b, "System.SByte") {
				return intNum(b, "System.SByte"), true
			}
		case sfUnsignedByte:
			if b := bi(); b != nil && tryCastInt(b, "System.Byte") {
				return intNum(b, "System.Byte"), true
			}
		case sfShort:
			if b := bi(); b != nil && tryCastInt(b, "System.Int16") {
				return intNum(b, "System.Int16"), true
			}
		case sfLong:
			if b := bi(); b != nil && tryCastInt(b, "System.Int64") {
				return intNum(b, "System.Int64"), true
			}
		case sfUnsignedShort:
			if b := bi(); b != nil && tryCastInt(b, "System.UInt16") {
				return intNum(b, "System.UInt16"), true
			}
		case sfUnsigned:
			if b := bi(); b != nil {
				if tryCastInt(b, "System.UInt32") {
					return intNum(b, "System.UInt32"), true
				} else if tryCastInt(b, "System.UInt64") {
					return intNum(b, "System.UInt64"), true
				}
			}
		case sfUnsignedLong:
			if b := bi(); b != nil && tryCastInt(b, "System.UInt64") {
				return intNum(b, "System.UInt64"), true
			}
		case sfBigInteger:
			if b := bi(); b != nil {
				return intNum(b, "System.Numerics.BigInteger"), true
			}
		}
		return nil, false
	}
	var bigValue *big.Int
	switch format {
	case nfHex:
		if !isHexDigit(char(strNum[0])) {
			if strNum[0] == '-' {
				multiplier = -multiplier
			}
			strNum = strNum[1:]
		}
		if suffix&sfUnsigned == 0 {
			expected := 0
			switch suffix {
			case sfSignedByte:
				expected = 2
			case sfShort:
				expected = 4
			case sfLong:
				expected = 16
			default:
				if len(strNum) < 16 {
					expected = 8
				} else {
					expected = 16
				}
			}
			if len(strNum) == expected+1 {
				strNum = strNum[1:]
			}
		}
		v, ok := new(big.Int).SetString(strNum, 16)
		if !ok {
			return nil, false
		}
		// AllowHexSpecifier: a leading digit with the high bit set is negative (two's complement).
		if hexVal(char(strNum[0])) >= 8 {
			v.Sub(v, new(big.Int).Lsh(bigOne, uint(4*len(strNum))))
		}
		bigValue = v
		if len(strNum) == 16 && (suffix == sfNone || suffix == sfUnsigned) {
			suffix |= sfLong
		}
	case nfBinary:
		if !isBinaryDigit(char(strNum[0])) {
			if strNum[0] == '-' {
				multiplier = -multiplier
			}
			strNum = strNum[1:]
		}
		bigValue = parseBinary(strNum, suffix&sfUnsigned != 0)
		if len(strNum) == 64 && (suffix == sfNone || suffix == sfUnsigned) {
			suffix |= sfLong
		}
	default:
		v, ok := new(big.Int).SetString(strNum, 10)
		if !ok {
			return nil, false
		}
		bigValue = v
	}
	bigValue = new(big.Int).Mul(bigValue, big.NewInt(multiplier))
	switch suffix {
	case sfSignedByte:
		if tryCastInt(bigValue, "System.SByte") {
			return intNum(bigValue, "System.SByte"), true
		}
	case sfUnsignedByte:
		if tryCastInt(bigValue, "System.Byte") {
			return intNum(bigValue, "System.Byte"), true
		}
	case sfShort:
		if tryCastInt(bigValue, "System.Int16") {
			return intNum(bigValue, "System.Int16"), true
		}
	case sfLong:
		if tryCastInt(bigValue, "System.Int64") {
			return intNum(bigValue, "System.Int64"), true
		}
	case sfUnsignedShort:
		if tryCastInt(bigValue, "System.UInt16") {
			return intNum(bigValue, "System.UInt16"), true
		}
	case sfUnsigned:
		if tryCastInt(bigValue, "System.UInt32") {
			return intNum(bigValue, "System.UInt32"), true
		} else if tryCastInt(bigValue, "System.UInt64") {
			return intNum(bigValue, "System.UInt64"), true
		}
	case sfUnsignedLong:
		if tryCastInt(bigValue, "System.UInt64") {
			return intNum(bigValue, "System.UInt64"), true
		}
	case sfDecimal:
		if bigValue.CmpAbs(decimalMax) <= 0 {
			return decimalNum(bigValue, 0), true
		}
	case sfBigInteger:
		return intNum(bigValue, "System.Numerics.BigInteger"), true
	case sfNone:
		if tryCastInt(bigValue, "System.Int32") {
			return intNum(bigValue, "System.Int32"), true
		}
		if tryCastInt(bigValue, "System.Int64") {
			return intNum(bigValue, "System.Int64"), true
		}
		if format == nfDecimal {
			if bigValue.CmpAbs(decimalMax) <= 0 {
				return decimalNum(bigValue, 0), true
			}
			f, _ := new(big.Float).SetInt(bigValue).Float64()
			return &NumberValue{Type: "System.Double", Text: formatDouble(f)}, true
		}
	}
	return nil, false
}

// parseBinary is Utils.ParseBinary. A signed literal of 8, 16, 32 or 64 bits
// with the top bit set is a negative two's-complement value.
func parseBinary(digits string, unsigned bool) *big.Int {
	v := new(big.Int)
	for i := 0; i < len(digits); i++ {
		v.Lsh(v, 1)
		if digits[i] == '1' {
			v.Or(v, bigOne)
		}
	}
	n := len(digits)
	if !unsigned && n > 0 && digits[0] == '1' && (n == 8 || n == 16 || n == 32 || n == 64) {
		v.Sub(v, new(big.Int).Lsh(bigOne, uint(n)))
	}
	return v
}

func (t *tokenizer) scanNumber(first char) *Token {
	strNum, format, suffix, real, multiplier, ok := t.scanNumberHelper(first)
	if !ok {
		t.curIndex = t.tokenStart
		return t.scanGenericTokenSB(nil)
	}
	value, vok := tryGetNumberValue(strNum, format, suffix, real, multiplier)
	if !vok {
		if !t.inExpressionMode() {
			t.curIndex = t.tokenStart
			return t.scanGenericTokenSB(nil)
		}
		t.reportErrorExtent(t.newExtent(t.tokenStart, t.curIndex), "BadNumericConstant")
	}
	return t.newNumberToken(value)
}

func (t *tokenizer) scanNumberHelper(first char) (string, numberFormat, suffixFlags, bool, int64, bool) {
	format := nfDecimal
	suffix := sfNone
	real := false
	multiplier := int64(1)
	notNumber := false
	signIndex := -1
	sb := make(sbuf, 0, 48)
	if isDash(first) || first == '+' {
		sb.add(first)
		first = t.getChar()
	}
	if first == '.' {
		sb.add('.')
		t.scanNumberAfterDot(&sb, &signIndex, &notNumber)
		real = true
	} else {
		c := t.peekChar()
		isHexOrBin := first == '0' && (c == 'x' || c == 'X' || c == 'b' || c == 'B')
		if isHexOrBin {
			t.skipChar()
			switch c {
			case 'x', 'X':
				sb.add('0')
				t.scanHexDigits(&sb)
				if sb.length() == 0 {
					notNumber = true
				}
				format = nfHex
			case 'b', 'B':
				t.scanBinaryDigits(&sb)
				if sb.length() == 0 {
					notNumber = true
				}
				format = nfBinary
			}
		} else {
			sb.add(first)
			t.scanDecimalDigits(&sb)
			c = t.peekChar()
			switch c {
			case '.':
				t.skipChar()
				if t.peekChar() == '.' {
					t.ungetChar()
				} else {
					sb.add(c)
					real = true
					t.scanNumberAfterDot(&sb, &signIndex, &notNumber)
				}
			case 'E', 'e':
				t.skipChar()
				sb.add(c)
				real = true
				t.scanExponent(&sb, &signIndex, &notNumber)
			}
		}
	}
	c := t.peekChar()
	if isTypeSuffix(c) {
		t.skipChar()
		switch c {
		case 'u', 'U':
			suffix |= sfUnsigned
		case 's', 'S':
			suffix |= sfShort
		case 'l', 'L':
			suffix |= sfLong
		case 'd', 'D':
			suffix |= sfDecimal
		case 'y', 'Y':
			suffix |= sfSignedByte
		case 'n', 'N':
			suffix |= sfBigInteger
		default:
			notNumber = true
		}
		c = t.peekChar()
		if isTypeSuffix(c) {
			t.skipChar()
			switch suffix {
			case sfUnsigned:
				switch c {
				case 'l', 'L':
					suffix |= sfLong
				case 's', 'S':
					suffix |= sfShort
				case 'y', 'Y':
					suffix |= sfSignedByte
				default:
					notNumber = true
				}
			default:
				notNumber = true
			}
			c = t.peekChar()
		}
	}
	if isMultiplierStart(c) {
		t.skipChar()
		switch c {
		case 'k', 'K':
			multiplier = 1024
		case 'm', 'M':
			multiplier = 1024 * 1024
		case 'g', 'G':
			multiplier = 1024 * 1024 * 1024
		case 't', 'T':
			multiplier = 1024 * 1024 * 1024 * 1024
		case 'p', 'P':
			multiplier = 1024 * 1024 * 1024 * 1024 * 1024
		}
		c1 := t.peekChar()
		if c1 == 'b' || c1 == 'B' {
			t.skipChar()
			c = t.peekChar()
		} else {
			notNumber = true
		}
	}
	if !forceStartNewToken(c) {
		if !t.inExpressionMode() || !forceStartNewTokenAfterNumber(c, t.forceEndNumberOnTernOp) {
			notNumber = true
		}
	}
	if notNumber {
		return "", format, suffix, real, multiplier, false
	}
	if signIndex != -1 && sb[signIndex] != '-' && isDash(sb[signIndex]) {
		sb[signIndex] = '-'
	}
	if sb[0] != '-' && isDash(sb[0]) {
		sb[0] = '-'
	}
	return sb.String(), format, suffix, real, multiplier, true
}

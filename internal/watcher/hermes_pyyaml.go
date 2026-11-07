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

package watcher

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// This file reads a YAML manifest the way the plugin scanner does: PyYAML's
// safe loader (yaml.load with CSafeLoader). While the scanner cannot be asked,
// the watcher needs the same answer to "which files does this manifest
// declare", and that answer depends on more than the parse tree: the loader's
// own implicit-tag rules (yes, on and ~ are not what a YAML 1.2 reader makes
// of them), the constructors that refuse a whole document (an int that is not
// a number, a binary that is not base64, an unknown tag, an unhashable key),
// how merge keys flatten (including a mapping that merges itself), and which
// keys a dictionary treats as one (1, 01, 1.0 and true). It is a port of the
// parts of PyYAML's resolver and SafeConstructor that decide those things, over
// the parse tree of yaml.v3; it builds only what a dictionary lookup needs.
// TestHermesFallbackEntrypointsMatchScanner compares it with the scanner.

const (
	pyYAMLNS = "tag:yaml.org,2002:"
	// hermesYAMLMaxDepth bounds the nesting the reader follows.
	hermesYAMLMaxDepth = 64
	// hermesYAMLMaxNodes bounds the nodes of one document.
	hermesYAMLMaxNodes = 200000
	// hermesYAMLMaxWork bounds the pairs copied by merge keys in one document.
	hermesYAMLMaxWork = 1000000
)

// pyYAMLResolvers are PyYAML's implicit resolvers in registration order, with
// the first characters a plain scalar must start with for each.
var pyYAMLResolvers = []struct {
	tag, first string
	re         *regexp.Regexp
}{
	{"bool", "yYnNtTfFoO", regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)},
	{"float", "-+0123456789.", regexp.MustCompile(`^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)},
	{"int", "-+0123456789", regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)},
	{"merge", "<", regexp.MustCompile(`^<<$`)},
	{"null", "~nN", regexp.MustCompile(`^(?:~|null|Null|NULL)$`)},
	{"timestamp", "0123456789", regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)},
	{"value", "=", regexp.MustCompile(`^=$`)},
}

// pyYAMLTimestamp is the constructor's timestamp pattern.
var pyYAMLTimestamp = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?$`)

// pyYAMLFloat is the text Python's float() accepts once a sign is taken off
// and the case is folded.
var pyYAMLFloat = regexp.MustCompile(`^[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?|inf|infinity|nan)$`)

// pyResolvePlain is the tag PyYAML gives a plain, untagged scalar.
func pyResolvePlain(value string) string {
	if value == "" {
		return pyYAMLNS + "null"
	}
	for _, r := range pyYAMLResolvers {
		if strings.IndexByte(r.first, value[0]) >= 0 && r.re.MatchString(value) {
			return pyYAMLNS + r.tag
		}
	}
	return pyYAMLNS + "str"
}

// pyYAMLPrintable reports whether PyYAML's reader accepts every character:
// tab, line breaks, printable ASCII and the printable planes.
func pyYAMLPrintable(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		switch {
		case r == 0x09 || r == 0x0A || r == 0x0D || (r >= 0x20 && r <= 0x7E) || r == 0x85:
		case r >= 0xA0 && r <= 0xD7FF, r >= 0xE000 && r <= 0xFFFD, r >= 0x10000 && r <= 0x10FFFF:
		default:
			return false
		}
	}
	return true
}

// pyIsSpace is Python's str.isspace for one character.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1C && r <= 0x1F)
}

// pyBlank reports whether Python's str.strip() leaves nothing.
func pyBlank(text string) bool {
	return strings.TrimFunc(text, pyIsSpace) == ""
}

// pyNode is a node after PyYAML's composer: aliases are the node they name,
// and the tag is resolved.
type pyNode struct {
	kind  yaml.Kind
	tag   string
	text  string
	items []*pyNode
	pairs []pyPair
}

type pyPair struct{ key, value *pyNode }

type pyKind int

const (
	pyHashable pyKind = iota // a number, null, bytes or a time
	pyStr
	pyList
	pyDict
	pySet
)

// pyVal is a constructed value, only as much of it as a lookup needs. key is
// the identity a dictionary gives a hashable value: Python treats 1, 1.0 and
// True as one key, and 'a' and b'a' as two.
type pyVal struct {
	kind    pyKind
	text    string
	key     string
	entries []pyEntry
	index   map[string]int
}

type pyEntry struct{ key, value *pyVal }

// set stores a value, keeping the first key object and the last value, as a
// dictionary does.
func (v *pyVal) set(key, value *pyVal) {
	if i, ok := v.index[key.key]; ok {
		v.entries[i].value = value
		return
	}
	v.index[key.key] = len(v.entries)
	v.entries = append(v.entries, pyEntry{key, value})
}

func (v *pyVal) lookup(key string) *pyVal {
	if i, ok := v.index[key]; ok {
		return v.entries[i].value
	}
	return nil
}

// pyLoader composes and constructs one document.
type pyLoader struct {
	nodes    int
	work     int
	over     bool // a bound was reached: the document is undecided, not refused
	composed map[*yaml.Node]*pyNode
	memo     map[*pyNode]*pyVal
	pending  []func() bool
}

func newPyLoader() *pyLoader {
	return &pyLoader{composed: map[*yaml.Node]*pyNode{}, memo: map[*pyNode]*pyVal{}}
}

func pyExpandTag(tag string) string {
	if rest, ok := strings.CutPrefix(tag, "!!"); ok {
		return pyYAMLNS + rest
	}
	return tag
}

// compose turns a yaml.v3 node into a pyNode, sharing the node an alias names.
func (l *pyLoader) compose(n *yaml.Node, depth int) (*pyNode, bool) {
	if n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil {
		return nil, false
	}
	if pn, ok := l.composed[n]; ok {
		return pn, true
	}
	if l.nodes++; depth > hermesYAMLMaxDepth || l.nodes > hermesYAMLMaxNodes {
		l.over = true
		return nil, false
	}
	pn := &pyNode{kind: n.Kind}
	l.composed[n] = pn
	tagged := n.Style&yaml.TaggedStyle != 0
	switch n.Kind {
	case yaml.ScalarNode:
		pn.text = n.Value
		switch {
		case tagged:
			pn.tag = pyExpandTag(n.Tag)
		case n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0:
			pn.tag = pyYAMLNS + "str"
		default:
			pn.tag = pyResolvePlain(n.Value)
		}
	case yaml.SequenceNode, yaml.MappingNode:
		pn.tag = pyYAMLNS + "seq"
		if n.Kind == yaml.MappingNode {
			pn.tag = pyYAMLNS + "map"
		}
		if tagged {
			pn.tag = pyExpandTag(n.Tag)
		}
		for i := 0; i < len(n.Content); i++ {
			child, ok := l.compose(n.Content[i], depth+1)
			if !ok {
				return nil, false
			}
			switch {
			case n.Kind == yaml.SequenceNode:
				pn.items = append(pn.items, child)
			case i%2 == 0:
				pn.pairs = append(pn.pairs, pyPair{key: child})
			default:
				pn.pairs[len(pn.pairs)-1].value = child
			}
		}
		if n.Kind == yaml.MappingNode && len(n.Content)%2 != 0 {
			return nil, false
		}
	default:
		return nil, false
	}
	return pn, true
}

// flatten is SafeConstructor.flatten_mapping: merge keys are taken out of the
// mapping (before the mapping they name is flattened, so a mapping that merges
// itself ends), the pairs they bring come first, and a value-tagged key
// becomes a string key. It changes the nodes, as PyYAML does, so the order the
// mappings are constructed in matters and is kept.
func (l *pyLoader) flatten(n *pyNode) bool {
	var merge []pyPair
	for i := 0; i < len(n.pairs); {
		switch n.pairs[i].key.tag {
		case pyYAMLNS + "merge":
			value := n.pairs[i].value
			n.pairs = append(n.pairs[:i:i], n.pairs[i+1:]...)
			switch value.kind {
			case yaml.MappingNode:
				if !l.flatten(value) || !l.spend(len(value.pairs)) {
					return false
				}
				merge = append(merge, value.pairs...)
			case yaml.SequenceNode:
				var subs [][]pyPair
				for _, sub := range value.items {
					if sub.kind != yaml.MappingNode || !l.flatten(sub) {
						return false
					}
					subs = append(subs, sub.pairs)
				}
				for j := len(subs) - 1; j >= 0; j-- {
					if !l.spend(len(subs[j])) {
						return false
					}
					merge = append(merge, subs[j]...)
				}
			default:
				return false
			}
		case pyYAMLNS + "value":
			n.pairs[i].key.tag = pyYAMLNS + "str"
			i++
		default:
			i++
		}
	}
	if len(merge) > 0 {
		n.pairs = append(merge, n.pairs...)
	}
	return true
}

func (l *pyLoader) spend(n int) bool {
	if l.work += n; l.work > hermesYAMLMaxWork {
		l.over = true
		return false
	}
	return true
}

// scalar is construct_scalar: a scalar's text, or the text of the value a
// mapping holds under a value-tagged key.
func (l *pyLoader) scalar(n *pyNode) (string, bool) {
	for depth := 0; n.kind == yaml.MappingNode; depth++ {
		var next *pyNode
		for _, p := range n.pairs {
			if p.key.tag == pyYAMLNS+"value" {
				next = p.value
				break
			}
		}
		if next == nil || depth > hermesYAMLMaxDepth {
			return "", false
		}
		n = next
	}
	return n.text, n.kind == yaml.ScalarNode
}

// construct builds the document: the root, then every container it holds,
// level by level, as PyYAML's constructor does. ok is false where PyYAML
// raises, which refuses the whole document.
func (l *pyLoader) construct(root *pyNode) (*pyVal, bool) {
	value, ok := l.object(root)
	for ok && len(l.pending) > 0 {
		batch := l.pending
		l.pending = nil
		for _, fill := range batch {
			if !fill() {
				return nil, false
			}
		}
	}
	return value, ok
}

func (l *pyLoader) object(n *pyNode) (*pyVal, bool) {
	if v, ok := l.memo[n]; ok {
		return v, true
	}
	v, ok := l.build(n)
	if ok {
		l.memo[n] = v
	}
	return v, ok
}

func (l *pyLoader) container(n *pyNode, v *pyVal, fill func() bool) (*pyVal, bool) {
	l.memo[n] = v
	l.pending = append(l.pending, fill)
	return v, true
}

// build is construct_object for one node: the SafeConstructor registered for
// its tag. A tag with no constructor, or a constructor handed the wrong kind
// of node, raises.
func (l *pyLoader) build(n *pyNode) (*pyVal, bool) {
	switch n.tag {
	case pyYAMLNS + "str":
		text, ok := l.scalar(n)
		return &pyVal{kind: pyStr, text: text, key: "s" + text}, ok
	case pyYAMLNS + "int":
		text, ok := l.scalar(n)
		if !ok {
			return nil, false
		}
		number, ok := pyConstructInt(text)
		if !ok {
			return nil, false
		}
		return &pyVal{key: "i" + number.String()}, true
	case pyYAMLNS + "float":
		text, ok := l.scalar(n)
		if !ok {
			return nil, false
		}
		key, ok := pyConstructFloat(text, n)
		return &pyVal{key: key}, ok
	case pyYAMLNS + "bool":
		text, ok := l.scalar(n)
		if !ok {
			return nil, false
		}
		switch strings.ToLower(text) {
		case "yes", "true", "on":
			return &pyVal{key: "i1"}, true
		case "no", "false", "off":
			return &pyVal{key: "i0"}, true
		}
		return nil, false
	case pyYAMLNS + "null":
		_, ok := l.scalar(n)
		return &pyVal{key: "n"}, ok
	case pyYAMLNS + "binary":
		text, ok := l.scalar(n)
		if !ok || !pyASCII(text) {
			return nil, false
		}
		data, ok := pyDecodeBase64(text)
		return &pyVal{key: "b" + string(data)}, ok
	case pyYAMLNS + "timestamp":
		text, ok := l.scalar(n)
		if !ok {
			return nil, false
		}
		key, ok := pyConstructTimestamp(text)
		return &pyVal{key: key}, ok
	case pyYAMLNS + "seq":
		if n.kind != yaml.SequenceNode {
			return nil, false
		}
		return l.container(n, &pyVal{kind: pyList}, func() bool {
			for _, item := range n.items {
				if _, ok := l.object(item); !ok {
					return false
				}
			}
			return true
		})
	case pyYAMLNS + "map", pyYAMLNS + "set":
		if n.kind != yaml.MappingNode {
			return nil, false
		}
		v := &pyVal{kind: pyDict, index: map[string]int{}}
		if n.tag == pyYAMLNS+"set" {
			v.kind = pySet
		}
		return l.container(n, v, func() bool { return l.fillMapping(n, v) })
	case pyYAMLNS + "omap", pyYAMLNS + "pairs":
		if n.kind != yaml.SequenceNode {
			return nil, false
		}
		return l.container(n, &pyVal{kind: pyList}, func() bool {
			for _, item := range n.items {
				if item.kind != yaml.MappingNode || len(item.pairs) != 1 {
					return false
				}
				if _, ok := l.object(item.pairs[0].key); !ok {
					return false
				}
				if _, ok := l.object(item.pairs[0].value); !ok {
					return false
				}
			}
			return true
		})
	}
	return nil, false
}

// fillMapping is construct_mapping: merge keys are flattened, every key must
// be hashable, and a later pair replaces an earlier one with an equal key.
func (l *pyLoader) fillMapping(n *pyNode, v *pyVal) bool {
	if !l.flatten(n) {
		return false
	}
	for _, p := range n.pairs {
		key, ok := l.object(p.key)
		if !ok || key.kind == pyList || key.kind == pyDict || key.kind == pySet {
			return false
		}
		value, ok := l.object(p.value)
		if !ok {
			return false
		}
		if v.kind == pyDict {
			v.set(key, value)
		}
	}
	return true
}

func pyASCII(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// pyParseInt is Python's int(text, base) for ASCII text: surrounding space, a
// sign and the prefix of the base are allowed.
func pyParseInt(text string, base int) (*big.Int, bool) {
	text = strings.TrimFunc(text, pyIsSpace)
	negative := false
	if text != "" && (text[0] == '+' || text[0] == '-') {
		negative = text[0] == '-'
		text = text[1:]
	}
	prefix := map[int]string{2: "0b", 8: "0o", 16: "0x"}[base]
	if prefix != "" && len(text) > 2 && strings.EqualFold(text[:2], prefix) {
		text = text[2:]
	}
	number, ok := new(big.Int).SetString(text, base)
	if !ok || text == "" || strings.ContainsAny(text, "+-_") {
		return nil, false
	}
	if negative {
		number.Neg(number)
	}
	return number, true
}

// pyConstructInt is SafeConstructor.construct_yaml_int.
func pyConstructInt(text string) (*big.Int, bool) {
	value := strings.ReplaceAll(text, "_", "")
	sign := int64(1)
	if value != "" && value[0] == '-' {
		sign = -1
	}
	if value != "" && (value[0] == '-' || value[0] == '+') {
		value = value[1:]
	}
	var number *big.Int
	var ok bool
	switch {
	case value == "":
		return nil, false
	case value == "0":
		number, ok = new(big.Int), true
	case strings.HasPrefix(value, "0b"):
		number, ok = pyParseInt(value[2:], 2)
	case strings.HasPrefix(value, "0x"):
		number, ok = pyParseInt(value[2:], 16)
	case value[0] == '0':
		number, ok = pyParseInt(value, 8)
	case strings.Contains(value, ":"):
		number, ok = new(big.Int), true
		base := big.NewInt(1)
		parts := strings.Split(value, ":")
		for i := len(parts) - 1; i >= 0 && ok; i-- {
			var digit *big.Int
			if digit, ok = pyParseInt(parts[i], 10); ok {
				number.Add(number, digit.Mul(digit, base))
				base = new(big.Int).Mul(base, big.NewInt(60))
			}
		}
	default:
		number, ok = pyParseInt(value, 10)
	}
	if !ok {
		return nil, false
	}
	return number.Mul(number, big.NewInt(sign)), true
}

func pyParseFloat(text string) (float64, bool) {
	text = strings.ToLower(strings.TrimFunc(text, pyIsSpace))
	if !pyYAMLFloat.MatchString(text) {
		return 0, false
	}
	if strings.TrimLeft(text, "+-") == "nan" {
		return math.NaN(), true
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil && !math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

// pyConstructFloat is SafeConstructor.construct_yaml_float. It returns the
// float's dictionary identity: equal to an int of the same value, and to
// nothing else. The loader hands out one object for every .nan, so those are
// one key; any other NaN is its own.
func pyConstructFloat(text string, id *pyNode) (key string, ok bool) {
	value := strings.ToLower(strings.ReplaceAll(text, "_", ""))
	sign := 1.0
	if value != "" && value[0] == '-' {
		sign = -1
	}
	if value != "" && (value[0] == '-' || value[0] == '+') {
		value = value[1:]
	}
	var number float64
	switch {
	case value == "":
		return "", false
	case value == ".inf":
		number = math.Inf(1)
	case value == ".nan":
		return "nan", true
	case strings.Contains(value, ":"):
		base := 1.0
		parts := strings.Split(value, ":")
		for i := len(parts) - 1; i >= 0; i-- {
			digit, ok := pyParseFloat(parts[i])
			if !ok {
				return "", false
			}
			number += digit * base
			base *= 60
		}
	default:
		if number, ok = pyParseFloat(value); !ok {
			return "", false
		}
	}
	number *= sign
	switch {
	case math.IsNaN(number):
		return fmt.Sprintf("nan:%p", id), true
	case math.IsInf(number, 1):
		return "inf", true
	case math.IsInf(number, -1):
		return "-inf", true
	case number == math.Trunc(number):
		whole, _ := new(big.Float).SetFloat64(number).Int(nil)
		return "i" + whole.String(), true
	}
	return "f" + strconv.FormatFloat(number, 'g', -1, 64), true
}

// pyDecodeBase64 is base64.decodebytes (binascii.a2b_base64): characters
// outside the alphabet are skipped, and the data must end on a whole group.
func pyDecodeBase64(text string) ([]byte, bool) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	var left byte
	quad, pads := 0, 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '=' {
			if quad >= 2 {
				if pads++; quad+pads >= 4 {
					return out, true
				}
			}
			continue
		}
		v := strings.IndexByte(alphabet, c)
		if v < 0 {
			continue
		}
		pads = 0
		b := byte(v)
		switch quad {
		case 0:
			left = b
		case 1:
			out = append(out, left<<2|b>>4)
			left = b & 0xf
		case 2:
			out = append(out, left<<4|b>>2)
			left = b & 3
		case 3:
			out = append(out, left<<6|b)
		}
		quad = (quad + 1) & 3
	}
	return out, quad == 0
}

// pyConstructTimestamp is SafeConstructor.construct_yaml_timestamp: a date or
// a datetime, refused where Python's constructor raises. The key is what a
// dictionary compares: a date by day, a naive datetime by its fields, an aware
// one by the instant.
func pyConstructTimestamp(text string) (string, bool) {
	m := pyYAMLTimestamp.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	number := func(s string) int {
		v, _ := strconv.Atoi(s)
		return v
	}
	year, month, day := number(m[1]), number(m[2]), number(m[3])
	if year < 1 || month < 1 || month > 12 || day < 1 || day > time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return "", false
	}
	if m[4] == "" {
		return fmt.Sprintf("d%04d-%02d-%02d", year, month, day), true
	}
	hour, minute, second := number(m[4]), number(m[5]), number(m[6])
	if hour > 23 || minute > 59 || second > 59 {
		return "", false
	}
	fraction := m[7]
	if len(fraction) > 6 {
		fraction = fraction[:6]
	}
	micro := number(fraction + strings.Repeat("0", 6-len(fraction)))
	var offset time.Duration
	if m[9] != "" {
		offset = time.Duration(number(m[10]))*time.Hour + time.Duration(number(m[11]))*time.Minute
		if offset >= 24*time.Hour {
			return "", false
		}
		if m[9] == "-" {
			offset = -offset
		}
	}
	at := time.Date(year, time.Month(month), day, hour, minute, second, micro*1000, time.UTC)
	const layout = "2006-01-02T15:04:05.000000"
	if m[8] == "" {
		return "t" + at.Format(layout), true
	}
	return "a" + at.Add(-offset).Format(layout), true
}

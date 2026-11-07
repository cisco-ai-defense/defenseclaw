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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// This file reads a plugin manifest the way the plugin scanner does. The
// scanner loads a YAML manifest with PyYAML (yaml.load with the safe loader,
// _safe_read_manifest in plugin_scanner/scanner.py) and a JSON manifest with
// json.loads, then reads main, bin, entrypoint and entry from the dict it gets
// (_manifest_entrypoints). Rather than guess at the dict from the text, the
// manifest is built into the same Python value model: the tag PyYAML gives
// each node (resolver.py), the value its constructor makes (constructor.py),
// the dict that value makes (one key per Python-equal key, the last value
// winning, merge keys flattened beneath the mapping own pairs), and the errors
// that make the scanner skip the manifest. A manifest the scanner refuses
// declares nothing; a manifest the model cannot decide is reported as not
// parsed, so the caller treats every cache file as declared. Whatever the
// model gets wrong errs towards declaring more, never less: a key it cannot
// classify is distinct, and a scalar it cannot place is a string.

var (
	errPyLoad    = errors.New("the plugin scanner refuses this manifest")
	errPyUnknown = errors.New("beyond what the manifest reader models")
)

// pyKind is the part of a Python type the scanner reads or a dict key needs.
type pyKind uint8

const (
	pyStr    pyKind = iota // str
	pyScalar               // None, bool, number, bytes or timestamp: hashable, not a str
	pyMap                  // dict
	pyList                 // list or set: not hashable
)

// pyValue is a Python value built from a manifest. key is the identity under
// which a hashable value is one dict key with an equal value: 1, 1.0 and True
// are one key, a str is another.
type pyValue struct {
	kind    pyKind
	key     string
	str     string
	entries []pyEntry
	index   map[string]int
}

type pyEntry struct {
	key   string
	value *pyValue
}

// set stores value under key as a dict does: a later value replaces an earlier
// one, and the key keeps its first position.
func (v *pyValue) set(key string, value *pyValue) {
	if v.index == nil {
		v.index = map[string]int{}
	}
	if i, ok := v.index[key]; ok {
		v.entries[i].value = value
		return
	}
	v.index[key] = len(v.entries)
	v.entries = append(v.entries, pyEntry{key, value})
}

func (v *pyValue) get(name string) *pyValue {
	if i, ok := v.index["s:"+name]; ok {
		return v.entries[i].value
	}
	return nil
}

func pyString(s string) *pyValue { return &pyValue{kind: pyStr, key: "s:" + s, str: s} }

// pyManifestEntrypoints reads the entrypoint strings from a manifest dict as
// _manifest_entrypoints does: main, entrypoint and entry when a non-blank str,
// bin when a non-blank str or a dict, every value of which that is a non-blank
// str.
func pyManifestEntrypoints(top *pyValue) []string {
	if top == nil || top.kind != pyMap {
		return nil
	}
	var out []string
	add := func(v *pyValue) {
		if v != nil && v.kind == pyStr && strings.TrimSpace(v.str) != "" {
			out = append(out, v.str)
		}
	}
	for _, name := range hermesManifestEntrypointKeys {
		v := top.get(name)
		add(v)
		if name == "bin" && v != nil && v.kind == pyMap {
			for _, e := range v.entries {
				add(e.value)
			}
		}
	}
	return out
}

// The implicit resolvers of PyYAML 6 (yaml/resolver.py), in its order.
var (
	pyYAMLBoolRe  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	pyYAMLFloatRe = regexp.MustCompile(`^(?:[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
	pyYAMLIntRe   = regexp.MustCompile(`^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$`)
	pyYAMLNullRe  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	pyYAMLTimeRe  = regexp.MustCompile(`^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$`)
)

const (
	yamlTagPrefix = "tag:yaml.org,2002:"
	yamlTagMerge  = yamlTagPrefix + "merge"
	yamlTagValue  = yamlTagPrefix + "value"
)

// pyYAMLTag is the tag PyYAML gives a node (an alias already followed): an
// explicit tag as written, a quoted or block scalar a str, a plain scalar the
// first implicit resolver it matches, a collection a map or a seq.
func pyYAMLTag(n *yaml.Node) string {
	if n.Style&yaml.TaggedStyle != 0 {
		if rest, ok := strings.CutPrefix(n.Tag, "!!"); ok {
			return yamlTagPrefix + rest
		}
		return n.Tag
	}
	switch n.Kind {
	case yaml.MappingNode:
		return yamlTagPrefix + "map"
	case yaml.SequenceNode:
		return yamlTagPrefix + "seq"
	}
	if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return yamlTagPrefix + "str"
	}
	switch text := n.Value; {
	case pyYAMLBoolRe.MatchString(text):
		return yamlTagPrefix + "bool"
	case pyYAMLFloatRe.MatchString(text):
		return yamlTagPrefix + "float"
	case pyYAMLIntRe.MatchString(text):
		return yamlTagPrefix + "int"
	case text == "<<":
		return yamlTagMerge
	case pyYAMLNullRe.MatchString(text):
		return yamlTagPrefix + "null"
	case pyYAMLTimeRe.MatchString(text):
		return yamlTagPrefix + "timestamp"
	case text == "=":
		return yamlTagValue
	}
	return yamlTagPrefix + "str"
}

type pyYAMLPair struct{ key, value *yaml.Node }

// pyYAMLBuilder builds the Python value of a document. Each node is built
// once, as PyYAML does, and the work is bounded by a budget.
type pyYAMLBuilder struct {
	budget   int
	built    map[*yaml.Node]*pyValue
	flat     map[*yaml.Node][]pyYAMLPair
	flatting map[*yaml.Node]bool
	nans     int
}

func (b *pyYAMLBuilder) spend(n int) error {
	if b.budget -= n; b.budget < 0 {
		return errPyUnknown
	}
	return nil
}

func pyYAMLFollow(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 64; i++ {
		n = n.Alias
	}
	if n == nil || n.Kind == yaml.AliasNode {
		return nil
	}
	return n
}

// flatten lists the pairs PyYAML builds a mapping from (flatten_mapping): the
// pairs of its merge keys first, a later merge key beneath an earlier one and
// the first mapping of a merge list beneath the rest, then its own pairs.
func (b *pyYAMLBuilder) flatten(n *yaml.Node) ([]pyYAMLPair, error) {
	if pairs, ok := b.flat[n]; ok {
		return pairs, nil
	}
	if b.flatting[n] {
		return nil, errPyUnknown
	}
	b.flatting[n] = true
	defer delete(b.flatting, n)
	var merged, own []pyYAMLPair
	for i := 0; i+1 < len(n.Content); i += 2 {
		if err := b.spend(1); err != nil {
			return nil, err
		}
		key, value := pyYAMLFollow(n.Content[i]), pyYAMLFollow(n.Content[i+1])
		if key == nil || value == nil {
			return nil, errPyUnknown
		}
		if key.Kind != yaml.ScalarNode || pyYAMLTag(key) != yamlTagMerge {
			own = append(own, pyYAMLPair{n.Content[i], n.Content[i+1]})
			continue
		}
		var sources []*yaml.Node
		switch value.Kind {
		case yaml.MappingNode:
			sources = []*yaml.Node{value}
		case yaml.SequenceNode:
			for j := len(value.Content) - 1; j >= 0; j-- {
				source := pyYAMLFollow(value.Content[j])
				if source == nil {
					return nil, errPyUnknown
				}
				if source.Kind != yaml.MappingNode {
					return nil, errPyLoad
				}
				sources = append(sources, source)
			}
		default:
			return nil, errPyLoad
		}
		for _, source := range sources {
			sub, err := b.flatten(source)
			if err != nil {
				return nil, err
			}
			if err := b.spend(len(sub)); err != nil {
				return nil, err
			}
			merged = append(merged, sub...)
		}
	}
	pairs := append(merged, own...)
	b.flat[n] = pairs
	return pairs, nil
}

// construct builds the Python value of a node, or reports that the scanner
// refuses the document (errPyLoad) or that the model cannot tell
// (errPyUnknown).
func (b *pyYAMLBuilder) construct(n *yaml.Node) (*pyValue, error) {
	if err := b.spend(1); err != nil {
		return nil, err
	}
	if n = pyYAMLFollow(n); n == nil {
		return nil, errPyUnknown
	}
	if v, ok := b.built[n]; ok {
		return v, nil
	}
	tag := pyYAMLTag(n)
	scalar := n.Kind == yaml.ScalarNode
	hashable := func(key string) (*pyValue, error) {
		if !scalar {
			return nil, errPyLoad
		}
		v := &pyValue{kind: pyScalar, key: key}
		b.built[n] = v
		return v, nil
	}
	switch tag {
	case yamlTagPrefix + "null":
		return hashable("none")
	case yamlTagPrefix + "bool":
		switch strings.ToLower(n.Value) {
		case "yes", "true", "on":
			return hashable("n:1")
		case "no", "false", "off":
			return hashable("n:0")
		}
		return nil, errPyLoad
	case yamlTagPrefix + "int":
		if !scalar {
			return nil, errPyLoad
		}
		num, err := pyYAMLInt(n.Value)
		if err != nil {
			return nil, err
		}
		return hashable("n:" + new(big.Rat).SetInt(num).RatString())
	case yamlTagPrefix + "float":
		if !scalar {
			return nil, errPyLoad
		}
		key, err := b.pyYAMLFloatKey(n.Value)
		if err != nil {
			return nil, err
		}
		return hashable(key)
	case yamlTagPrefix + "str":
		if !scalar {
			return nil, errPyLoad
		}
		v := pyString(n.Value)
		b.built[n] = v
		return v, nil
	case yamlTagPrefix + "binary":
		if !scalar {
			return nil, errPyLoad
		}
		key, err := pyYAMLBinaryKey(n.Value)
		if err != nil {
			return nil, err
		}
		return hashable(key)
	case yamlTagPrefix + "timestamp":
		if !scalar {
			return nil, errPyLoad
		}
		key, err := pyYAMLTimestampKey(n.Value)
		if err != nil {
			return nil, err
		}
		return hashable(key)
	case yamlTagPrefix + "map", yamlTagPrefix + "set":
		if n.Kind != yaml.MappingNode {
			return nil, errPyLoad
		}
		kind := pyMap
		if tag != yamlTagPrefix+"map" {
			kind = pyList
		}
		return b.constructMapping(n, &pyValue{kind: kind})
	case yamlTagPrefix + "seq":
		if n.Kind != yaml.SequenceNode {
			return nil, errPyLoad
		}
		return b.constructList(n, false)
	case yamlTagPrefix + "omap", yamlTagPrefix + "pairs":
		if n.Kind != yaml.SequenceNode {
			return nil, errPyLoad
		}
		return b.constructList(n, true)
	}
	// Every other tag, a merge or value tag on a value included, has no
	// constructor in the safe loader.
	return nil, errPyLoad
}

func (b *pyYAMLBuilder) constructList(n *yaml.Node, pairs bool) (*pyValue, error) {
	v := &pyValue{kind: pyList}
	b.built[n] = v
	for _, item := range n.Content {
		if !pairs {
			if _, err := b.construct(item); err != nil {
				return nil, err
			}
			continue
		}
		pair := pyYAMLFollow(item)
		if pair == nil {
			return nil, errPyUnknown
		}
		if pair.Kind != yaml.MappingNode || len(pair.Content) != 2 {
			return nil, errPyLoad
		}
		for _, part := range pair.Content {
			if _, err := b.construct(part); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}

func (b *pyYAMLBuilder) constructMapping(n *yaml.Node, v *pyValue) (*pyValue, error) {
	b.built[n] = v
	pairs, err := b.flatten(n)
	if err != nil {
		return nil, err
	}
	for _, p := range pairs {
		var key *pyValue
		if k := pyYAMLFollow(p.key); k != nil && k.Kind == yaml.ScalarNode && pyYAMLTag(k) == yamlTagValue {
			// flatten_mapping reads a key tagged value as a str.
			key = pyString(k.Value)
		} else if key, err = b.construct(p.key); err != nil {
			return nil, err
		}
		if key.kind == pyMap || key.kind == pyList {
			return nil, errPyLoad // found unhashable key
		}
		value, err := b.construct(p.value)
		if err != nil {
			return nil, err
		}
		v.set(key.key, value)
	}
	return v, nil
}

var pyYAMLTimestampRe = regexp.MustCompile(`^([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)?$`)

// pyYAMLTimestampKey reads a timestamp scalar as construct_yaml_timestamp
// does: text the constructor pattern does not match, or a date or time that
// datetime refuses, is an error. A date is one key however it is written; a
// date and time is the key of its text.
func pyYAMLTimestampKey(text string) (string, error) {
	m := pyYAMLTimestampRe.FindStringSubmatch(text)
	if m == nil {
		return "", errPyLoad
	}
	num := func(i int) int {
		n, _ := strconv.Atoi(m[i])
		return n
	}
	year, month, day := num(1), num(2), num(3)
	if year < 1 || month < 1 || month > 12 || day < 1 || day > time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return "", errPyLoad
	}
	if m[4] == "" {
		return fmt.Sprintf("t:%04d-%02d-%02d", year, month, day), nil
	}
	if num(4) > 23 || num(5) > 59 || num(6) > 59 {
		return "", errPyLoad
	}
	return "t:" + text, nil
}

// pyYAMLBinaryKey reads a binary scalar as construct_yaml_binary does: text
// that is not ASCII, or whose base64 data is cut short, is an error; other
// characters are skipped, as a2b_base64 skips them.
func pyYAMLBinaryKey(text string) (string, error) {
	if !isASCII(text) {
		return "", errPyLoad
	}
	var data []byte
	pads := 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '=':
			pads++
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/':
			if pads > 0 {
				return "", errPyUnknown
			}
			data = append(data, c)
		}
	}
	if rest := len(data) % 4; rest == 1 || rest > 1 && pads < 4-rest {
		return "", errPyLoad
	}
	decoded, err := base64.RawStdEncoding.DecodeString(string(data))
	if err != nil {
		return "", errPyUnknown
	}
	return "b:" + string(decoded), nil
}

// pyYAMLInt reads an integer scalar as construct_yaml_int does.
func pyYAMLInt(text string) (*big.Int, error) {
	text = strings.ReplaceAll(text, "_", "")
	refuse := errPyLoad
	if !isASCII(text) {
		refuse = errPyUnknown // Python reads digits this model does not
	}
	if text == "" {
		return nil, refuse
	}
	negative := text[0] == '-'
	if text[0] == '-' || text[0] == '+' {
		text = text[1:]
	}
	parse := func(digits string, base int) (*big.Int, error) {
		n, ok := new(big.Int).SetString(strings.TrimSpace(digits), base)
		if !ok {
			return nil, refuse
		}
		return n, nil
	}
	var num *big.Int
	var err error
	switch {
	case text == "0":
		num = new(big.Int)
	case strings.HasPrefix(text, "0b"):
		num, err = parse(text[2:], 2)
	case strings.HasPrefix(text, "0x"):
		num, err = parse(text[2:], 16)
	case strings.HasPrefix(text, "0"):
		num, err = parse(text, 8)
	case strings.Contains(text, ":"):
		num = new(big.Int)
		for _, part := range strings.Split(text, ":") {
			digit, perr := parse(part, 10)
			if perr != nil {
				return nil, perr
			}
			num.Mul(num, big.NewInt(60)).Add(num, digit)
		}
	default:
		num, err = parse(text, 10)
	}
	if err != nil {
		return nil, err
	}
	if negative {
		num.Neg(num)
	}
	return num, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

var pyFloatRe = regexp.MustCompile(`^[-+]?(?:[0-9]+\.?[0-9]*(?:e[-+]?[0-9]+)?|\.[0-9]+(?:e[-+]?[0-9]+)?|inf|infinity|nan)$`)

// pyFloat reads a string as Python float() does (already lower case).
func pyFloat(text string) (float64, error) {
	text = strings.TrimSpace(text)
	if !pyFloatRe.MatchString(text) {
		if isASCII(text) {
			return 0, errPyLoad
		}
		return 0, errPyUnknown
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, errPyLoad
	}
	return f, nil
}

// pyYAMLFloatKey reads a float scalar as construct_yaml_float does and returns
// its dict-key identity: equal to an int of the same value, one key for every
// .nan (the loader returns one object), and a fresh key for the nan float()
// makes.
func (b *pyYAMLBuilder) pyYAMLFloatKey(text string) (string, error) {
	text = strings.ToLower(strings.ReplaceAll(text, "_", ""))
	if text == "" {
		return "", errPyLoad
	}
	sign := 1.0
	if text[0] == '-' {
		sign = -1
	}
	if text[0] == '-' || text[0] == '+' {
		text = text[1:]
	}
	var f float64
	switch {
	case text == ".inf":
		f = sign * math.Inf(1)
	case text == ".nan":
		return "n:nan", nil
	case strings.Contains(text, ":"):
		parts := strings.Split(text, ":")
		base := 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			digit, err := pyFloat(parts[i])
			if err != nil {
				return "", err
			}
			f += digit * base
			base *= 60
		}
		f *= sign
	default:
		digit, err := pyFloat(text)
		if err != nil {
			return "", err
		}
		f = sign * digit
	}
	switch {
	case math.IsNaN(f):
		b.nans++
		return "n:nan#" + strconv.Itoa(b.nans), nil
	case math.IsInf(f, 1):
		return "n:+inf", nil
	case math.IsInf(f, -1):
		return "n:-inf", nil
	}
	return "n:" + new(big.Rat).SetFloat64(f).RatString(), nil
}

// hermesYAMLEntrypoints lists the entrypoint strings the plugin scanner reads
// from a YAML manifest. ok is false when the text is not YAML this package
// reads or the work is over budget; a document the scanner refuses (a second
// document, an unhashable key, a tag the safe loader does not know, a bad
// merge) declares nothing.
func hermesYAMLEntrypoints(data []byte) (out []string, ok bool) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		return nil, errors.Is(err, io.EOF) // an empty stream loads as None
	}
	var next yaml.Node
	if err := decoder.Decode(&next); !errors.Is(err, io.EOF) {
		return nil, true // expected a single document in the stream
	}
	root := &doc
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil, true
		}
		root = doc.Content[0]
	}
	b := &pyYAMLBuilder{
		budget:   hermesManifestMaxNodes,
		built:    map[*yaml.Node]*pyValue{},
		flat:     map[*yaml.Node][]pyYAMLPair{},
		flatting: map[*yaml.Node]bool{},
	}
	top, err := b.construct(root)
	switch {
	case errors.Is(err, errPyLoad):
		return nil, true
	case err != nil:
		return nil, false
	}
	return pyManifestEntrypoints(top), true
}

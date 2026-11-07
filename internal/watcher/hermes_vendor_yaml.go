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

	"gopkg.in/yaml.v3"
)

// PyYAML resolves a plain scalar to a null, a Boolean, an integer or a float
// by these patterns (yaml/resolver.py); anything else is a string. A key of
// any of these types is a dict key in Python, where 1, 1.0 and True are one
// key.
var (
	hermesYAMLNullRe  = regexp.MustCompile(`^(?:~|null|Null|NULL|)$`)
	hermesYAMLBoolRe  = regexp.MustCompile(`^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$`)
	hermesYAMLIntRe   = regexp.MustCompile(`^[-+]?(?:0b[0-1_]+|0[0-7_]+|(?:0|[1-9][0-9_]*)|0x[0-9a-fA-F_]+)$`)
	hermesYAMLFloatRe = regexp.MustCompile(`^(?:[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?)$`)
	hermesYAMLTimeRe  = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}`)
	// Sexagesimal numbers, infinity and not-a-number: numbers in Python, not
	// compared here.
	hermesYAMLOtherNumRe = regexp.MustCompile(`^(?:[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
)

// hermesYAMLKeyIdentity returns a string that is equal for two mapping keys
// exactly when PyYAML builds one dict key from them, so the later pair
// replaces the earlier one. It errs towards "distinct": a key it cannot
// classify never equals another, which only keeps a pair the scanner has
// replaced, never drops one the scanner reads.
func hermesYAMLKeyIdentity(key *yaml.Node) string {
	if key == nil || key.Kind != yaml.ScalarNode {
		return fmt.Sprintf("node:%p", key)
	}
	if key.Style&yaml.TaggedStyle != 0 && key.ShortTag() != "!!str" {
		return "tag:" + key.Tag + ":" + key.Value
	}
	if key.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 ||
		key.Style&yaml.TaggedStyle != 0 {
		return "str:" + key.Value
	}
	text := key.Value
	switch {
	case hermesYAMLNullRe.MatchString(text):
		return "null"
	case hermesYAMLBoolRe.MatchString(text):
		switch strings.ToLower(text) {
		case "yes", "true", "on":
			return "num:1"
		}
		return "num:0"
	case hermesYAMLIntRe.MatchString(text):
		if n, ok := hermesYAMLInt(text); ok {
			return "num:" + n.String()
		}
	case hermesYAMLFloatRe.MatchString(text):
		f, err := strconv.ParseFloat(strings.ReplaceAll(text, "_", ""), 64)
		if err != nil {
			break
		}
		if f == math.Trunc(f) && math.Abs(f) < 1e15 {
			return "num:" + strconv.FormatInt(int64(f), 10)
		}
		return "float:" + strconv.FormatFloat(f, 'g', -1, 64)
	case hermesYAMLTimeRe.MatchString(text), hermesYAMLOtherNumRe.MatchString(text):
		return "other:" + text
	default:
		return "str:" + text
	}
	return "other:" + text
}

// hermesYAMLInt reads a PyYAML integer scalar: underscores dropped, a 0b, 0x
// or leading-0 (octal) prefix, otherwise decimal.
func hermesYAMLInt(text string) (*big.Int, bool) {
	text = strings.ReplaceAll(text, "_", "")
	sign := ""
	if text != "" && (text[0] == '-' || text[0] == '+') {
		if text[0] == '-' {
			sign = "-"
		}
		text = text[1:]
	}
	base := 10
	switch {
	case strings.HasPrefix(text, "0b"):
		base, text = 2, text[2:]
	case strings.HasPrefix(text, "0x"):
		base, text = 16, text[2:]
	case len(text) > 1 && text[0] == '0':
		base = 8
	}
	return new(big.Int).SetString(sign+text, base)
}

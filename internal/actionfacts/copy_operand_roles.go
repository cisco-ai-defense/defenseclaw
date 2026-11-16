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

// CopyOperandRoles reads the words after the program word of a cp, mv, install
// or ln call and tells which word names the destination. Every spelling of the
// target-directory option counts: -t DIR, -tDIR, a short cluster that ends in
// t (-at DIR) or holds it (-atDIR), --target-directory DIR, --target-directory=DIR
// and any unambiguous abbreviation of it; the last one given wins. Without one
// the destination is the last operand. A word is an option when it starts with
// a dash and no "--" came before it. A word with no static spelling is passed
// as the text it is written with, so only its first characters matter.
//
// destination is the index of the word that is the destination (the value of
// a separate target-directory option, else the last operand), or -1 when the
// value is attached to an option word (it is returned in attached) or the call
// has no operand. option[index] is true for an option word.
func CopyOperandRoles(words []string) (destination int, attached string, option []bool) {
	option = make([]bool, len(words))
	destination = -1
	targetGiven, optionsDone, last := false, false, -1
	for index := 0; index < len(words); index++ {
		word := words[index]
		if optionsDone || len(word) < 2 || word[0] != '-' {
			last = index
			continue
		}
		option[index] = true
		if word == "--" {
			optionsDone = true
			continue
		}
		value, attachedValue, target := copyOptionTarget(word)
		if !target {
			continue
		}
		if targetGiven && destination >= 0 {
			option[destination] = true
		}
		targetGiven, destination, attached = true, -1, ""
		if attachedValue {
			attached = value
		} else if index+1 < len(words) {
			index++
			destination = index
		}
	}
	if !targetGiven {
		destination = last
	}
	return destination, attached, option
}

// copyOptionTarget reads one option word of cp, mv, install or ln: whether it
// is the target-directory option, and when it is, the value attached to the
// word (the empty value of a long option with "=" counts as attached).
func copyOptionTarget(word string) (value string, attached, target bool) {
	if name, long := strings.CutPrefix(word, "--"); long {
		name, value, attached = strings.Cut(name, "=")
		return value, attached, name != "" && strings.HasPrefix("target-directory", name)
	}
	// The first letter of a cluster that takes a value ends it: the rest of
	// the word is that value.
	for position := 1; position < len(word); position++ {
		if strings.IndexByte("Smogt", word[position]) < 0 {
			continue
		}
		value = word[position+1:]
		return value, value != "", word[position] == 't'
	}
	return "", false, false
}

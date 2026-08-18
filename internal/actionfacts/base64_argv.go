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

// portableBase64DecodeArgvParse describes the argv subset whose input and
// decoded-stdout behavior agree between GNU coreutils and BSD/macOS base64.
// GNU treats -i as ignore-garbage while BSD/macOS treats it as an input-file
// option. Pairing -i with exactly one following operand gives both families
// the same effective input.
type portableBase64DecodeArgvParse struct {
	Complete bool
	Decode   bool

	InputSet         bool
	Input            string
	InputOptionIndex int
	InputValueIndex  int
	ReadsStdin       bool
}

// provesDecodedStdout reports whether the complete portable grammar selects
// decode mode. The accepted grammar has no output option, so decoded bytes are
// emitted on stdout.
func (parsed portableBase64DecodeArgvParse) provesDecodedStdout() bool {
	return parsed.Complete && parsed.Decode
}

// parsePortableBase64DecodeArgv accepts portable decode flags, repeated
// bundled -d flags, and bundles made of one or more d flags followed by a
// terminal i. A terminal i owns the next argv token for the portable model.
func parsePortableBase64DecodeArgv(argv []string) portableBase64DecodeArgvParse {
	parsed := portableBase64DecodeArgvParse{
		Complete:   true,
		ReadsStdin: true,
	}
	if len(argv) == 0 || argv[0] == "" {
		parsed.Complete = false
		return parsed
	}

	options := true
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if !options {
			parsed.Complete = false
			return parsed
		}

		switch argument {
		case "-d", "--decode":
			parsed.Decode = true
			continue
		case "-i":
			if !consumePortableBase64Input(&parsed, argv, &index) {
				parsed.Complete = false
				return parsed
			}
			continue
		}

		if strings.HasPrefix(argument, "-") && argument != "-" {
			shorts := argument[1:]
			if allPortableBase64DecodeFlags(shorts) {
				parsed.Decode = true
				continue
			}
			if terminalPortableBase64InputFlag(shorts) {
				parsed.Decode = true
				if !consumePortableBase64Input(&parsed, argv, &index) {
					parsed.Complete = false
					return parsed
				}
				continue
			}
		}

		// Positional input paths are supported by GNU base64 but not by the
		// BSD/macOS grammar. They are portable only through -i above.
		parsed.Complete = false
		return parsed
	}
	return parsed
}

func consumePortableBase64Input(
	parsed *portableBase64DecodeArgvParse,
	argv []string,
	index *int,
) bool {
	if parsed.InputSet || *index+1 >= len(argv) {
		return false
	}
	valueIndex := *index + 1
	value := argv[valueIndex]
	if value == "" || value != "-" && strings.HasPrefix(value, "-") {
		return false
	}

	parsed.InputSet = true
	parsed.Input = value
	parsed.InputOptionIndex = *index
	parsed.InputValueIndex = valueIndex
	parsed.ReadsStdin = value == "-"
	*index = valueIndex
	return true
}

func allPortableBase64DecodeFlags(shorts string) bool {
	if shorts == "" {
		return false
	}
	for _, option := range shorts {
		if option != 'd' {
			return false
		}
	}
	return true
}

func terminalPortableBase64InputFlag(shorts string) bool {
	if len(shorts) < 2 || shorts[len(shorts)-1] != 'i' {
		return false
	}
	return allPortableBase64DecodeFlags(shorts[:len(shorts)-1])
}

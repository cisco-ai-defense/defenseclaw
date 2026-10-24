// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hookToolCallJSONUnambiguous checks the raw hook body before a map decoder
// selects one value of a duplicate key: every object of the body, and of a
// Copilot toolArgs string that holds a JSON object or array (the Copilot
// projection reads such a string as the arguments), has unique keys, and
// the body is one JSON value. Malformed input, trailing data or a value
// nested deeper than the gateway's decoder reads cannot prove one tool call.
func hookToolCallJSONUnambiguous(connector string, body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if !hookUniqueJSONValue(decoder, 0, "", connector == "copilot") {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// hookMaxJSONDepth is encoding/json's own nesting limit, so no body the
// gateway decoded is refused for its depth alone. The body size bounds the
// work (apiRequestBodyMaxBytes).
const hookMaxJSONDepth = 10000

func hookUniqueJSONValue(decoder *json.Decoder, depth int, parentKey string, copilot bool) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, composite := token.(json.Delim)
	if !composite {
		value, isString := token.(string)
		if !isString || !copilot || depth != 1 || parentKey != "toolArgs" {
			return true
		}
		trimmed := strings.TrimSpace(value)
		if len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' {
			return true
		}
		if depth >= hookMaxJSONDepth {
			return false
		}
		inner := json.NewDecoder(strings.NewReader(trimmed))
		inner.UseNumber()
		if !hookUniqueJSONValue(inner, depth+1, "", false) {
			return false
		}
		_, err := inner.Token()
		return err == io.EOF
	}
	if depth >= hookMaxJSONDepth {
		return false
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false
			}
			key, ok := keyToken.(string)
			if !ok {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !hookUniqueJSONValue(decoder, depth+1, key, copilot) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !hookUniqueJSONValue(decoder, depth+1, "", copilot) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

// copilotWriteCallUnproven refuses a structured write when its projected
// arguments do not prove every target. ActionFacts applies the same bounded
// over-limit reduction used by the policy path. A spelling resembling a
// known write tool but not recognized by the parser is an unknown alias,
// never a read-only tool by default.
func copilotWriteCallUnproven(name string, args json.RawMessage, cwd, home string) bool {
	name = strings.TrimSpace(name)
	if copilotWriteAlias(name) && !copilotKnownWriteSpelling(name) {
		return true
	}
	tool := copilotargs.LocalActionTool(name)
	if !actionfacts.StructuredWriteTool(tool) {
		return false
	}
	if actionfacts.ApplyPatchTool(tool) {
		targets, known := hookpaths.ApplyPatchWriteTargets(tool, args, "", cwd, home)
		return !known || len(targets) == 0
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	// Copilot CLI includes a display-only description on edit and a file
	// mode on create. The gateway judges the call without them
	// (agentHookTrustedActionArgs), so that is the call proven here; any
	// other extra field stays unproven.
	if clean, ok := copilotargs.WriteArgsWithoutMetadata(tool, args); ok {
		input.Args = clean
	}
	facts := actionfacts.Analyze(input)
	if reduced, _, ok := actionfacts.OverLimitWriteTargetReduction(input, facts); ok {
		facts = reduced
	}
	if !facts.Authoritative() {
		return true
	}
	for _, target := range facts.Paths {
		switch target.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			return false
		}
	}
	return true
}

func copilotKnownWriteSpelling(name string) bool {
	switch name {
	case "create_file", "replace_string_in_file", "insert_edit_into_file", "apply_patch",
		"write_file", "edit_file", "delete_file", "copy_file", "move_file",
		"multi_edit", "multiedit":
		return true
	default:
		return false
	}
}

func copilotWriteAlias(name string) bool {
	canonical := strings.Map(func(r rune) rune {
		switch r {
		case '_', '-':
			return -1
		default:
			if 'A' <= r && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}
	}, name)
	switch canonical {
	case "createfile", "replacestringinfile", "inserteditintofile",
		"applypatch", "writefile", "editfile", "deletefile", "copyfile", "movefile", "multiedit":
		return true
	default:
		return false
	}
}

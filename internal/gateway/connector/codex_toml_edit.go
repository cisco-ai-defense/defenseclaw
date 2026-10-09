// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// editCodexOwnedTOML replaces only the tables and keys the connector owns.
// Codex users commonly keep comments, quoted strings and a deliberate key
// order in the rest of config.toml; a whole-document TOML marshal loses all
// three. The caller validates the decoded result before publishing it.
func editCodexOwnedTOML(raw []byte, desired map[string]interface{}) ([]byte, error) {
	bom := []byte(nil)
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		bom, raw = raw[:3], raw[3:]
	}
	newline := "\n"
	if bytes.Contains(raw, []byte("\r\n")) {
		newline = "\r\n"
		raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	}
	root := map[string]interface{}{}
	if value, ok := desired["notify"]; ok {
		root["notify"] = value
	}
	rootBytes, err := toml.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("render Codex notify: %w", err)
	}
	sections := map[string]interface{}{}
	for _, key := range []string{"hooks", "otel"} {
		if value, ok := desired[key]; ok {
			sections[key] = value
		}
	}
	sectionBytes, err := toml.Marshal(sections)
	if err != nil {
		return nil, fmt.Errorf("render Codex owned tables: %w", err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	var out strings.Builder
	section := ""
	rootWritten := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			if !rootWritten {
				out.Write(rootBytes)
				rootWritten = true
			}
			name := strings.TrimLeft(strings.TrimRight(trimmed, "]"), "[")
			section = strings.SplitN(name, ".", 2)[0]
		}
		if section == "hooks" || section == "otel" {
			continue
		}
		if key, _, ok := strings.Cut(trimmed, "="); ok {
			key = strings.TrimSpace(key)
			if section == "" && (key == "notify" || key == "openai_base_url" && desired[key] == nil) {
				if key == "notify" && !rootWritten {
					out.Write(rootBytes)
					rootWritten = true
				}
				// A top-level notify array may span lines. Its closing bracket
				// belongs to the same value, not to the next user key.
				if key == "notify" && strings.Count(line, "[") > strings.Count(line, "]") {
					depth := strings.Count(line, "[") - strings.Count(line, "]")
					for depth > 0 && i+1 < len(lines) {
						i++
						depth += strings.Count(lines[i], "[") - strings.Count(lines[i], "]")
					}
				}
				continue
			}
			if section == "features" && (key == "hooks" || key == "codex_hooks") {
				features, _ := desired["features"].(map[string]interface{})
				if _, keep := features[key]; !keep {
					continue
				}
			}
		}
		out.WriteString(line)
	}
	if !rootWritten {
		out.Write(rootBytes)
	}
	if len(sectionBytes) != 0 {
		if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString("\n")
		}
		out.Write(sectionBytes)
	}
	result := strings.ReplaceAll(out.String(), "\n", newline)
	return append(bom, []byte(result)...), nil
}

func parseCodexTOML(raw []byte, target interface{}) error {
	return toml.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), target)
}

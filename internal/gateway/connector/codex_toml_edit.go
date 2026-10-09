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
	writeRoot := func() {
		if rootWritten {
			return
		}
		if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
		out.Write(rootBytes)
		rootWritten = true
	}
	var syntax tomlEditSyntax
	skipNotify := false
	for _, line := range lines {
		inMultiline, inArray := syntax.multiline != 0, syntax.arrayDepth != 0
		visible := syntax.visible(line)
		trimmed := strings.TrimSpace(visible)
		if skipNotify {
			if syntax.arrayDepth == 0 {
				skipNotify = false
			}
			continue
		}
		if !inMultiline && !inArray && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			writeRoot()
			name := strings.TrimSpace(strings.Trim(trimmed, "[]"))
			section = strings.SplitN(name, ".", 2)[0]
		}
		if section == "hooks" || section == "otel" {
			continue
		}
		if key, _, ok := strings.Cut(trimmed, "="); ok {
			key = strings.TrimSpace(key)
			if section == "" && (key == "notify" || key == "openai_base_url" && desired[key] == nil) {
				if key == "notify" {
					writeRoot()
					skipNotify = syntax.arrayDepth != 0
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
	writeRoot()
	if len(sectionBytes) != 0 {
		if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteByte('\n')
		}
		out.Write(sectionBytes)
	}
	result := strings.ReplaceAll(out.String(), "\n", newline)
	return append(bom, []byte(result)...), nil
}

// tomlEditSyntax masks strings and comments so the line editor only sees TOML
// structure. Array depth lets a replaced notify value span multiple lines.
type tomlEditSyntax struct {
	multiline  byte
	arrayDepth int
}

func (s *tomlEditSyntax) visible(line string) string {
	out := []byte(strings.Repeat(" ", len(line)))
	for i := 0; i < len(line); {
		if s.multiline != 0 {
			if s.multiline == '"' && line[i] == '\\' && i+1 < len(line) {
				i += 2
				continue
			}
			if line[i] == s.multiline {
				j := i
				for j < len(line) && line[j] == s.multiline {
					j++
				}
				if j-i >= 3 {
					s.multiline = 0
				}
				i = j
				continue
			}
			i++
			continue
		}
		if line[i] == '#' {
			break
		}
		if line[i] == '"' || line[i] == '\'' {
			quote := line[i]
			if i+2 < len(line) && line[i+1] == quote && line[i+2] == quote {
				s.multiline = quote
				i += 3
				continue
			}
			i++
			for i < len(line) {
				if quote == '"' && line[i] == '\\' && i+1 < len(line) {
					i += 2
				} else if line[i] == quote {
					i++
					break
				} else {
					i++
				}
			}
			continue
		}
		out[i] = line[i]
		switch line[i] {
		case '[':
			s.arrayDepth++
		case ']':
			s.arrayDepth--
		}
		i++
	}
	return string(out)
}

func parseCodexTOML(raw []byte, target interface{}) error {
	return toml.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), target)
}

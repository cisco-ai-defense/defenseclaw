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
	// A table header or key names its table by TOML key, so ["otel"],
	// [ otel . exporter ] and a root otel.x = ... key are the owned otel
	// table too; reading the raw bracket text appended a second [otel] to a
	// quoted one, which Codex refuses to load (p0 GAP-1300).
	sectionPath := []string(nil)
	skipValue := false
	for _, line := range lines {
		inMultiline, inArray := syntax.multiline != 0, syntax.arrayDepth != 0
		visible := syntax.visible(line)
		trimmed := strings.TrimSpace(visible)
		if skipValue {
			skipValue = syntax.arrayDepth != 0 || syntax.multiline != 0
			continue
		}
		if !inMultiline && !inArray && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			writeRoot()
			header := strings.TrimLeft(strings.TrimLeft(line, " \t"), "[")
			sectionPath = tomlKeyPath(header)
			section = ""
			if len(sectionPath) > 0 {
				section = sectionPath[0]
			}
		}
		if section == "hooks" || section == "otel" {
			continue
		}
		var key []string
		if !inMultiline && !inArray && strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "[") {
			key = tomlKeyPath(line)
		}
		if section == "" && len(key) > 0 {
			owned := key[0] == "hooks" || key[0] == "otel"
			if len(key) == 1 && (key[0] == "notify" || key[0] == "openai_base_url" && desired[key[0]] == nil) {
				owned = true
				if key[0] == "notify" {
					writeRoot()
				}
			}
			if owned {
				skipValue = syntax.arrayDepth != 0 || syntax.multiline != 0
				continue
			}
		}
		feature := ""
		if section == "features" && len(sectionPath) == 1 && len(key) == 1 {
			feature = key[0]
		} else if section == "" && len(key) == 2 && key[0] == "features" {
			feature = key[1]
		}
		if feature == "hooks" || feature == "codex_hooks" {
			features, _ := desired["features"].(map[string]interface{})
			if _, keep := features[feature]; !keep {
				continue
			}
			if feature == "hooks" && features["hooks"] == true {
				// Managed reconciliation may have to undo a user preference
				// that contradicts the administrator's pinned hooks=true.
				// Replace just the boolean token; retain the user's spelling,
				// whitespace, comments and the rest of config.toml.
				if equals := strings.IndexByte(visible, '='); equals >= 0 &&
					strings.TrimSpace(visible[equals+1:]) == "false" {
					value := equals + 1 + strings.Index(visible[equals+1:], "false")
					out.WriteString(line[:value] + "true" + line[value+len("false"):])
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

// RemoveCodexManagedHookFeature removes a user preference for the hooks
// feature when machine requirements own that feature. Codex can write
// features.hooks=false despite the managed true value, then reject an
// unrelated project-trust write because the user key is disallowed.
func RemoveCodexManagedHookFeature(raw []byte) ([]byte, error) {
	bom := []byte(nil)
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		bom, raw = raw[:3], raw[3:]
	}
	var document map[string]interface{}
	if err := toml.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("parse Codex user config: %w", err)
	}
	features, ok := document["features"].(map[string]interface{})
	if !ok {
		if _, present := document["features"]; present {
			return nil, fmt.Errorf("codex user config features is not a table")
		}
		return append(bom, raw...), nil
	}
	if _, present := features["hooks"]; !present {
		return append(bom, raw...), nil
	}
	newline := "\n"
	if bytes.Contains(raw, []byte("\r\n")) {
		newline = "\r\n"
		raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	}
	var syntax tomlEditSyntax
	section := []string(nil)
	removed, inline := false, false
	var out strings.Builder
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		complex := syntax.multiline != 0 || syntax.arrayDepth != 0
		visible := strings.TrimSpace(syntax.visible(line))
		if !complex && strings.HasPrefix(visible, "[") && strings.HasSuffix(visible, "]") {
			header := strings.TrimSpace(line)
			if end := strings.IndexByte(header, ']'); end >= 0 {
				section = tomlKeyPath(header[1:end])
			}
		}
		if !complex && strings.Contains(visible, "=") && !strings.HasPrefix(visible, "[") {
			key := tomlKeyPath(line)
			if len(section) == 0 && len(key) == 1 && key[0] == "features" {
				removed, inline = true, true
				continue
			}
			if len(section) == 0 && len(key) == 2 && key[0] == "features" && key[1] == "hooks" ||
				len(section) == 1 && section[0] == "features" && len(key) == 1 && key[0] == "hooks" {
				removed = true
				continue
			}
		}
		out.WriteString(line)
	}
	if !removed {
		return nil, fmt.Errorf("codex user config defines features.hooks in an unsupported layout")
	}
	if inline {
		delete(features, "hooks")
		if len(features) != 0 {
			encoded, err := toml.Marshal(map[string]interface{}{"features": features})
			if err != nil {
				return nil, fmt.Errorf("render remaining Codex features: %w", err)
			}
			if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
				out.WriteByte('\n')
			}
			out.Write(encoded)
		}
	}
	result := []byte(strings.ReplaceAll(out.String(), "\n", newline))
	var checked map[string]interface{}
	if err := toml.Unmarshal(result, &checked); err != nil {
		return nil, fmt.Errorf("codex user config after removing features.hooks: %w", err)
	}
	if found, ok := checked["features"].(map[string]interface{}); ok {
		if _, present := found["hooks"]; present {
			return nil, fmt.Errorf("codex user config still defines features.hooks after repair")
		}
	}
	return append(bom, result...), nil
}

// tomlKeyPath decodes the dotted TOML key at the start of s: bare, "basic"
// and 'literal' parts, with optional blanks around the dots. It returns nil
// when s does not start with a key.
func tomlKeyPath(s string) []string {
	var path []string
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return nil
		}
		var part string
		switch s[0] {
		case '"':
			end := 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				return nil
			}
			var decoded struct {
				K string `toml:"k"`
			}
			if err := toml.Unmarshal([]byte("k = "+s[:end+1]), &decoded); err != nil {
				return nil
			}
			part, s = decoded.K, s[end+1:]
		case '\'':
			end := strings.IndexByte(s[1:], '\'')
			if end < 0 {
				return nil
			}
			part, s = s[1:end+1], s[end+2:]
		default:
			end := 0
			for end < len(s) && isTOMLBareKeyByte(s[end]) {
				end++
			}
			if end == 0 {
				return nil
			}
			part, s = s[:end], s[end:]
		}
		path = append(path, part)
		s = strings.TrimLeft(s, " \t")
		if !strings.HasPrefix(s, ".") {
			return path
		}
		s = s[1:]
	}
}

func isTOMLBareKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
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

// ParseCodexTOML accepts the UTF-8 BOM emitted by Windows PowerShell 5.1.
// Keep the original bytes for writers so they can preserve the BOM.
func ParseCodexTOML(raw []byte, target interface{}) error {
	return toml.Unmarshal(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), target)
}

func parseCodexTOML(raw []byte, target interface{}) error { return ParseCodexTOML(raw, target) }

func retainCodexTOMLBOM(original, rendered []byte) []byte {
	if bytes.HasPrefix(original, []byte{0xef, 0xbb, 0xbf}) {
		return append([]byte{0xef, 0xbb, 0xbf}, rendered...)
	}
	return rendered
}

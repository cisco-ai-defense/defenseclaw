// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"path/filepath"
	"strings"
)

// SkillSelection reads the skill a hook call selects from one field map.
// The gateway and the calling user's hook share this parser, so both sides
// accept the same name and path forms. It returns the normalized name, the
// explicit source path ("" for a name-only selection) and the raw input when
// normalization changed it.
func SkillSelection(values map[string]any) (name, sourcePath, rawName string) {
	if values == nil {
		return "", "", ""
	}
	sourcePath = firstSkillString(values, "skill_path", "skillPath", "source_path", "sourcePath")
	if raw := firstSkillString(values, "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId"); raw != "" {
		name = SkillRuntimeName(raw)
		return name, sourcePath, SkillRawNameIfNormalized(raw, name)
	}
	for _, key := range []string{"skill", "skill_info", "skillInfo", "source_skill", "sourceSkill"} {
		if value, ok := values[key]; ok {
			if nestedName, nestedPath, nestedRaw := skillSelectionValue(value); nestedName != "" {
				if sourcePath == "" {
					sourcePath = nestedPath
				}
				return nestedName, sourcePath, nestedRaw
			}
		}
	}
	if sourcePath != "" {
		name = SkillRuntimeName(sourcePath)
		return name, sourcePath, SkillRawNameIfNormalized(sourcePath, name)
	}
	return "", "", ""
}

func skillSelectionValue(value any) (string, string, string) {
	switch v := value.(type) {
	case string:
		name := SkillRuntimeName(v)
		return name, skillPathIfLooksLikePath(v), SkillRawNameIfNormalized(v, name)
	case map[string]any:
		sourcePath := firstSkillString(v, "path", "source_path", "sourcePath", "skill_path", "skillPath")
		raw := firstSkillString(v, "name", "key", "id", "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId")
		if raw == "" && sourcePath != "" {
			raw = sourcePath
		}
		name := SkillRuntimeName(raw)
		return name, sourcePath, SkillRawNameIfNormalized(raw, name)
	default:
		return "", "", ""
	}
}

// SkillRuntimeName maps a selected skill spelling to its registry name: a
// path names its folder (the folder holding SKILL.md for a manifest path).
func SkillRuntimeName(value string) string {
	name := strings.Trim(strings.TrimSpace(value), `"'`)
	if name == "" {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		path := filepath.Clean(name)
		if strings.EqualFold(filepath.Base(path), "SKILL.md") {
			path = filepath.Dir(path)
		}
		name = filepath.Base(path)
	}
	name = strings.TrimPrefix(name, "@")
	return strings.TrimSpace(name)
}

// SkillRawNameIfNormalized returns raw only when normalization changed it
// (path stripping, quote stripping, "@" removal), so audit records keep a
// path-shaped input next to the registry name.
func SkillRawNameIfNormalized(raw, normalized string) string {
	if strings.TrimSpace(raw) == "" || raw == normalized {
		return ""
	}
	return raw
}

func skillPathIfLooksLikePath(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if strings.ContainsAny(value, `/\`) {
		return value
	}
	return ""
}

// firstSkillString reads string fields only, so a structured value never
// becomes a name such as "map[a:b]".
func firstSkillString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := values[key].(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				return t
			}
		}
	}
	return ""
}

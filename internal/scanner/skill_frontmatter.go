// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// maxSkillManifestBytes bounds how much of SKILL.md is read to find the
// frontmatter description.
const maxSkillManifestBytes = 1 << 20

// skillDescription returns the frontmatter description of the skill at
// target (a skill directory or its SKILL.md), or "" when there is none.
func skillDescription(target string) string {
	manifest := target
	if info, err := os.Stat(target); err != nil {
		return ""
	} else if info.IsDir() {
		manifest = filepath.Join(target, "SKILL.md")
	}
	info, err := os.Stat(manifest)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSkillManifestBytes {
		return ""
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return ""
	}
	text := strings.ReplaceAll(strings.TrimPrefix(string(data), "\ufeff"), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return ""
	}
	end := strings.Index(text[4:], "\n---")
	if end < 0 {
		return ""
	}
	var front struct {
		Description any `yaml:"description"`
	}
	if yaml.Unmarshal([]byte(text[4:4+end]), &front) != nil {
		return ""
	}
	description, _ := front.Description.(string)
	return strings.TrimSpace(description)
}

// scanDescription YARA-scans a skill's frontmatter description (GAP-1671).
//
// skill-scanner runs YARA on the SKILL.md body only, but the description is
// the text every agent session loads. The Python 'skill scan' adds an
// analyzer for it in-process (GAP-1376); the gateway runs the upstream CLI,
// so it scans a throwaway skill whose body is the description, static
// analyzers only, and keeps the YARA findings. A failure here returns nothing:
// the main scan still decides on its own.
func (s *SkillScanner) scanDescription(ctx context.Context, description string) []Finding {
	dir, err := os.MkdirTemp("", "dc-skill-description-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)
	skillDir := filepath.Join(dir, "description")
	if err := os.Mkdir(skillDir, 0o700); err != nil {
		return nil
	}
	manifest := "---\nname: description\n" +
		"description: The frontmatter description of the scanned skill, checked as text.\n" +
		"license: Apache-2.0\n---\n\n" + description + "\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(manifest), 0o600); err != nil {
		return nil
	}

	args := []string{"scan", "--format", "json"}
	if s.Config.Policy != "" {
		args = append(args, "--policy", s.Config.Policy)
	}
	if s.Config.Lenient {
		args = append(args, "--lenient")
	}
	args = append(args, skillDir)
	cmd := processutil.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()
	out, err := cmd.Output()
	if len(out) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scanner] skill description scan: %v\n", err)
		}
		return nil
	}
	findings, err := parseSkillOutput(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[scanner] skill description scan: %v\n", err)
		return nil
	}
	kept := findings[:0]
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "YARA_") {
			continue
		}
		f.Location = "SKILL.md (frontmatter description)"
		kept = append(kept, f)
	}
	return kept
}

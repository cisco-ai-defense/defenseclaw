// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows || linux

package workspace

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	gitconfig "github.com/go-git/go-git/v5/plumbing/format/config"
)

const (
	hostStageMaxEntries = 250_000
	hostStageMaxDepth   = 128
	hostStageDeadline   = 5 * time.Minute
)

// Keep the existing Windows entry-name subset unchanged on both hosts. Linux
// intentionally refuses wider POSIX names until that capability is reviewed.
func validateWindowsHostStageName(name string) error {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsRune(name, utf8.RuneError) ||
		strings.ContainsAny(name, "\\/:*?\"<>|\x00") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") ||
		!filepath.IsLocal(name) || len(utf16.Encode([]rune(name))) > 255 {
		return errors.New("workspace: ambiguous or reserved Windows entry name")
	}
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return errors.New("workspace: reserved Windows device entry name")
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if suffix, ok := strings.CutPrefix(base, prefix); ok &&
			(len(suffix) == 1 && suffix[0] >= '0' && suffix[0] <= '9' || suffix == "¹" || suffix == "²" || suffix == "³") {
			return errors.New("workspace: reserved Windows device entry name")
		}
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("workspace: control character in Windows entry name")
		}
	}
	return nil
}

func parseCapturedGitConfig(data []byte) (*gitconfig.Config, error) {
	if len(data) > 1<<20 || bytes.Count(data, []byte{'\n'}) > 10_000 || bytes.IndexByte(data, 0) >= 0 {
		return nil, capturedRefuse("config_structure_limit")
	}
	cfg := gitconfig.New()
	if err := gitconfig.NewDecoder(bytes.NewReader(data)).Decode(cfg); err != nil {
		return nil, capturedRefuse("invalid_repository_config")
	}
	return cfg, nil
}

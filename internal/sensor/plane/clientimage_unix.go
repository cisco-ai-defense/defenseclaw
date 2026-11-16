// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package plane

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// claudeImageVersion is the release version an image's install layout names:
// the native installer's .../claude/versions/<version>, a Homebrew cask's
// Caskroom/claude-code/<version>/claude, or the npm package's
// @anthropic-ai/claude-code/bin/claude.exe with its package.json. "" for any
// other path, which is not hashed. The version only picks the manifest to
// compare with; the image digest is the identity.
func claudeImageVersion(path string) string {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ""
	}
	base, dir := filepath.Base(path), filepath.Dir(path)
	switch {
	case IsClaudeReleaseVersion(base) && filepath.Base(dir) == "versions" &&
		filepath.Base(filepath.Dir(dir)) == "claude":
		return base
	case base == "claude" && IsClaudeReleaseVersion(filepath.Base(dir)) &&
		filepath.Base(filepath.Dir(dir)) == "claude-code" &&
		filepath.Base(filepath.Dir(filepath.Dir(dir))) == "Caskroom":
		return filepath.Base(dir)
	case base == "claude.exe" && filepath.Base(dir) == "bin" &&
		filepath.Base(filepath.Dir(dir)) == "claude-code" &&
		filepath.Base(filepath.Dir(filepath.Dir(dir))) == "@anthropic-ai":
		return npmClaudeVersion(filepath.Join(filepath.Dir(dir), "package.json"))
	}
	return ""
}

// npmClaudeVersion reads the version of the @anthropic-ai/claude-code package
// whose manifest is at path, without following a link.
func npmClaudeVersion(path string) string {
	file, err := openNoFollow(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return ""
	}
	var metadata struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &metadata) != nil || metadata.Name != "@anthropic-ai/claude-code" ||
		!IsClaudeReleaseVersion(metadata.Version) {
		return ""
	}
	return metadata.Version
}

func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// macOS configuration profiles deliver Claude Code policy in the
// com.anthropic.claudecode managed-preferences domain, which outranks the
// file-based managed settings.
const claudeManagedPreferencesPlist = "/Library/Managed Preferences/com.anthropic.claudecode.plist"

func platformClaudeHigherSources(opts Options) ([]higherClaudeSource, error) {
	var sources []higherClaudeSource
	candidates := []string{rooted(opts, claudeManagedPreferencesPlist)}
	if matches, err := filepath.Glob(rooted(opts, "/Library/Managed Preferences/*/com.anthropic.claudecode.plist")); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return sources, err
		}
		if !info.Mode().IsRegular() {
			return sources, fmt.Errorf("%s is not a regular file", path)
		}
		data, err := plistToJSON(path)
		if err != nil {
			return sources, fmt.Errorf("convert %s: %w", path, err)
		}
		doc, err := decodeOrderedObject(data)
		if err != nil {
			return sources, fmt.Errorf("decode %s: %w", path, err)
		}
		sources = append(sources, higherClaudeSource{name: path, doc: doc})
	}
	return sources, nil
}

func plistToJSON(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "--", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	stdout, stderr := newLimitedBuffer(policyFileLimit), newLimitedBuffer(64<<10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	if stdout.Truncated() {
		// A policy document larger than the cap is never parsed in part.
		return nil, fmt.Errorf("%s converts to more than %d bytes of JSON", path, policyFileLimit)
	}
	return stdout.Bytes(), nil
}

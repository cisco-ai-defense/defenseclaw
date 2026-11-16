// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrAgentConfigOutsideHome marks a config write or removal DefenseClaw
// refused because the path is in the account's home but a symlink, the file
// itself or a folder on the way, takes it out of that home (rel-1-0-3
// GAP-0206).
var ErrAgentConfigOutsideHome = errors.New("agent config leads outside the home")

// AgentConfigOutsideHomeError names the agent config, the place outside the
// home it leads to and, when known, what that file still holds.
type AgentConfigOutsideHomeError struct {
	Path, Target, Detail string
}

func (e *AgentConfigOutsideHomeError) Error() string {
	detail := ""
	if e.Detail != "" {
		detail = ", " + e.Detail
	}
	return fmt.Sprintf("%s leads outside the home, to %s%s; DefenseClaw changed neither the link nor that file: "+
		"remove DefenseClaw's entries from that file, or replace the link with that file, then rerun", e.Path, e.Target, detail)
}

func (e *AgentConfigOutsideHomeError) Unwrap() error { return ErrAgentConfigOutsideHome }

// AgentConfigOutsideHome reports where path really leads when it is inside
// home but a symlink takes it out: a link out of the home, a link whose
// chain ends out of it (also when that file does not exist), or a linked
// folder on the way. A path outside home, or one that stays inside, is
// not reported. A link chain that cannot be followed is an error.
func AgentConfigOutsideHome(home, path string) (string, bool, error) {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return "", false, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	home = filepath.Clean(home)
	realHome := home
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		realHome = resolved
	}
	inside := func(candidate string) bool {
		return managedPathWithin(candidate, home) || managedPathWithin(candidate, realHome)
	}
	if !inside(absolute) {
		return "", false, nil
	}
	resolved, err := resolveAtomicWritePath(absolute)
	if err != nil {
		return "", false, err
	}
	physical, err := canonicalAtomicTransformTargetPath(resolved)
	if err != nil {
		// The folders on the way do not resolve; judge the link target.
		physical = filepath.Clean(resolved)
	}
	if inside(physical) {
		return "", false, nil
	}
	return physical, true, nil
}

// confineAtomicWritePath refuses a change through path when it leads out of
// the account home the enterprise per-user code bound with WithUserHomeDir.
// A teardown that restores or removes an agent config writes through a
// symlinked config; one that leads out of the home must leave that file
// alone, whoever owns it. The writers call it only for a change: a write
// or transform that would leave the file as it is still passes, so a file
// the account cleaned by hand does not keep its cleanup failing. Windows
// validates reparse points separately and is not confined here; with no
// bound home nothing changes.
func confineAtomicWritePath(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	home := activeUserHomeOverride()
	if home == "" {
		return nil
	}
	target, outside, err := AgentConfigOutsideHome(home, path)
	if err != nil {
		return err
	}
	if outside {
		return &AgentConfigOutsideHomeError{Path: filepath.Clean(path), Target: target}
	}
	return nil
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package skillrootsafe validates the filesystem path of a watched skill root.
package skillrootsafe

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Resolve returns the physical directory behind a configured skill root.
// Account-owned links are accepted only when every link and directory on the
// resolved path is controlled by that account or root. A permission-denied
// resolution may use the existing plain-directory proof, needed by a Windows
// service with access only to an enrolled user's skills folder.
func Resolve(path string, eval func(string) (string, error)) (string, error) {
	resolved, _, err := resolve(path, eval)
	return resolved, err
}

// ResolveWithWarnings is Resolve plus the folders of a linked route that the
// root was admitted through on the strength of a private group alone: group
// writable folders whose group is the private group of their owner, on a host
// where pam_group is loaded and so can add an account to that group at login
// (GAP-0905). The caller admits the root and watches it closely (every change
// under it is scanned again), and tells the user to remove the group write
// bit. Empty for a plain root and for a route with no group-writable folder.
func ResolveWithWarnings(path string, eval func(string) (string, error)) (string, []string, error) {
	resolved, folders, err := resolve(path, eval)
	if err != nil {
		return "", nil, err
	}
	return resolved, groupWritableWarnings(folders), nil
}

// resolve is Resolve plus the folders a linked route passes only because of a
// private group, before pam_group is asked.
func resolve(path string, eval func(string) (string, error)) (string, []string, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", nil, err
	}
	if eval == nil {
		eval = filepath.EvalSymlinks
	}
	canonical := canonicalSystemPath(absolute)
	resolved, err := eval(absolute)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) && UnlinkedAncestors(canonical) {
			return canonical, nil, nil
		}
		return "", nil, err
	}
	if samePath(canonical, resolved) {
		return resolved, nil, nil
	}
	return acceptLinkedRoot(canonical, resolved)
}

// UnlinkedAncestors is the fallback proof when a service can read a skills
// folder but cannot resolve its profile ancestors.
func UnlinkedAncestors(path string) bool {
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
	}
}

func samePath(left, right string) bool {
	left, leftErr := filepath.Abs(filepath.Clean(left))
	right, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

// macOS exposes these root-owned system folders through /private. Accept
// only those platform aliases; links below them still require validation.
func canonicalSystemPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, alias := range []string{"/etc", "/var", "/tmp"} {
		if path != alias && !strings.HasPrefix(path, alias+string(filepath.Separator)) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(alias)
		if err != nil || resolved != "/private"+alias {
			return path
		}
		if path == alias {
			return resolved
		}
		return filepath.Join(resolved, strings.TrimPrefix(path, alias+string(filepath.Separator)))
	}
	return path
}

// WritableAncestorError names the folder of a linked skill root that an
// account other than the owner can write, so the root is not trusted: a link
// target could be replaced through it.
type WritableAncestorError struct {
	Ancestor string
	Mode     os.FileMode
}

func (e *WritableAncestorError) Error() string {
	return fmt.Sprintf("%s is writable by another account (mode %04o); remove its group and other write bits (chmod go-w) to restore admission scanning",
		e.Ancestor, e.Mode.Perm())
}

func unsafeRoot(path string) error { return fmt.Errorf("linked or unavailable skill root: %s", path) }

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"fmt"
	"strings"
)

// ErrLinkBelowRoot reports a path that does not reach its file from a root
// through plain folders only: the root or an element below it is a link (a
// reparse point: a junction, a symbolic link, a mount point), or an opened
// file's final path is not the root's final path plus the path's own
// elements. A caller that holds more rights than the account owning the root
// (LocalSystem reading an account's file) refuses such a path: every folder
// between the root and the file is resolved with the caller's rights.
var ErrLinkBelowRoot = errors.New("a link (reparse point) lies at or below the root")

// errNotBelowRoot is a path that is not lexically below its root.
var errNotBelowRoot = errors.New("not below the root")

// ElementsBelow returns root and every path from root down to path, one
// element at a time, in Windows spelling (forward slashes and the \\?\
// prefix are normalised; root is compared case-insensitively). path must be
// lexically below root; an empty, "." or ".." element is refused. It is
// OS-independent so the decisions built on it run on every CI runner.
func ElementsBelow(root, path string) ([]string, error) {
	plainRoot := plainWindowsPath(root)
	if plainRoot == "" {
		return nil, fmt.Errorf("%w: empty root", errNotBelowRoot)
	}
	rest, err := windowsRelativeBelow(plainRoot, plainWindowsPath(path))
	if err != nil {
		return nil, err
	}
	elements := []string{plainRoot}
	current := plainRoot
	for _, part := range rest {
		current = joinWindowsElement(current, part)
		elements = append(elements, current)
	}
	return elements, nil
}

// ExpectedFinalPathBelow is the final path (GetFinalPathNameByHandle) a file
// at path has when nothing between root and it is a link: the final path of
// root followed by path's own elements below root. path is spelled below root
// (the same spelling of root as a prefix); the root's final path may differ
// from its spelling (a redirected profile, an 8.3 name, the \\?\ prefix).
func ExpectedFinalPathBelow(finalRoot, root, path string) (string, error) {
	rest, err := windowsRelativeBelow(plainWindowsPath(root), plainWindowsPath(path))
	if err != nil {
		return "", err
	}
	current := plainWindowsPath(finalRoot)
	if current == "" {
		return "", fmt.Errorf("%w: empty final root", errNotBelowRoot)
	}
	for _, part := range rest {
		current = joinWindowsElement(current, part)
	}
	return current, nil
}

// SameWindowsPath compares two Windows paths case-insensitively, with the
// \\?\ (and \\?\UNC\) prefix, forward slashes and a trailing separator
// normalised.
func SameWindowsPath(a, b string) bool {
	return strings.EqualFold(plainWindowsPath(a), plainWindowsPath(b))
}

// plainWindowsPath is path with backslashes, without the \\?\ prefix
// (\\?\UNC\server becomes \\server) and without a trailing separator other
// than a drive root's.
func plainWindowsPath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	switch {
	case len(path) >= 8 && strings.EqualFold(path[:8], `\\?\UNC\`):
		path = `\\` + path[8:]
	case strings.HasPrefix(path, `\\?\`):
		path = path[4:]
	}
	for len(path) > 3 && strings.HasSuffix(path, `\`) {
		path = path[:len(path)-1]
	}
	return path
}

func windowsRelativeBelow(root, path string) ([]string, error) {
	prefix := root
	if !strings.HasSuffix(prefix, `\`) {
		prefix += `\`
	}
	if len(path) <= len(prefix) || !strings.EqualFold(path[:len(prefix)], prefix) {
		return nil, fmt.Errorf("%w: %s is not below %s", errNotBelowRoot, path, root)
	}
	parts := strings.Split(path[len(prefix):], `\`)
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("%w: %s has an empty, . or .. element", errNotBelowRoot, path)
		}
	}
	return parts, nil
}

func joinWindowsElement(parent, name string) string {
	if strings.HasSuffix(parent, `\`) {
		return parent + name
	}
	return parent + `\` + name
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// memFS is an in-memory filesystem, so golden policies contain fixed paths
// and symlink layouts can be built without touching the host.
type memFS struct {
	nodes     map[string]memNode
	untrusted []string // path prefixes Trusted refuses
}

type memNode struct {
	dir  bool
	link string
	elf  bool
	mode fs.FileMode
}

func newMemFS() *memFS {
	return &memFS{nodes: map[string]memNode{"/": {dir: true, mode: 0o755}}}
}

func (m *memFS) mkdir(paths ...string) {
	for _, p := range paths {
		for cur := path.Clean(p); cur != "/" && cur != "."; cur = path.Dir(cur) {
			if _, ok := m.nodes[cur]; !ok {
				m.nodes[cur] = memNode{dir: true, mode: 0o755}
			}
		}
	}
}

func (m *memFS) file(p string, mode fs.FileMode) {
	m.mkdir(path.Dir(p))
	m.nodes[p] = memNode{mode: mode}
}

func (m *memFS) elf(p string) {
	m.mkdir(path.Dir(p))
	m.nodes[p] = memNode{elf: true, mode: 0o755}
}

func (m *memFS) script(p string) {
	m.file(p, 0o755)
}

func (m *memFS) symlink(p, target string) {
	m.mkdir(path.Dir(p))
	m.nodes[p] = memNode{link: target, mode: fs.ModeSymlink | 0o777}
}

func (m *memFS) resolve(p string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.New("too many links")
	}
	parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	cur := ""
	for i, part := range parts {
		if part == "" {
			continue
		}
		next := cur + "/" + part
		node, ok := m.nodes[next]
		if !ok {
			return "", fs.ErrNotExist
		}
		if node.link != "" {
			target := node.link
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(next), target)
			}
			return m.resolve(path.Join(target, strings.Join(parts[i+1:], "/")), depth+1)
		}
		cur = next
	}
	if cur == "" {
		cur = "/"
	}
	return cur, nil
}

type memInfo struct {
	name string
	node memNode
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64  { return 0 }
func (i memInfo) Mode() fs.FileMode {
	if i.node.dir {
		return fs.ModeDir | i.node.mode
	}
	return i.node.mode
}
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.node.dir }
func (i memInfo) Sys() any           { return nil }

func (m *memFS) EvalSymlinks(p string) (string, error) { return m.resolve(p, 0) }

func (m *memFS) Lstat(p string) (fs.FileInfo, error) {
	node, ok := m.nodes[path.Clean(p)]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return memInfo{name: path.Base(p), node: node}, nil
}

func (m *memFS) Stat(p string) (fs.FileInfo, error) {
	real, err := m.resolve(p, 0)
	if err != nil {
		return nil, err
	}
	return memInfo{name: path.Base(real), node: m.nodes[real]}, nil
}

func (m *memFS) ReadDir(p string) ([]fs.DirEntry, error) {
	real, err := m.resolve(p, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for key := range m.nodes {
		if key != real && path.Dir(key) == real {
			names = append(names, key)
		}
	}
	sort.Strings(names)
	var out []fs.DirEntry
	for _, key := range names {
		out = append(out, fs.FileInfoToDirEntry(memInfo{name: path.Base(key), node: m.nodes[key]}))
	}
	return out, nil
}

func (m *memFS) Glob(pattern string) ([]string, error) {
	var out []string
	for key := range m.nodes {
		if ok, _ := path.Match(pattern, key); ok {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memFS) IsELF(p string) bool {
	real, err := m.resolve(p, 0)
	return err == nil && m.nodes[real].elf
}

func (m *memFS) Trusted(p string, uid int) bool {
	for _, prefix := range m.untrusted {
		if inside(prefix, p) {
			return false
		}
		if real, err := m.resolve(p, 0); err == nil && inside(prefix, real) {
			return false
		}
	}
	return true
}

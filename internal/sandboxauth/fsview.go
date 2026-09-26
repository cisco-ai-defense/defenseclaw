// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxauth

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

var (
	// ErrNoHostView is returned for every path of a copy-mode sandbox: its
	// files live only inside the sandbox, and a same-named host path is
	// unrelated (possibly private) host data.
	ErrNoHostView = errors.New("sandboxauth: copy-mode sandbox paths have no host view")
	// ErrOutsideView is returned for a path that is not inside a mount, or
	// that resolves (through symlinks or "..") outside the mount it names.
	ErrOutsideView = errors.New("sandboxauth: path is outside the sandbox's mounted project")
	// ErrMasked is returned for a secret file the sandbox sees as empty.
	ErrMasked = errors.New("sandboxauth: path is a masked secret file")
	// ErrNotRegular is returned by ReadFile for anything but a regular file.
	ErrNotRegular = errors.New("sandboxauth: path is not a regular file")
	// ErrTooLarge is returned by ReadFile when the file exceeds the limit.
	ErrTooLarge = errors.New("sandboxauth: file exceeds the read limit")
)

// FS is the host filesystem surface an FSView uses. Production uses OSFS;
// tests substitute fakes to prove exactly which host operations a view
// performs (none, for copy mode).
type FS interface {
	Lstat(name string) (fs.FileInfo, error)
	EvalSymlinks(name string) (string, error)
	// OpenInRoot opens name relative to root for reading. Neither ".." nor
	// any symlink may resolve outside root, and opening must not block on a
	// FIFO. The returned file must implement Stat.
	OpenInRoot(root, name string) (fs.File, error)
}

// OSFS is the host filesystem.
type OSFS struct{}

// Lstat implements FS.
func (OSFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

// EvalSymlinks implements FS.
func (OSFS) EvalSymlinks(name string) (string, error) { return filepath.EvalSymlinks(name) }

// OpenInRoot implements FS with os.Root, which confines every path
// component, symlink target and ".." to root even if the tree changes
// concurrently.
func (OSFS) OpenInRoot(root, name string) (fs.File, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.OpenFile(name, os.O_RDONLY|openNonBlocking, 0)
}

// FSView maps paths named in a sandbox's hook payloads onto the host.
//
// In mount mode a sandbox path under a mount resolves to the host path it
// is bound to, and is accepted only if its real path (after every symlink)
// is still inside that same mount's real host root and is not a masked
// secret. A symlink the agent planted in the project resolves inside the
// container, but the gateway resolves it on the host, so this check is what
// keeps a link to ~/.ssh from turning a hook into a host-file read.
//
// In copy mode every method refuses without touching the filesystem.
//
// A view is cheap and request-scoped; it caches only the resolved mount
// roots. It is safe for concurrent use.
type FSView struct {
	mode   WorkdirMode
	mounts []Mount // longest SandboxPath first
	masks  []string
	// hostMasks are the lexical host paths of masks that lie under a mount.
	hostMasks []string
	fs        FS

	mu        sync.Mutex
	realRoots map[string]realRoot
}

type realRoot struct {
	path string
	err  error
}

// NewFSView builds the view for b. A nil fsys uses OSFS. Construction never
// touches the filesystem.
func NewFSView(b Binding, fsys FS) *FSView {
	if fsys == nil {
		fsys = OSFS{}
	}
	v := &FSView{mode: b.Workdir.Mode, fs: fsys, realRoots: make(map[string]realRoot)}
	if v.mode != WorkdirMount {
		return v
	}
	v.mounts = slices.Clone(b.Workdir.Mounts)
	slices.SortStableFunc(v.mounts, func(a, b Mount) int { return len(b.SandboxPath) - len(a.SandboxPath) })
	v.masks = slices.Clone(b.Workdir.Masks)
	for _, mask := range v.masks {
		for _, m := range v.mounts {
			if rel, ok := sandboxRel(m.SandboxPath, mask); ok {
				v.hostMasks = append(v.hostMasks, joinHost(m.HostPath, rel))
			}
		}
	}
	return v
}

// Mode returns the binding's workdir mode.
func (v *FSView) Mode() WorkdirMode { return v.mode }

// HostAccess reports whether any sandbox path can map to the host.
func (v *FSView) HostAccess() bool { return v.mode == WorkdirMount && len(v.mounts) > 0 }

// HostPath maps an existing sandbox path to its real host path.
func (v *FSView) HostPath(sandboxPath string) (string, error) {
	m, rel, err := v.mapSandbox(sandboxPath)
	if err != nil {
		return "", err
	}
	return v.resolve(m, rel)
}

// HostDir is HostPath restricted to directories. Hook handlers use it for
// the working directory named in a payload.
func (v *FSView) HostDir(sandboxPath string) (string, error) {
	real, err := v.HostPath(sandboxPath)
	if err != nil {
		return "", err
	}
	info, err := v.fs.Lstat(real)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("sandboxauth: %s is not a directory", sandboxPath)
	}
	return real, nil
}

// ContainHostPath validates a host path derived from a mapped path, such as
// a mapped working directory joined with a relative operand, and returns
// its real path. It refuses anything outside the view.
func (v *FSView) ContainHostPath(hostPath string) (string, error) {
	m, rel, err := v.mapHost(hostPath)
	if err != nil {
		return "", err
	}
	return v.resolve(m, rel)
}

// SandboxPath maps a host path inside a mount back into the sandbox
// namespace. It is lexical apart from resolving mount roots, and exists for
// values the gateway hands back to the harness, such as watch paths.
func (v *FSView) SandboxPath(hostPath string) (string, bool) {
	m, rel, err := v.mapHost(hostPath)
	if err != nil {
		return "", false
	}
	if rel == "" {
		return m.SandboxPath, true
	}
	return path.Join(m.SandboxPath, rel), true
}

// ReadFile reads a regular file named either by a sandbox path or by a host
// path inside the view. The open is confined to the mount's host root, so a
// symlink or directory swapped in after validation still cannot redirect
// the read outside the project, and a masked secret is refused by file
// identity as well as by name.
func (v *FSView) ReadFile(name string, maxBytes int64) ([]byte, fs.FileInfo, error) {
	if !v.HostAccess() {
		return nil, nil, ErrNoHostView
	}
	if maxBytes <= 0 {
		return nil, nil, errors.New("sandboxauth: read limit must be positive")
	}
	m, rel, err := v.mapSandbox(name)
	if errors.Is(err, ErrOutsideView) {
		m, rel, err = v.mapHost(name)
	}
	if err != nil {
		return nil, nil, err
	}
	if v.maskedHostLexical(joinHost(m.HostPath, rel)) {
		return nil, nil, ErrMasked
	}
	target := "."
	if rel != "" {
		target = filepath.FromSlash(rel)
	}
	f, err := v.fs.OpenInRoot(m.HostPath, target)
	if err != nil {
		if isEscape(err) {
			return nil, nil, ErrOutsideView
		}
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrNotRegular
	}
	if info.Size() > maxBytes {
		return nil, nil, ErrTooLarge
	}
	if v.maskedIdentity(info) {
		return nil, nil, ErrMasked
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, ErrTooLarge
	}
	return data, info, nil
}

func (v *FSView) mapSandbox(sandboxPath string) (Mount, string, error) {
	if !v.HostAccess() {
		return Mount{}, "", ErrNoHostView
	}
	if sandboxPath == "" || len(sandboxPath) > maxPathLength || strings.ContainsRune(sandboxPath, 0) ||
		!strings.HasPrefix(sandboxPath, "/") {
		return Mount{}, "", ErrOutsideView
	}
	cleaned := path.Clean(sandboxPath)
	for _, mask := range v.masks {
		if _, ok := sandboxRel(mask, cleaned); ok {
			return Mount{}, "", ErrMasked
		}
	}
	for _, m := range v.mounts {
		if rel, ok := sandboxRel(m.SandboxPath, cleaned); ok {
			return m, rel, nil
		}
	}
	return Mount{}, "", ErrOutsideView
}

func (v *FSView) mapHost(hostPath string) (Mount, string, error) {
	if !v.HostAccess() {
		return Mount{}, "", ErrNoHostView
	}
	if hostPath == "" || len(hostPath) > maxPathLength || strings.ContainsRune(hostPath, 0) ||
		!filepath.IsAbs(hostPath) {
		return Mount{}, "", ErrOutsideView
	}
	cleaned := filepath.Clean(hostPath)
	best, bestRel, bestLen := Mount{}, "", -1
	for _, m := range v.mounts {
		for _, root := range v.rootsOf(m) {
			if rel, ok := hostRel(root, cleaned); ok && len(root) > bestLen {
				best, bestRel, bestLen = m, rel, len(root)
			}
		}
	}
	if bestLen < 0 {
		return Mount{}, "", ErrOutsideView
	}
	return best, bestRel, nil
}

// resolve returns the real host path of rel under m after proving it stays
// inside m's real root and is not a mask.
func (v *FSView) resolve(m Mount, rel string) (string, error) {
	candidate := joinHost(m.HostPath, rel)
	if v.maskedHostLexical(candidate) {
		return "", ErrMasked
	}
	root, err := v.realRootOf(m)
	if err != nil {
		return "", err
	}
	real, err := v.fs.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if _, ok := hostRel(root, real); !ok {
		return "", ErrOutsideView
	}
	if v.maskedReal(real) {
		return "", ErrMasked
	}
	return real, nil
}

func (v *FSView) realRootOf(m Mount) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if cached, ok := v.realRoots[m.HostPath]; ok {
		return cached.path, cached.err
	}
	real, err := v.fs.EvalSymlinks(m.HostPath)
	if err != nil {
		err = fmt.Errorf("sandboxauth: resolve mount root: %w", err)
	}
	v.realRoots[m.HostPath] = realRoot{path: real, err: err}
	return real, err
}

// rootsOf returns the lexical and (when it resolves) real host roots of m.
func (v *FSView) rootsOf(m Mount) []string {
	roots := []string{m.HostPath}
	if real, err := v.realRootOf(m); err == nil && real != m.HostPath {
		roots = append(roots, real)
	}
	return roots
}

func (v *FSView) maskedHostLexical(hostPath string) bool {
	for _, mask := range v.hostMasks {
		if _, ok := hostRel(mask, hostPath); ok {
			return true
		}
	}
	return false
}

func (v *FSView) maskedReal(real string) bool {
	for _, mask := range v.hostMasks {
		if _, ok := hostRel(mask, real); ok {
			return true
		}
		if resolved, err := v.fs.EvalSymlinks(mask); err == nil {
			if _, ok := hostRel(resolved, real); ok {
				return true
			}
		}
	}
	return false
}

func (v *FSView) maskedIdentity(opened fs.FileInfo) bool {
	for _, mask := range v.hostMasks {
		target := mask
		if resolved, err := v.fs.EvalSymlinks(mask); err == nil {
			target = resolved
		}
		if info, err := v.fs.Lstat(target); err == nil && os.SameFile(opened, info) {
			return true
		}
	}
	return false
}

// sandboxRel returns p relative to root ("" for root itself) when p is root
// or below it. Both are clean absolute POSIX paths.
func sandboxRel(root, p string) (string, bool) {
	if p == root {
		return "", true
	}
	prefix := root
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if strings.HasPrefix(p, prefix) {
		return strings.TrimPrefix(p, prefix), true
	}
	return "", false
}

// hostRel is sandboxRel for host paths, returned in slash form.
func hostRel(root, p string) (string, bool) {
	if p == root {
		return "", true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if strings.HasPrefix(p, prefix) {
		return filepath.ToSlash(strings.TrimPrefix(p, prefix)), true
	}
	return "", false
}

func joinHost(root, rel string) string {
	if rel == "" {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

// isEscape recognises os.Root's refusal to leave its directory.
func isEscape(err error) bool {
	return err != nil && strings.Contains(err.Error(), "path escapes from parent")
}

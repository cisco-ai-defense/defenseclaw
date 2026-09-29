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

package openshell

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The OpenShell 0.1.1 CLI opens a sandbox's ssh sessions (sandbox connect,
// upload, download, forward start) by running `ssh` from PATH with a
// ProxyCommand that names the sandbox, and the same host name, "sandbox",
// for every sandbox. The user's ssh_config still applies, so a
// `ControlMaster auto` / `ControlPath ~/.ssh/cm-%C` there gives every
// sandbox the same control socket: for as long as the first session's
// master connection stays up (ControlPersist), every later ssh the CLI
// runs, whatever sandbox it names, rides it into the first sandbox. An
// upload then lands in the wrong sandbox and a connect attaches the
// terminal to it.
//
// DefenseClaw does not edit the user's ssh configuration. Every openshell
// invocation it runs instead gets a private directory first on its PATH
// holding an `ssh` shim that runs the real ssh with SSHNoSharingOptions
// before the CLI's own arguments. Options on the ssh command line win over
// every ssh_config file.

// sshNoSharingOptions turn OpenSSH connection sharing off: no master
// connection, no control socket to reuse, nothing kept open afterwards.
var sshNoSharingOptions = [...]string{"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"}

// SSHNoSharingOptions are the options the shim puts before the OpenShell
// CLI's own ssh arguments.
func SSHNoSharingOptions() []string { return append([]string(nil), sshNoSharingOptions[:]...) }

const (
	// sshShimPrefix starts the name of every shim directory.
	sshShimPrefix = "defenseclaw-ssh-"
	// sshShimMarker is the shim's second line. An ssh on PATH with it near
	// the top is another DefenseClaw process's shim, never the real ssh.
	sshShimMarker = "# defenseclaw: the ssh the OpenShell CLI runs, without connection sharing"
	// maxSSHShimBytes bounds what Verify reads back.
	maxSSHShimBytes = 4096
)

// sshShimBase is where shim directories are made; empty means
// os.TempDir(). Tests point it at their own directory.
var sshShimBase = ""

// sshShimOwned judges the shim and its directory, sshShimTrusted the
// directories above it (the caller's or root's). Tests replace them.
var (
	sshShimOwned   = ownedByCaller
	sshShimTrusted = ownedByCallerOrRoot
)

// SSHShim is a private directory holding an `ssh` that runs the real ssh
// with connection sharing off.
type SSHShim struct {
	// Dir is the directory, owner-only, first on the child's PATH.
	Dir string
	// Path is the shim, Dir/ssh.
	Path string
	// Real is the ssh the shim runs: the first ssh on the PATH it was made
	// for, as an absolute path.
	Real string

	// made marks a shim NewSSHShim wrote, whose directory Remove deletes.
	made   bool
	remove sync.Once
}

// NewSSHShim finds the ssh that pathEnv (a PATH value) resolves and writes
// a shim for it in a new private directory under the temporary directory.
// It returns nil and no error when pathEnv has no ssh, which leaves the
// OpenShell CLI none to share connections with either, and on Windows,
// where OpenShell sandboxes do not run and Win32-OpenSSH has no connection
// sharing. It refuses a temporary directory that another user could
// replace the shim in. The caller removes the shim once the command it
// was made for has exited.
func NewSSHShim(pathEnv string) (*SSHShim, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	realSSH, ok := findRealSSH(pathEnv)
	if !ok {
		return nil, nil
	}
	return newSSHShimIn(sshShimBase, realSSH)
}

func newSSHShimIn(base, realSSH string) (*SSHShim, error) {
	if base == "" {
		base = os.TempDir()
	}
	if strings.ContainsAny(realSSH, "\x00\n\r") || !filepath.IsAbs(realSSH) {
		return nil, fmt.Errorf("ssh shim: unusable ssh path %q", realSSH)
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("ssh shim: temporary directory %s: %w", base, err)
	}
	if err := checkSSHShimAncestors(resolved); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(resolved, sshShimPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("ssh shim: %w", err)
	}
	s := &SSHShim{Dir: dir, Path: filepath.Join(dir, "ssh"), Real: realSSH, made: true}
	if err := s.write(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return s, nil
}

// write puts the shim in place atomically (a temporary file renamed over
// Path) and reads it back.
func (s *SSHShim) write() error {
	if err := checkSSHShimDir(s.Dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".ssh-*")
	if err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.Write(sshShimScript(s.Real))
	if werr == nil {
		werr = f.Chmod(0o700)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("ssh shim: write %s: %w", tmp, werr)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	return s.Verify()
}

// Verify checks that the shim is still exactly what NewSSHShim wrote, a
// regular file of the user's, in a directory only the user can write.
func (s *SSHShim) Verify() error {
	if err := checkSSHShimDir(s.Dir); err != nil {
		return err
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	if !info.Mode().IsRegular() || !sshShimOwned(info) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("ssh shim: %s is not a private file of yours (mode %v)", s.Path, info.Mode())
	}
	data, err := safefile.ReadRegularFileBounded(s.Path, maxSSHShimBytes)
	if err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	if !bytes.Equal(data, sshShimScript(s.Real)) {
		return fmt.Errorf("ssh shim: %s is not the shim DefenseClaw wrote", s.Path)
	}
	return nil
}

// Environ returns env with Dir first on PATH.
func (s *SSHShim) Environ(env []string) []string {
	out := make([]string, 0, len(env)+1)
	path := s.Dir
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if name == "PATH" {
			if value != "" {
				path = s.Dir + string(os.PathListSeparator) + value
			}
			continue
		}
		out = append(out, kv)
	}
	return append(out, "PATH="+path)
}

// Remove deletes a shim NewSSHShim made. The ssh it started keeps running:
// the shim execs the real ssh, so nothing needs the file once ssh runs.
func (s *SSHShim) Remove() error {
	if s == nil || !s.made {
		return nil
	}
	var err error
	s.remove.Do(func() { err = os.RemoveAll(s.Dir) })
	return err
}

// sshShimScript is the shim that runs realSSH.
func sshShimScript(realSSH string) []byte {
	return []byte("#!/bin/sh\n" + sshShimMarker + "\nexec " + shellQuote(realSSH) + " " + strings.Join(sshNoSharingOptions[:], " ") + " \"$@\"\n")
}

// findRealSSH is the ssh a command-name lookup of pathEnv finds, skipping
// relative entries (never trusted for this) and DefenseClaw's own shims.
func findRealSSH(pathEnv string) (string, bool) {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) || strings.HasPrefix(filepath.Base(dir), sshShimPrefix) {
			continue
		}
		p := filepath.Join(dir, "ssh")
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		if isSSHShim(p) {
			continue
		}
		return p, true
	}
	return "", false
}

// isSSHShim reports whether the executable at p is a DefenseClaw shim.
func isSSHShim(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 256)
	n, _ := f.Read(head)
	return bytes.Contains(head[:n], []byte(sshShimMarker))
}

// checkSSHShimDir refuses a shim directory that is not a directory of the
// user's, or that other users can write.
func checkSSHShimDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	switch {
	case !info.IsDir():
		return fmt.Errorf("ssh shim: %s is not a directory", dir)
	case !sshShimOwned(info):
		return fmt.Errorf("ssh shim: %s is not owned by you", dir)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("ssh shim: %s is writable by other users (mode %04o)", dir, info.Mode().Perm())
	}
	return nil
}

// errSSHShimUnsafe marks a temporary directory another user could replace
// a shim in.
var errSSHShimUnsafe = errors.New("another user could replace the ssh DefenseClaw gives the OpenShell CLI there; set TMPDIR to a directory only you can write")

// checkSSHShimAncestors refuses a temporary directory (already free of
// symbolic links) that, or any directory above it, belongs to another user
// than the caller or root, or that other users can write without the
// sticky bit that stops them renaming what is inside (as in /tmp).
func checkSSHShimAncestors(dir string) error {
	for p := dir; ; {
		info, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("ssh shim: %w", err)
		}
		switch {
		case !info.IsDir():
			return fmt.Errorf("ssh shim: %s is not a directory", p)
		case !sshShimTrusted(info):
			return fmt.Errorf("ssh shim: %s belongs to another user: %w", p, errSSHShimUnsafe)
		case info.Mode().Perm()&0o022 != 0 && info.Mode()&fs.ModeSticky == 0:
			return fmt.Errorf("ssh shim: %s is writable by other users (mode %04o): %w", p, info.Mode().Perm(), errSSHShimUnsafe)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

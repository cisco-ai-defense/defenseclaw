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
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

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
//
// A PATH search passes over a file it cannot execute and runs the next
// `ssh` on PATH, the user's own, with its connection sharing: a shim on a
// filesystem mounted noexec (/tmp on hardened Linux hosts) would be put in
// place and never run. So a shim counts only once a PATH search of the
// child's PATH has found it and it has run; when the temporary directory
// cannot hold one that does, the shim goes under DefenseClaw's data
// directory, and when that cannot either the command is refused.

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
	// sshShimProbeEnv, set, makes a shim print its value and exit without
	// running ssh: the run that proves the shim executes. Environ keeps it
	// from the OpenShell CLI.
	sshShimProbeEnv = "DEFENSECLAW_SSH_SHIM_PROBE"
	// sshShimFallbackName is the directory under DefenseClaw's data
	// directory that holds shims when the temporary directory cannot.
	sshShimFallbackName = "openshell-ssh"
	// sshShimProbeTimeout bounds the probe run.
	sshShimProbeTimeout = 10 * time.Second
	// maxSSHShimBytes bounds what Verify reads back.
	maxSSHShimBytes = 4096
)

// sshShimBase is where shim directories are made first; empty means
// os.TempDir(). Tests point it at their own directory.
var sshShimBase = ""

// sshShimFallback is where shim directories are made when sshShimBase
// cannot hold one that runs; empty means nowhere. Tests replace it.
var sshShimFallback = defaultSSHShimFallback

// sshShimOwned judges the shim and its directory, sshShimTrusted the
// directories above it (the caller's or root's). Tests replace them.
var (
	sshShimOwned   = ownedByCaller
	sshShimTrusted = ownedByCallerOrRoot
)

// sshShimNoexec reports whether a directory's filesystem is mounted
// noexec; sshShimMode is the mode the shim is written with. Tests replace
// them to stand for a filesystem the shim cannot run from.
var (
	sshShimNoexec             = mountedNoexec
	sshShimMode   fs.FileMode = 0o700
)

// sshShimDataDir is DefenseClaw's data directory, as SetSSHShimDataDir
// named it.
var sshShimDataDir struct {
	sync.Mutex
	dir string
}

// SetSSHShimDataDir names DefenseClaw's data directory. Its openshell-ssh
// folder holds the ssh shims when the temporary directory cannot hold one
// that runs. Unset, it is $DEFENSECLAW_HOME, else ~/.defenseclaw.
func SetSSHShimDataDir(dir string) {
	sshShimDataDir.Lock()
	defer sshShimDataDir.Unlock()
	sshShimDataDir.dir = dir
}

// defaultSSHShimFallback is the openshell-ssh folder of DefenseClaw's data
// directory, or empty when there is none to use.
func defaultSSHShimFallback() string {
	sshShimDataDir.Lock()
	dir := sshShimDataDir.dir
	sshShimDataDir.Unlock()
	if dir == "" {
		dir = os.Getenv("DEFENSECLAW_HOME")
	}
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".defenseclaw")
		}
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return ""
	}
	return filepath.Join(dir, sshShimFallbackName)
}

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
	// Fallback, when set, says why the temporary directory could not hold
	// the shim, which is then under DefenseClaw's data directory.
	Fallback string

	// pathEnv is the PATH the shim was made for.
	pathEnv string
	// made marks a shim NewSSHShim wrote, whose directory Remove deletes.
	made   bool
	remove sync.Once
}

// errSSHShimUnsafe marks a directory another user could replace a shim
// in.
var errSSHShimUnsafe = errors.New("another user could replace the ssh DefenseClaw gives the OpenShell CLI there")

// NewSSHShim finds the ssh that pathEnv (a PATH value) resolves and writes
// a shim for it in a new private directory under the temporary directory,
// or, when no shim there would run (or the directory is not safe), under
// DefenseClaw's data directory. It returns nil and no error when pathEnv
// has no ssh, which leaves the OpenShell CLI none to share connections
// with either, and on Windows, where OpenShell sandboxes do not run and
// Win32-OpenSSH has no connection sharing. It refuses when neither
// directory can hold a shim that runs and that no other user could
// replace. The caller removes the shim once the command it was made for
// has exited.
func NewSSHShim(pathEnv string) (*SSHShim, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	realSSH, ok := findRealSSH(pathEnv)
	if !ok {
		return nil, nil
	}
	if strings.ContainsAny(realSSH, "\x00\n\r") || !filepath.IsAbs(realSSH) {
		return nil, fmt.Errorf("ssh shim: unusable ssh path %q", realSSH)
	}
	base := sshShimBase
	if base == "" {
		base = os.TempDir()
	}
	s, err := newSSHShimIn(base, realSSH, pathEnv, false)
	if err == nil {
		return s, nil
	}
	reasons := []string{err.Error()}
	if fallback := sshShimFallback(); fallback != "" && filepath.Clean(fallback) != filepath.Clean(base) {
		s, ferr := newSSHShimIn(fallback, realSSH, pathEnv, true)
		if ferr == nil {
			s.Fallback = err.Error()
			return s, nil
		}
		reasons = append(reasons, ferr.Error())
	}
	return nil, fmt.Errorf("ssh shim: DefenseClaw found no directory for an ssh with connection sharing off that the OpenShell CLI would run (%s); "+
		"set TMPDIR to a directory only you can write, on a filesystem not mounted noexec", strings.Join(reasons, "; "))
}

// newSSHShimIn makes a shim in a new directory under base, which create
// makes when it is missing, and proves that it runs.
func newSSHShimIn(base, realSSH, pathEnv string, create bool) (*SSHShim, error) {
	if create {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return nil, err
		}
	}
	resolved, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, err
	}
	if err := checkSSHShimAncestors(resolved); err != nil {
		return nil, err
	}
	switch noexec, err := sshShimNoexec(resolved); {
	case err != nil:
		return nil, fmt.Errorf("%s: %w", resolved, err)
	case noexec:
		return nil, fmt.Errorf("%s is on a filesystem mounted noexec", resolved)
	}
	dir, err := os.MkdirTemp(resolved, sshShimPrefix+"*")
	if err != nil {
		return nil, err
	}
	s := &SSHShim{Dir: dir, Path: filepath.Join(dir, "ssh"), Real: realSSH, pathEnv: pathEnv, made: true}
	if err := s.write(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := s.probe(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return s, nil
}

// write puts the shim in place atomically (a temporary file renamed over
// Path) and reads it back.
func (s *SSHShim) write() error {
	if _, err := checkSSHShimDir(s.Dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".ssh-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	_, werr := f.Write(sshShimScript(s.Real))
	if werr == nil {
		werr = f.Chmod(sshShimMode)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("write %s: %w", tmp, werr)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return err
	}
	return s.verify()
}

// probe runs the shim once the way the OpenShell CLI will: found by a PATH
// search of the child's PATH, then executed. With sshShimProbeEnv set it
// answers without running ssh. A shim the search passes over (not
// executable, on a filesystem mounted noexec) or that the system refuses
// to run fails the probe: the CLI would run the user's own ssh instead.
func (s *SSHShim) probe() error {
	childPath := s.Dir
	if s.pathEnv != "" {
		childPath += string(os.PathListSeparator) + s.pathEnv
	}
	if found := lookPathIn("ssh", childPath); found != s.Path {
		if found == "" {
			found = "no ssh"
		}
		return fmt.Errorf("a PATH search passes over the shim in %s, which it cannot execute, and finds %s", s.Dir, found)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	want := hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithTimeout(context.Background(), sshShimProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Path)
	cmd.Env = []string{"PATH=" + childPath, sshShimProbeEnv + "=" + want}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	switch {
	case err != nil:
		return fmt.Errorf("the shim in %s does not run: %v", s.Dir, err)
	case strings.TrimSpace(string(out)) != want:
		return fmt.Errorf("the shim in %s answered %q when run, not what DefenseClaw wrote in it", s.Dir, bytes.TrimSpace(out))
	}
	return nil
}

// Verify checks that the shim is still exactly what NewSSHShim wrote, a
// regular file of the user's, in a directory only the user can write, and
// that no macOS ACL on either lets another user write them.
func (s *SSHShim) Verify() error {
	if err := s.verify(); err != nil {
		return fmt.Errorf("ssh shim: %w", err)
	}
	return nil
}

func (s *SSHShim) verify() error {
	dirInfo, err := checkSSHShimDir(s.Dir)
	if err != nil {
		return err
	}
	info, err := os.Lstat(s.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !sshShimOwned(info) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a private file of yours (mode %v)", s.Path, info.Mode())
	}
	// What the mode bits do not show: an ACL entry, inherited from the
	// directory or added since, that lets another user rewrite the shim.
	if err := checkSSHShimACL(s.Dir, dirInfo, false); err != nil {
		return fmt.Errorf("%v: %w", err, errSSHShimUnsafe)
	}
	if err := checkSSHShimACL(s.Path, info, false); err != nil {
		return fmt.Errorf("%v: %w", err, errSSHShimUnsafe)
	}
	data, err := safefile.ReadRegularFileBounded(s.Path, maxSSHShimBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, sshShimScript(s.Real)) {
		return fmt.Errorf("%s is not the shim DefenseClaw wrote", s.Path)
	}
	return nil
}

// Environ returns env with Dir first on PATH, and without the variable
// that makes the shim answer a probe instead of running ssh.
func (s *SSHShim) Environ(env []string) []string {
	out := make([]string, 0, len(env)+1)
	path := s.Dir
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		switch name {
		case "PATH":
			if value != "" {
				path = s.Dir + string(os.PathListSeparator) + value
			}
			continue
		case sshShimProbeEnv:
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
	return []byte("#!/bin/sh\n" + sshShimMarker + "\n" +
		"if [ -n \"${" + sshShimProbeEnv + "+x}\" ]; then printf '%s\\n' \"$" + sshShimProbeEnv + "\"; exit 0; fi\n" +
		"exec " + shellQuote(realSSH) + " " + strings.Join(sshNoSharingOptions[:], " ") + " \"$@\"\n")
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

// lookPathIn is the file a PATH search for name finds in pathEnv, as
// exec.LookPath does it: the first regular file the caller may execute.
// Relative entries are skipped.
func lookPathIn(name, pathEnv string) string {
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		if p := filepath.Join(dir, name); executableFile(p) {
			return p
		}
	}
	return ""
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
// user's, or that other users can write by its mode bits, and returns
// what it found.
func checkSSHShimDir(dir string) (fs.FileInfo, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	switch {
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a directory", dir)
	case !sshShimOwned(info):
		return nil, fmt.Errorf("%s is not owned by you", dir)
	case info.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s is writable by other users (mode %04o)", dir, info.Mode().Perm())
	}
	return info, nil
}

// checkSSHShimAncestors refuses a directory (already free of symbolic
// links) that, or any directory above it, belongs to another user than
// the caller or root, that other users can write without the sticky bit
// that stops them renaming what is inside (as in /tmp), or whose macOS
// ACL grants a write-capable right, inheritable or not.
func checkSSHShimAncestors(dir string) error {
	for p := dir; ; {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case !info.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case !sshShimTrusted(info):
			return fmt.Errorf("%s belongs to another user: %w", p, errSSHShimUnsafe)
		case info.Mode().Perm()&0o022 != 0 && info.Mode()&fs.ModeSticky == 0:
			return fmt.Errorf("%s is writable by other users (mode %04o): %w", p, info.Mode().Perm(), errSSHShimUnsafe)
		}
		if err := checkSSHShimACL(p, info, true); err != nil {
			return fmt.Errorf("%v: %w", err, errSSHShimUnsafe)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

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

package workspace

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSandbox implements Transport against a local directory standing in
// for the sandbox filesystem: "/sandbox/x" is <root>/sandbox/x. Exec runs
// the command with the host shell after rewriting sandbox paths, which is
// enough for the git scripts copy mode sends.
type fakeSandbox struct {
	t    *testing.T
	root string
	home string

	mu        sync.Mutex
	uploads   []string
	downloads []string
	// failExec makes the next Exec return this error.
	failExec error
}

func newFakeSandbox(t *testing.T, e *env) *fakeSandbox {
	root := filepath.Join(e.root, "sandbox-fs")
	mustMkdir(t, filepath.Join(root, "sandbox"))
	return &fakeSandbox{t: t, root: root, home: e.home}
}

func (f *fakeSandbox) local(p string) string {
	return filepath.Join(f.root, filepath.FromSlash(p))
}

func (f *fakeSandbox) rewrite(s string) string {
	return strings.ReplaceAll(s, "/sandbox/", f.root+"/sandbox/")
}

func (f *fakeSandbox) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	f.mu.Lock()
	if err := f.failExec; err != nil {
		f.failExec = nil
		f.mu.Unlock()
		return nil, err
	}
	f.mu.Unlock()
	argv := make([]string, len(req.Argv))
	for i, a := range req.Argv {
		argv[i] = f.rewrite(a)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = f.local("/sandbox")
	cmd.Env = append(os.Environ(), "HOME="+f.home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if req.Stdout != nil {
		cmd.Stdout = req.Stdout
	}
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		return nil, err
	}
	return &ExecResult{ExitCode: code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

func (f *fakeSandbox) Upload(_ context.Context, sandbox, localPath, remoteDir string) error {
	f.mu.Lock()
	f.uploads = append(f.uploads, localPath+" -> "+remoteDir)
	f.mu.Unlock()
	dst := filepath.Join(f.local(remoteDir), filepath.Base(localPath))
	return copyTree(localPath, dst)
}

func (f *fakeSandbox) Download(_ context.Context, sandbox, remotePath, localDir string) error {
	f.mu.Lock()
	f.downloads = append(f.downloads, remotePath+" -> "+localDir)
	f.mu.Unlock()
	return copyTree(f.local(remotePath), filepath.Join(localDir, filepath.Base(remotePath)))
}

func copyTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return copyRegular(src, dst, info.Mode(), info.ModTime())
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		to := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(to, info.Mode().Perm()|0o700)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, to)
		default:
			return copyRegular(p, to, info.Mode(), info.ModTime())
		}
	})
}

// agent runs a git command in the sandbox copy as the agent would.
func (f *fakeSandbox) agent(dir string, args ...string) string {
	f.t.Helper()
	return runGit(f.t, f.home, f.local(dir), args...)
}

func (f *fakeSandbox) write(rel, content string) {
	f.t.Helper()
	writeFile(f.t, f.root, strings.TrimPrefix(rel, "/"), content)
}

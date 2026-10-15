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

package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func testHomeCompiler(t *testing.T, content string) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	installer := filepath.Join(home, "installer")
	if err := os.Mkdir(installer, 0o700); err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(installer, "policy_compiler.py")
	if err := os.WriteFile(compiler, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, compiler
}

func TestDefaultHomeCompilerWhenEnvironmentUnset(t *testing.T) {
	base := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", "")
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", base)
	} else {
		t.Setenv("HOME", base)
	}
	home := filepath.Join(base, ".defenseclaw")
	installer := filepath.Join(home, "installer")
	if err := os.MkdirAll(installer, 0o700); err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(installer, "policy_compiler.py")
	if err := os.WriteFile(compiler, []byte("# synthetic compiler\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := homeInstallerRoot(); got != home {
		t.Fatalf("default installer home = %q, want %q", got, home)
	}
	if got := homeInstallerCompilerPath(); got != compiler {
		t.Fatalf("default installer compiler = %q, want %q", got, compiler)
	}
	if !isUnderAllowedDir(compiler) {
		t.Fatal("default installed compiler rejected by trusted path validation")
	}
	if sourceCompilerPath() == "" && defaultCompilerPath() != compiler {
		t.Fatalf("default compiler selection did not find %q", compiler)
	}
}

func TestHomeInstallerCompilerUsesPinnedPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test needs Unix venv symlinks")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	python, err = filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	home, compiler := testHomeCompiler(t, "import sys\nsys.exit(65)\n")
	venvBin := filepath.Join(home, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o700); err != nil {
		t.Fatal(err)
	}
	venvPython := filepath.Join(venvBin, "python")
	if err := os.Symlink(python, venvPython); err != nil {
		t.Fatal(err)
	}
	if got := homeInstallerCompilerPath(); got != compiler {
		t.Fatalf("home compiler = %q, want %q", got, compiler)
	}
	if got, err := pythonForCompiler(compiler); err != nil || got != venvPython {
		t.Fatalf("Python = %q, %v; want %q", got, err, venvPython)
	}
	svc := NewService(nil, nil, nil, &Config{CompilerPath: compiler})
	_, err = svc.Compile([]byte("default_action: block\n"), "standard", 1)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("compiler exit 65 should be invalid policy, got %v", err)
	}
	if err := os.WriteFile(compiler, []byte("import sys\nsys.exit(1)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Compile([]byte("default_action: block\n"), "standard", 1)
	if err == nil || errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("compiler runtime exit 1 should stay server error, got %v", err)
	}
	_, err = svc.Compile([]byte("x"), "unknown", 1)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid profile should be invalid policy, got %v", err)
	}
	_, err = svc.Compile([]byte(strings.Repeat("x", 65537)), "standard", 1)
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("oversized YAML should be invalid policy, got %v", err)
	}
}

func TestHomeInstallerCompilerRejectsWritableOrLinkedScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission test")
	}
	home, compiler := testHomeCompiler(t, "# bundled compiler\n")
	installer := filepath.Dir(compiler)
	if err := os.Chmod(installer, 0o777); err != nil {
		t.Fatal(err)
	}
	if got := homeInstallerCompilerPath(); got != "" {
		t.Fatalf("accepted writable compiler directory %q", got)
	}
	if err := os.Chmod(installer, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(compiler, filepath.Join(home, "target.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "target.py"), compiler); err != nil {
		t.Fatal(err)
	}
	if got := homeInstallerCompilerPath(); got != "" {
		t.Fatalf("accepted linked compiler script %q", got)
	}
}

func TestPolicyVersionRejectsErasedFlashSentinel(t *testing.T) {
	svc, _, store := newTestService()
	if _, err := svc.Compile([]byte("default_action: block\n"), "standard", 65535); !errors.Is(err, ErrPolicyVersionExhausted) {
		t.Fatalf("compiler accepted reserved version 65535: %v", err)
	}
	if _, err := svc.Compile([]byte("default_action: block\n"), "standard", 0); errors.Is(err, ErrPolicyVersionExhausted) {
		t.Fatalf("simulation version zero was rejected: %v", err)
	}
	if _, err := svc.Compile([]byte("default_action: block\n"), "standard", 65534); errors.Is(err, ErrPolicyVersionExhausted) {
		t.Fatalf("compiler prematurely exhausted version 65534: %v", err)
	}
	if err := store.SavePolicy(1, 2, 65534, BuildPolicyBlob(65534, 0, nil), make([]byte, 64), "standard"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CompileSignAndStore([]byte("default_action: block\n"), "standard", 1, 2); !errors.Is(err, ErrPolicyVersionExhausted) {
		t.Fatalf("automatic allocator issued reserved version 65535: %v", err)
	}
}

func TestConcurrentPolicyPushAllocatesDistinctVersions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test needs Unix venv symlinks")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	python, err = filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately widen the race between GetLatestPolicy and SavePolicy.
	// This compiler writes a valid minimal policy header without PyYAML.
	const compilerSource = `import argparse, pathlib, struct, time
p = argparse.ArgumentParser()
p.add_argument('--input')
p.add_argument('--profile')
p.add_argument('--version', type=int)
p.add_argument('--output-binary')
p.add_argument('--output-header')
a = p.parse_args()
time.sleep(0.03)
pathlib.Path(a.output_binary).write_bytes(struct.pack('>HHHH', a.version, 0, 0, 0))
`
	home, compiler := testHomeCompiler(t, compilerSource)
	venvBin := filepath.Join(home, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(python, filepath.Join(venvBin, "python")); err != nil {
		t.Fatal(err)
	}
	signer, err := NewHMACSigner([]byte("test-key-for-unit-tests-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryPolicyStore()
	svc := NewService(store, signer, nil, &Config{CompilerPath: compiler})
	const pushes = 12
	var wg sync.WaitGroup
	versions := make(chan uint32, pushes)
	errors := make(chan error, pushes)
	for i := 0; i < pushes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, version, err := svc.CompileSignAndStore([]byte("default_action: block\n"), "edge", 1, 2)
			if err != nil {
				errors <- err
				return
			}
			versions <- version
		}()
	}
	wg.Wait()
	close(errors)
	close(versions)
	for err := range errors {
		t.Errorf("concurrent policy push failed: %v", err)
	}
	var got []int
	for version := range versions {
		got = append(got, int(version))
	}
	sort.Ints(got)
	if len(got) != pushes {
		t.Fatalf("successful versions = %v, want %d", got, pushes)
	}
	for i, version := range got {
		if version != i+1 {
			t.Fatalf("versions = %v, want contiguous 1..%d", got, pushes)
		}
	}
	latest, err := store.GetLatestPolicy(1, 2)
	if err != nil || latest == nil || latest.Version != pushes {
		t.Fatalf("latest policy = %+v, %v; want version %d", latest, err, pushes)
	}
}

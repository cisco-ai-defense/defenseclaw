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
	"path/filepath"
	"testing"
	"time"
)

// privateHomeCompiler writes a compiler stub under a private DEFENSECLAW_HOME
// and returns the home directory, or skips when this host's temp directory
// cannot satisfy the trusted-path checks.
func privateHomeCompiler(t *testing.T) string {
	t.Helper()
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "dchome")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "pc.py"), []byte("print('stub')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCompilerPath(filepath.Join(home, "pc.py")); err != nil {
		t.Skipf("private-home compiler not trusted on this host: %v", err)
	}
	return base
}

// A relative compiler path is resolved once, so the file that is validated
// is the file that is executed (not one relative to the compile temp dir).
func TestRelativeCompilerPathResolvedOnce(t *testing.T) {
	base := privateHomeCompiler(t)
	t.Chdir(base)
	svc := NewService(nil, nil, nil, &Config{CompilerPath: "dchome/pc.py"})
	want := filepath.Join(base, "dchome", "pc.py")
	if svc.compilerPath != want {
		t.Fatalf("compiler path = %q, want %q", svc.compilerPath, want)
	}
	// Changing directory later does not change which file runs.
	t.Chdir(t.TempDir())
	if svc.compilerPath != want || !filepath.IsAbs(svc.compilerPath) {
		t.Fatalf("compiler path changed with cwd: %q", svc.compilerPath)
	}
}

// Compiler processes are bounded: when every slot stays busy a request fails
// with ErrCompilerBusy instead of starting another process.
func TestCompileBoundsConcurrentCompilerProcesses(t *testing.T) {
	base := privateHomeCompiler(t)
	svc := NewService(nil, nil, nil, &Config{CompilerPath: filepath.Join(base, "dchome", "pc.py")})
	old := compileSlotWait
	compileSlotWait = 50 * time.Millisecond
	t.Cleanup(func() { compileSlotWait = old })
	for i := 0; i < maxConcurrentCompiles; i++ {
		svc.compileSlots <- struct{}{}
	}
	if _, err := svc.Compile([]byte("x: 1"), "standard", 0); !errors.Is(err, ErrCompilerBusy) {
		t.Fatalf("compile with all slots busy: %v", err)
	}
	<-svc.compileSlots
	if _, err := svc.Compile([]byte("x: 1"), "standard", 0); errors.Is(err, ErrCompilerBusy) {
		t.Fatal("compile reported busy with a free slot")
	}
	if len(svc.compileSlots) != maxConcurrentCompiles-1 {
		t.Fatalf("compile leaked a slot: %d in use", len(svc.compileSlots))
	}
}

// A policy push waits longer than a simulate request: it must not fail with
// ErrCompilerBusy just because other compiles hold the slots for a while.
func TestPushWaitsLongerThanSimulateForCompilerSlot(t *testing.T) {
	base := privateHomeCompiler(t)
	signer, err := NewHMACSigner([]byte("test-key-for-unit-tests-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(NewMemoryPolicyStore(), signer, nil, &Config{CompilerPath: filepath.Join(base, "dchome", "pc.py")})
	old := compileSlotWait
	compileSlotWait = 50 * time.Millisecond
	t.Cleanup(func() { compileSlotWait = old })
	for i := 0; i < maxConcurrentCompiles; i++ {
		svc.compileSlots <- struct{}{}
	}
	go func() {
		time.Sleep(300 * time.Millisecond) // longer than the simulate wait
		<-svc.compileSlots
	}()
	if _, _, err := svc.CompileSignAndStore([]byte("x: 1"), "standard", 1, 2); errors.Is(err, ErrCompilerBusy) {
		t.Fatal("policy push failed with ErrCompilerBusy instead of waiting for a slot")
	}
}

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

//go:build !windows

package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestHookFireMicroVMProbeParentIsTheDoctorsProbeDir: the doctor checks that
// Docker shares openshell.HookFireProbeDir, so the builder must mount its
// MicroVM probe files from that same directory (GAP-0452).
func TestHookFireMicroVMProbeParentIsTheDoctorsProbeDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", "")
	got, err := (&Builder{}).microVMProbeParent()
	if err != nil {
		t.Fatalf("microVMProbeParent: %v", err)
	}
	if want := openshell.HookFireProbeDir(); want == "" || got != want {
		t.Fatalf("microVMProbeParent = %q, openshell.HookFireProbeDir = %q", got, want)
	}
}

// resolutionMountSources returns the host paths bound over the MicroVM
// scenario's name-resolution files.
func resolutionMountSources(args []string) []string {
	var sources []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "--mount" {
			continue
		}
		var source, target string
		for _, field := range strings.Split(args[i+1], ",") {
			key, value, _ := strings.Cut(field, "=")
			switch key {
			case "source":
				source = value
			case "target":
				target = value
			}
		}
		if target == "/etc/hosts" || target == "/etc/resolv.conf" {
			sources = append(sources, source)
		}
	}
	return sources
}

func verifyMicroVMImage(t *testing.T, b *Builder, c *Context) Record {
	t.Helper()
	if _, err := b.Build(context.Background(), c.Spec, BuildOptions{SkipHookFire: true}); err != nil {
		t.Fatal(err)
	}
	rec, _, err := b.VerifyHooks(context.Background(), c, HookFireOptions{Network: HookFireNetworkHost, SinkHost: "127.0.0.1"})
	if err != nil {
		t.Fatalf("VerifyHooks: %v", err)
	}
	return rec
}

func TestHookFireMicroVMProbeDirIsPrivateUnderCache(t *testing.T) {
	root := t.TempDir()
	home, systemTemp := filepath.Join(root, "home"), filepath.Join(root, "system-temp")
	for _, dir := range []string{home, systemTemp} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("TMPDIR", systemTemp)
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(cache, "defenseclaw", "hookfire")
	// An earlier, wider directory must be tightened before Docker sees it.
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	c := hookFireVMContext(t)
	store := testStore(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
	var sources []string
	docker := verifyDocker(t, c, sim, func(args []string) int {
		if mounted := resolutionMountSources(args); len(mounted) != 0 {
			sources = append(sources, mounted...)
			for _, dir := range []string{parent, filepath.Dir(mounted[0])} {
				info, err := os.Lstat(dir)
				if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
					t.Errorf("probe directory %q: info %v, error %v; want mode 0700 while Docker runs", dir, info, err)
				}
			}
		}
		return 0
	})
	rec := verifyMicroVMImage(t, &Builder{Docker: docker, Store: store}, c)
	if !rec.HookFireVerified || !rec.MicroVMVerified {
		t.Fatalf("record = %+v", rec)
	}
	if len(sources) != 2 {
		t.Fatalf("MicroVM mounts = %v; want two", sources)
	}
	runDir := filepath.Dir(sources[0])
	if filepath.Dir(runDir) != parent || !strings.HasPrefix(filepath.Base(runDir), "defenseclaw-hookfire-microvm-") || filepath.Dir(sources[1]) != runDir {
		t.Fatalf("MicroVM mounts = %v; want one run directory under %s", sources, parent)
	}
	for _, source := range sources {
		if strings.HasPrefix(source, systemTemp+string(filepath.Separator)) || strings.HasPrefix(source, filepath.Dir(store.Path())+string(filepath.Separator)) {
			t.Errorf("MicroVM mount %q is under system temp or the image store", source)
		}
	}
	if _, err := os.Lstat(runDir); !os.IsNotExist(err) {
		t.Errorf("MicroVM run directory %q remains after verification: %v", runDir, err)
	}
	if left, err := os.ReadDir(parent); err != nil || len(left) != 0 {
		t.Errorf("probe parent contains leftovers: %v, %v", left, err)
	}
}

func TestHookFireMicroVMTempDirOverride(t *testing.T) {
	override := t.TempDir()
	c := hookFireVMContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
	var sources []string
	docker := verifyDocker(t, c, sim, func(args []string) int {
		sources = append(sources, resolutionMountSources(args)...)
		return 0
	})
	rec := verifyMicroVMImage(t, &Builder{Docker: docker, Store: testStore(t), TempDir: override}, c)
	if !rec.MicroVMVerified || len(sources) != 2 {
		t.Fatalf("record = %+v, mounts = %v", rec, sources)
	}
	for _, source := range sources {
		if !strings.HasPrefix(source, override+string(filepath.Separator)+"defenseclaw-hookfire-microvm-") {
			t.Errorf("override %q did not supply mount %q", override, source)
		}
	}
	if left, err := os.ReadDir(override); err != nil || len(left) != 0 {
		t.Errorf("override contains leftovers: %v, %v", left, err)
	}
}

func TestHookFireMicroVMNoHomeDirectory(t *testing.T) {
	systemTemp := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("TMPDIR", systemTemp)
	c := hookFireVMContext(t)
	sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
	rec := verifyMicroVMImage(t, &Builder{Docker: verifyDocker(t, c, sim, nil), Store: testStore(t)}, c)
	if !rec.HookFireVerified || !rec.MicroVMUnchecked() || !strings.Contains(rec.MicroVMInconclusive, "home directory") {
		t.Fatalf("record without HOME = %+v", rec)
	}
	if left, err := os.ReadDir(systemTemp); err != nil || len(left) != 0 {
		t.Errorf("system temp contains probe files: %v, %v", left, err)
	}
}

func TestHookFireMicroVMProbeParentRejectsSymlinkOrFile(t *testing.T) {
	for _, kind := range []string{"symlink", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			t.Setenv("HOME", home)
			t.Setenv("XDG_CACHE_HOME", "")
			cache, err := os.UserCacheDir()
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(cache, "defenseclaw", "hookfire")
			if err := os.MkdirAll(filepath.Dir(parent), 0o700); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.Symlink(root, parent); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
			b := &Builder{}
			mounts, cleanup, err := b.microVMMounts(hookFireNet{mode: HookFireNetworkHost, bindHost: "127.0.0.1"}, "")
			if cleanup != nil {
				cleanup()
			}
			want := kind
			if kind == "file" {
				want = "not a directory"
			}
			if err == nil || len(mounts) != 0 || !strings.Contains(err.Error(), parent) || !strings.Contains(err.Error(), want) {
				t.Fatalf("microVMMounts with %s parent = %v, %v; want a path-specific refusal", kind, mounts, err)
			}
		})
	}
}

type mountRefusalDocker struct {
	Docker
	stderr   string
	probeDir string
}

func (d *mountRefusalDocker) Run(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if len(args) > 0 && args[0] == "run" {
		if mounts := resolutionMountSources(args); len(mounts) == 2 {
			d.probeDir = filepath.Dir(mounts[0])
			_, _ = io.WriteString(stderr, d.stderr)
			return &CommandError{Args: args, ExitCode: 125}
		}
	}
	return d.Docker.Run(ctx, stdin, stdout, stderr, args...)
}

func TestHookFireMicroVMMountRefusalPrerequisite(t *testing.T) {
	for _, tc := range []struct {
		name, stderr string
		mount        bool
	}{
		{"Docker Desktop", "docker: Error response from daemon: Mounts denied: The path /var/folders/x is not shared from the host and is not known to Docker.", true},
		{"Colima", "docker: Error response from daemon: invalid mount config for type \"bind\": bind source path does not exist: /var/folders/x", true},
		{"other failure", "unrelated Docker failure", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := hookFireVMContext(t)
			sim := &containerSim{t: t, events: fullClaudeRun, port: c.Spec.IngressPort, llm: true}
			docker := &mountRefusalDocker{Docker: verifyDocker(t, c, sim, nil), stderr: tc.stderr}
			rec := verifyMicroVMImage(t, &Builder{Docker: docker, Store: testStore(t), TempDir: t.TempDir()}, c)
			wantPrefix := "the hook-fire probe could not run Claude Code with an OpenShell MicroVM's name resolution: "
			if !rec.HookFireVerified || !rec.MicroVMUnchecked() || !strings.HasPrefix(rec.MicroVMInconclusive, wantPrefix) || docker.probeDir == "" {
				t.Fatalf("record = %+v, probe directory = %q", rec, docker.probeDir)
			}
			message := rec.MicroVMInconclusive
			if tc.mount {
				for _, want := range []string{docker.probeDir, "File sharing", "Colima", "OrbStack", "defenseclaw sandbox image build"} {
					if !strings.Contains(message, want) {
						t.Errorf("mount refusal %q does not contain %q", message, want)
					}
				}
				for _, banned := range []string{"enforce", "guardrail", "unprotected", "bypass"} {
					if strings.Contains(strings.ToLower(message), banned) {
						t.Errorf("mount refusal %q contains %q", message, banned)
					}
				}
			} else {
				want := wantPrefix + fmt.Sprintf("openshell image: hook-fire microvm run: docker run exited 125: %s", tc.stderr)
				if message != want {
					t.Errorf("other Docker failure = %q, want %q", message, want)
				}
			}
		})
	}
}

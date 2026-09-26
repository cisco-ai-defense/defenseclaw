// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitsafe

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

func TestCommandScrubsEnvironmentAndPrependsFlags(t *testing.T) {
	t.Setenv("GIT_DIR", "/attacker")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=evil'")
	t.Setenv("XDG_CONFIG_HOME", "/attacker/xdg")
	cmd, err := Command(context.Background(), t.TempDir(), "status")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := envValue(cmd.Env, "GIT_DIR"); ok {
		t.Fatal("GIT_DIR leaked into the child")
	}
	if _, ok := envValue(cmd.Env, "GIT_CONFIG_PARAMETERS"); ok {
		t.Fatal("GIT_CONFIG_PARAMETERS leaked into the child")
	}
	for key, want := range map[string]string{"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"} {
		if got, _ := envValue(cmd.Env, key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	home, _ := envValue(cmd.Env, "HOME")
	if xdg, _ := envValue(cmd.Env, "XDG_CONFIG_HOME"); xdg != home || home == "" {
		t.Fatalf("HOME=%q XDG_CONFIG_HOME=%q, want the same private temp dir", home, xdg)
	}
	args := strings.Join(cmd.Args, " ")
	for _, flag := range []string{"core.fsmonitor=false", "core.hooksPath=/dev/null", "--no-optional-locks"} {
		if !strings.Contains(args, flag) {
			t.Fatalf("args %q missing %s", args, flag)
		}
	}
	if cmd.Args[len(cmd.Args)-1] != "status" {
		t.Fatalf("subcommand not last: %v", cmd.Args)
	}
}

func TestCommandRejectsEmptyInput(t *testing.T) {
	if _, err := Command(context.Background(), "", "status"); err == nil {
		t.Fatal("empty dir accepted")
	}
	if _, err := Command(context.Background(), t.TempDir()); err == nil {
		t.Fatal("empty args accepted")
	}
}

func TestSafeHomeDirIsSharedAcrossConcurrentCallers(t *testing.T) {
	var wg sync.WaitGroup
	homes := make([]string, 16)
	for i := range homes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, err := safeHomeDir()
			if err != nil {
				t.Error(err)
			}
			homes[i] = h
		}(i)
	}
	wg.Wait()
	for _, h := range homes {
		if h == "" || h != homes[0] {
			t.Fatalf("homes differ: %v", homes)
		}
	}
}

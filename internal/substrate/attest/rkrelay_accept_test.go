// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Acceptance tests of the RKRELAY review of 61da1c1a18 (GAP-0355). The deny
// list let these through; the allowlist refuses every one.

// Variables that make every bash, git, perl, ... process load code, with
// any value; and an image Env entry without "=" (a variable set to "").
func TestRKEnvCandidatesAreRefused(t *testing.T) {
	for _, k := range []string{"SHELLOPTS", "PS4", "PERLLIB", "XDG_CONFIG_HOME", "GIT_DIR", "OPENSSL_CONF", "OPENSSL_MODULES",
		"GCONV_PATH", "LUA_INIT", "LUA_PATH", "LUA_CPATH", "TCLLIBPATH", "CLASSPATH", "CORECLR_PROFILER_PATH",
		"CORECLR_ENABLE_PROFILING", "DOTNET_ADDITIONAL_DEPS", "PYTHONWARNINGS", "npm_config_script_shell",
		"NPM_CONFIG_NODE_OPTIONS", "GOFLAGS", "RUSTC_WRAPPER", "LESSOPEN", "GIT_PAGER", "GIT_SEQUENCE_EDITOR",
		"BASHOPTS", "PS1", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "GEM_PATH", "RUBYSHELL", "PERL5SHELL",
		"GIT_CONFIG_NOSYSTEM", "LD_PRELOAD", "ld_preload", "GIT_CONFIG_KEY_0", "BASH_FUNC_x%%", "ENV", "BASH_ENV"} {
		if bad := CheckEnv(map[string]string{k: "/tmp/x"}); len(bad) != 1 {
			t.Errorf("%s=/tmp/x is permitted", k)
		}
	}
	cfg := map[string]string{}
	for _, kv := range []string{"LD_PRELOAD", "PATH=/bin", "PATH=/x"} {
		k, v, _ := strings.Cut(kv, "=")
		cfg[k] = v
	}
	if got := EnvRefusalNames(CheckEnv(cfg)); len(got) != 1 || got[0] != "LD_PRELOAD" {
		t.Fatalf("an entry without '=': %v", got)
	}
}

// The variables the review ran code through on the box are refused (the
// probe runs only the tools that are installed).
func TestRKEnvThatRanCodeIsRefused(t *testing.T) {
	d := t.TempDir()
	run := func(name string, env []string, dir string, argv ...string) {
		t.Helper()
		if _, err := exec.LookPath(argv[0]); err != nil {
			t.Logf("%s: %s not installed, skipped", name, argv[0])
			return
		}
		marker := filepath.Join(d, name+".ran")
		for i := range env {
			env[i] = strings.ReplaceAll(env[i], "@M@", marker)
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + d}, env...)
		cmd.Dir = dir
		_, _ = cmd.CombinedOutput()
		_, err := os.Stat(marker)
		k, v, _ := strings.Cut(env[0], "=")
		refused := len(CheckEnv(map[string]string{k: v})) == 1
		t.Logf("%-16s code ran=%v refused=%v", name, err == nil, refused)
		if err == nil && !refused {
			t.Errorf("%s ran code and the allowlist permits %s", name, k)
		}
	}
	run("SHELLOPTS", []string{"SHELLOPTS=xtrace", "PS4=$(touch @M@)"}, d, "bash", "-c", "true")
	repo := filepath.Join(d, "repo")
	_ = exec.Command("git", "init", "-q", repo).Run()
	xdg := filepath.Join(d, "xdg")
	_ = os.MkdirAll(filepath.Join(xdg, "git"), 0o755)
	hook := filepath.Join(d, "fsm.sh")
	_ = os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+filepath.Join(d, "XDG_CONFIG_HOME.ran")+"\n"), 0o755)
	_ = os.WriteFile(filepath.Join(xdg, "git", "config"), []byte("[core]\n\tfsmonitor = "+hook+"\n"), 0o644)
	run("XDG_CONFIG_HOME", []string{"XDG_CONFIG_HOME=" + xdg}, repo, "git", "status", "--porcelain")
	evil := filepath.Join(d, "evil.git")
	_ = exec.Command("git", "init", "-q", "--bare", evil).Run()
	hook2 := filepath.Join(d, "fsm2.sh")
	_ = os.WriteFile(hook2, []byte("#!/bin/sh\ntouch "+filepath.Join(d, "GIT_DIR.ran")+"\n"), 0o755)
	if f, err := os.OpenFile(filepath.Join(evil, "config"), os.O_APPEND|os.O_WRONLY, 0); err == nil {
		_, _ = f.WriteString("[core]\n\tbare = false\n\tfsmonitor = " + hook2 + "\n")
		_ = f.Close()
	}
	run("GIT_DIR", []string{"GIT_DIR=" + evil, "GIT_WORK_TREE=" + repo}, repo, "git", "status", "--porcelain")
	pl := filepath.Join(d, "pl")
	_ = os.MkdirAll(pl, 0o755)
	_ = os.WriteFile(filepath.Join(pl, "strict.pm"), []byte("package strict; open(my $f,'>','"+filepath.Join(d, "PERLLIB.ran")+"'); sub import{} 1;\n"), 0o644)
	run("PERLLIB", []string{"PERLLIB=" + pl}, d, "perl", "-e", "use strict; 1")
}

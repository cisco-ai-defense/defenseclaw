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

// Package gitsafe runs git in scrubbed-environment, hostile-repo
// mode: no system or global config, no repository-local fsmonitor /
// hooks / external diff helpers, no optional locks, no replace-refs.
//
// # Background
//
// Codex / connector hook scanning runs `git diff`, `git ls-files`,
// and `git rev-parse` inside attacker-supplied working trees. Stock
// git honors a number of executable settings from .git/config (e.g.
// core.fsmonitor, core.hooksPath, core.useReplaceRefs) and from
// optional helper hooks. A malicious repository can therefore use
// those settings to invoke an attacker-controlled binary the moment
// any git command runs in cmd.Dir.
//
// This package centralizes the safe invocation: a single Command
// constructor that applies every relevant mitigation in one place
// so callers cannot accidentally drop one when they add a new
// command.
package gitsafe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// safeGitFlags are prepended to every command-line. They disable
// every executable-from-config code path that git supports.
// These are all valid as MAIN git options (positioned before the
// subcommand); subcommand-specific options like `--no-ext-diff`
// are emulated via `-c diff.external=` instead so the same flag
// list works for ls-files, rev-parse, diff, log, etc.
//
//	-c protocol.version=2              stable wire format, avoids legacy v1 helpers
//	-c core.fsmonitor=false            no helper invoked on index/working-tree IO
//	-c core.hooksPath=/dev/null        repository hooks are bypassed
//	-c core.useReplaceRefs=false       `replace` refs cannot redirect history reads
//	-c core.alternateRefsCommand=      no command runs when resolving refs from alternates
//	-c protocol.file.allow=user        file:// submodules require explicit opt-in
//	-c diff.external=                  empty external diff helper (overrides config)
//	-c core.editor=true                harmless editor (overrides hostile config)
//	-c core.pager=cat                  non-interactive pager
//	-c uploadpack.packObjectsHook=     empty pack-objects hook (overrides config)
//	-c remote.ext.uploadpack=          no uploadpack command for ext:: remotes
//	--no-optional-locks                avoids triggering helper-touching paths
//
// The command-name is appended after this slice.
var safeGitFlags = []string{
	"-c", "protocol.version=2",
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.useReplaceRefs=false",
	"-c", "core.alternateRefsCommand=",
	"-c", "protocol.file.allow=user",
	"-c", "diff.external=",
	"-c", "core.editor=true",
	"-c", "core.pager=cat",
	"-c", "uploadpack.packObjectsHook=",
	"-c", "remote.ext.uploadpack=",
	"--no-optional-locks",
}

// safeEnvKeyPrefixes is the deny-list of inherited env keys we strip
// from the child. Any GIT_*, XDG_*, or HOME-equivalent variable is
// dropped because git follows several of them to load executable
// config.
var safeEnvKeyPrefixes = []string{
	"GIT_",
	"XDG_",
}

// safeEnvKeysExact is the deny-list of inherited env keys we strip
// by exact match. HOME is the most consequential because git follows
// $HOME/.gitconfig, ~/.config/git/config, ~/.ssh/config, etc.
var safeEnvKeysExact = map[string]struct{}{
	"HOME":                {},
	"USERPROFILE":         {},
	"GIT_TERMINAL_PROMPT": {},
}

// Command builds an exec.Cmd that runs git with the safeGitFlags
// applied, the working directory set to dir, and a scrubbed
// environment that:
//
//   - clears every key in safeEnvKeyPrefixes / safeEnvKeysExact,
//   - sets GIT_CONFIG_NOSYSTEM=1 so /etc/gitconfig is ignored,
//   - sets GIT_CONFIG_GLOBAL=/dev/null so ~/.gitconfig cannot apply,
//   - sets GIT_CONFIG_COUNT=0 so no -c overrides are inherited,
//   - sets HOME and XDG_CONFIG_HOME to a writable empty temp dir so
//     git cannot read or write user config from the operator account,
//   - sets GIT_TERMINAL_PROMPT=0 so a credential prompt does not hang.
//
// The temp HOME is a new private directory under os.TempDir for this
// command. The returned cleanup removes it: call it (defer it) once the
// command has finished. Left to the OS, the directories piled up, one
// per process, in a TMPDIR that no housekeeping empties. cleanup is
// never nil when err is nil, and calling it more than once is harmless.
//
// Note: this still executes the local repository content via the
// commands we choose. Callers should always pair gitsafe.Command
// with a closed allow-list of git subcommands AND should not invoke
// commands that actually run in-repo executables (git submodule
// foreach, git filter-repo, etc).
func Command(ctx context.Context, dir string, args ...string) (cmd *exec.Cmd, cleanup func(), err error) {
	if len(args) == 0 {
		return nil, nil, errors.New("gitsafe: no git arguments supplied")
	}
	if dir == "" {
		return nil, nil, errors.New("gitsafe: empty working directory")
	}
	full := append([]string{}, safeGitFlags...)
	full = append(full, args...)
	home, cleanup := safeHomeDir()
	cmd = exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = scrubbedEnv(home)
	return cmd, cleanup, nil
}

// scrubbedEnv returns the env slice for the safe child, with home as
// its HOME and XDG_CONFIG_HOME.
func scrubbedEnv(tmpHome string) []string {
	out := make([]string, 0, 32)
	for _, e := range os.Environ() {
		eq := strings.IndexByte(e, '=')
		if eq <= 0 {
			continue
		}
		k := e[:eq]
		if _, drop := safeEnvKeysExact[k]; drop {
			continue
		}
		dropPrefix := false
		for _, p := range safeEnvKeyPrefixes {
			if strings.HasPrefix(k, p) {
				dropPrefix = true
				break
			}
		}
		if dropPrefix {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_COUNT=0",
		"GIT_TERMINAL_PROMPT=0",
		"HOME="+tmpHome,
		"XDG_CONFIG_HOME="+tmpHome,
	)
	return out
}

// safeHomeDir creates an empty private directory that git can use as
// $HOME without finding any operator-supplied config, and the func that
// removes it. When the directory cannot be created, git gets os.DevNull
// instead: it is not a directory, so git treats lookups against it as
// ENOTDIR and falls back to defaults without ever opening anything
// user-controlled.
func safeHomeDir() (string, func()) {
	dir, err := os.MkdirTemp("", "defenseclaw-gitsafe-home-")
	if err != nil {
		return os.DevNull, func() {}
	}
	// MkdirTemp creates it 0700 already; this only undoes an odd umask.
	_ = os.Chmod(dir, 0o700)
	dir = filepath.Clean(dir)
	var once sync.Once
	return dir, func() { once.Do(func() { _ = os.RemoveAll(dir) }) }
}

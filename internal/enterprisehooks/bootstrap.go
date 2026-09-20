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

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// defaultHookConfigStubForConnector returns the minimal-valid native
// hook config file DefenseClaw will pre-create on a target where the
// agent has never launched. Kept out of the connector package so we
// don't have to touch three connectors for what is otherwise a bag of
// literal bytes — matches the exact shape the shell installer's
// prepare_*_userspace helpers used before the multi-user rewrite (see
// packaging/macos/lib/installer_lib.sh:197-235). When a connector
// wants to own its stub bytes, it implements HookConfigBootstrap and
// the caller uses that instead.
//
// Returns a zero-value HookConfigStub (ContentPath == "") for
// connectors we don't know how to bootstrap — the installer's strict
// "must exist" precondition still applies to those.
func defaultHookConfigStubForConnector(conn connector.Connector, opts connector.SetupOpts, home string) connector.HookConfigStub {
	if bootstrap, ok := conn.(connector.HookConfigBootstrap); ok {
		return bootstrap.DefaultHookConfigStub(opts)
	}
	// Fallback map for the three connectors shipped in the pkg bundle
	// (codex, claudecode, cursor). Additional connectors either
	// implement HookConfigBootstrap or accept the strict precondition.
	name := strings.ToLower(strings.TrimSpace(conn.Name()))
	switch name {
	case "codex":
		return connector.HookConfigStub{
			ContentPath: filepath.Join(home, ".codex", "config.toml"),
			Contents: []byte("# Created by DefenseClaw installer so the enterprise hook guardian can\n" +
				"# repair this file. Edit freely; DefenseClaw only owns [hooks], [otel],\n" +
				"# and the top-level notify entries.\n"),
			Mode: 0o600,
		}
	case "claudecode":
		return connector.HookConfigStub{
			ContentPath: filepath.Join(home, ".claude", "settings.json"),
			Contents:    []byte("{}\n"),
			Mode:        0o600,
		}
	case "cursor":
		return connector.HookConfigStub{
			ContentPath: filepath.Join(home, ".cursor", "hooks.json"),
			Contents:    []byte("{\"version\":1,\"hooks\":{}}\n"),
			Mode:        0o600,
		}
	}
	return connector.HookConfigStub{}
}

// bootstrapMissingHookConfig writes the connector's default hook config
// stub if and only if the file is absent. Runs under withOwnerCredentials
// so parent dir + file both land owned by the target user (matches what
// the pre-2026.7.3 shell installer produced via prepare_userspace_for).
//
// Returns true iff a stub was written — the caller uses this to
// distinguish "we bootstrapped it just now" from "operator already
// prepped this". Never returns an error when the file already exists;
// the strict validate step downstream owns "present but broken"
// diagnostics.
//
// Preconditions:
//   - stub.ContentPath must be a subpath of home (checked here as
//     defense-in-depth against a malicious connector name; the caller
//     already validated home).
//   - Runs as the caller — the outer withOwnerCredentials at the
//     Install call site ensures euid/egid are the target user.
func bootstrapMissingHookConfig(home string, stub connector.HookConfigStub) (bool, error) {
	path := strings.TrimSpace(stub.ContentPath)
	if path == "" {
		return false, nil
	}
	// Cheap containment check — path must sit under the target's home.
	// Catches the case where a future connector accidentally returns
	// an absolute path outside the user's tree (e.g. /etc/agent.conf)
	// and the installer would otherwise chmod it 0600 as target user.
	cleanHome := filepath.Clean(home)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanHome, cleanPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
		return false, fmt.Errorf("enterprise hooks: hook config stub path %q is not inside user home %q", path, cleanHome)
	}
	// Already exists — leave it alone. Present-but-broken configs
	// (wrong owner, group-writable, symlink) surface via the strict
	// validate step immediately after us.
	if _, err := os.Lstat(cleanPath); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("enterprise hooks: inspect hook config %s before bootstrap: %w", cleanPath, err)
	}

	dir := filepath.Dir(cleanPath)
	// mkdir -p walks the ancestor chain — but we only ever create the
	// LEAF agent dir here (e.g. ~/.claude), not the whole ~/. If the
	// home itself is missing that's a validateUserHome failure the
	// caller already reported.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, fmt.Errorf("enterprise hooks: create hook config parent %s: %w", dir, err)
	}
	// Explicit chmod after MkdirAll — the process umask may have narrowed
	// the requested mode. 0700 is intentional: matches the shell installer's
	// prepare_*_userspace helpers, and is what Cursor / Codex / Claude Code
	// all use for their own dot-dirs when they create them themselves.
	if err := os.Chmod(dir, 0o700); err != nil {
		return false, fmt.Errorf("enterprise hooks: chmod hook config parent %s: %w", dir, err)
	}

	// O_CREATE|O_EXCL so a concurrent writer wins deterministically —
	// we treat "someone else created it since we Lstat'd" as
	// "already exists, leave alone". No os.WriteFile which would
	// clobber a racing agent-side write.
	mode := stub.Mode
	if mode == 0 {
		mode = 0o600
	}
	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		if os.IsExist(err) {
			// Concurrent create race — the file exists now, our downstream
			// validate step will inspect it.
			return false, nil
		}
		return false, fmt.Errorf("enterprise hooks: create hook config %s: %w", cleanPath, err)
	}
	if _, writeErr := f.Write(stub.Contents); writeErr != nil {
		_ = f.Close()
		_ = os.Remove(cleanPath)
		return false, fmt.Errorf("enterprise hooks: write hook config %s: %w", cleanPath, writeErr)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("enterprise hooks: close hook config %s: %w", cleanPath, err)
	}
	// Explicit chmod after create — same reason as the dir chmod: umask.
	if err := os.Chmod(cleanPath, mode); err != nil {
		return false, fmt.Errorf("enterprise hooks: chmod hook config %s: %w", cleanPath, err)
	}
	return true, nil
}

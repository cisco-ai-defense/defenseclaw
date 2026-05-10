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

package connector

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

// OTLPPathTokenScope identifies a connector-bound OTLP token used in
// loopback URLs of the shape /otlp/<source>/<token>/v1/<signal>. The
// token's authority is intentionally smaller than the master sidecar
// bearer:
//
//   - it is valid only on /otlp/<scope>/... paths;
//   - it is valid only over the loopback interface (enforced by
//     parseOTLPPathToken + tokenAuth in api.go);
//   - it never reaches the X-DefenseClaw-Token header path or the
//     general /api/v1/... routes.
//
// Per-source scoping means a process that can read one connector's
// OTLP token (e.g. by reading ~/.gemini/settings.json) cannot replay it
// against another connector's OTLP namespace, and cannot escalate to
// the full sidecar admin surface — both of which were possible with
// the previous design that wrote the master gateway bearer into
// settings.json.
type OTLPPathTokenScope string

const (
	// OTLPScopeGeminiCLI is the scope value for Gemini CLI's
	// settings.json telemetry path-token. Any new hook-only
	// connector that needs a path-token must add a new constant
	// here so the allow-list in OTLPPathTokenScopes() rejects
	// typos at compile time.
	OTLPScopeGeminiCLI OTLPPathTokenScope = "geminicli"
)

// OTLPPathTokenScopes returns the closed allow-list of scopes that
// EnsureOTLPPathToken will mint a token for. It exists so the API
// server can iterate the same set when it loads tokens at boot,
// guaranteeing that a new scope can never be added in one half of
// the codebase without the other.
func OTLPPathTokenScopes() []OTLPPathTokenScope {
	return []OTLPPathTokenScope{OTLPScopeGeminiCLI}
}

// otlpScopeRE prevents a future caller from sneaking a path traversal
// or a scope that collides with the master `expected` token route
// through the on-disk filename. Matches the same allow-list as
// parseOTLPPathToken's source segment.
var otlpScopeRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// otlpTokenLen is the unencoded byte length of a path-token. 32 bytes
// (64 hex chars) matches EnsureGatewayToken so the strength is at
// least equivalent to the master token; the loopback + /otlp/<scope>/
// constraints reduce the blast radius further.
const otlpTokenLen = 32

// otlpTokenMu serializes EnsureOTLPPathToken across goroutines. The
// guard is per-process; each token file is independently atomic via
// rename, so two instances of EnsureOTLPPathToken with different
// scopes never block each other.
var otlpTokenMu sync.Mutex

// otlpPathTokenFileName returns the on-disk filename for *scope* under
// the gateway data dir's hooks subtree. The hooks/ dir is already
// 0o700 (mirroring the .token file used by claude/codex hook scripts)
// so the per-source token inherits owner-only access without any
// additional chmod.
func otlpPathTokenFileName(scope OTLPPathTokenScope) string {
	return ".otlp-" + string(scope) + ".token"
}

// OTLPPathTokenFilePath returns the absolute on-disk location of the
// path-token for *scope* under *dataDir*. Exposed so the API server
// can read the same path the connector setup writes.
func OTLPPathTokenFilePath(dataDir string, scope OTLPPathTokenScope) (string, error) {
	if !validOTLPScope(scope) {
		return "", fmt.Errorf("invalid OTLP scope %q", scope)
	}
	if dataDir == "" {
		return "", fmt.Errorf("OTLPPathTokenFilePath: empty dataDir")
	}
	return filepath.Join(dataDir, "hooks", otlpPathTokenFileName(scope)), nil
}

// EnsureOTLPPathToken returns a non-empty hex-encoded token bound to
// *scope*. If a token already exists at the on-disk path, the existing
// value is returned unchanged so connector setup is idempotent across
// restarts (mirroring EnsureGatewayToken's contract). Otherwise a
// 32-byte CSPRNG token is generated, persisted with mode 0o600, and
// returned.
//
// Callers MUST treat the return value as a secret and MUST NOT log
// it; only the on-disk file is the source of truth, and that file is
// owner-only.
func EnsureOTLPPathToken(dataDir string, scope OTLPPathTokenScope) (string, error) {
	if !validOTLPScope(scope) {
		return "", fmt.Errorf("EnsureOTLPPathToken: invalid scope %q", scope)
	}
	if dataDir == "" {
		return "", fmt.Errorf("EnsureOTLPPathToken: empty dataDir; refusing to mint transient token")
	}
	otlpTokenMu.Lock()
	defer otlpTokenMu.Unlock()

	tokenPath, err := OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		return "", fmt.Errorf("create OTLP path-token dir: %w", err)
	}

	// ("Cross-process OTLP token minting can
	// desynchronize the returned token from the persisted token"):
	// the previous implementation serialized only goroutines in the
	// current process via otlpTokenMu and then wrote through a
	// fixed shared temp path of the form `<tokenPath>.tmp`. Two
	// setup or sidecar processes minting the same scoped token
	// concurrently could clobber each other's `.tmp` file, race
	// the rename, and return token A while the file ended up
	// containing token B (rejecting later loopback OTLP requests).
	//
	// We now (1) take a cross-process file lock against
	// `<tokenPath>.lock`, (2) re-check the existing token under
	// the lock, (3) use os.CreateTemp inside the token directory
	// so each minting process owns its own unique temp file,
	// (4) fsync before rename for durability, and (5) re-read the
	// final file after rename so the returned value matches the
	// post-rename on-disk contents even if a racing process had
	// already minted a different token.
	lockPath := tokenPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return "", fmt.Errorf("open OTLP path-token lock: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("acquire OTLP path-token lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	if existing, err := readTrimmedFile(tokenPath); err == nil && existing != "" {
		return existing, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read OTLP path-token %s: %w", tokenPath, err)
	}

	buf := make([]byte, otlpTokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("EnsureOTLPPathToken: csprng read: %w", err)
	}
	tok := hex.EncodeToString(buf)

	tmpFile, err := os.CreateTemp(filepath.Dir(tokenPath), filepath.Base(tokenPath)+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("create OTLP path-token temp: %w", err)
	}
	tmpName := tmpFile.Name()
	cleanupTmp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		cleanupTmp()
		return "", fmt.Errorf("chmod OTLP path-token: %w", err)
	}
	if _, err := tmpFile.Write([]byte(tok + "\n")); err != nil {
		cleanupTmp()
		return "", fmt.Errorf("write OTLP path-token: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanupTmp()
		return "", fmt.Errorf("fsync OTLP path-token: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close OTLP path-token temp: %w", err)
	}
	if err := os.Rename(tmpName, tokenPath); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("rename OTLP path-token: %w", err)
	}
	final, err := readTrimmedFile(tokenPath)
	if err != nil || final == "" {
		return "", fmt.Errorf("verify OTLP path-token post-rename: %w", err)
	}
	return final, nil
}

// LoadOTLPPathToken reads the token for *scope* from disk if present.
// Returns "" with no error when the file does not exist so the caller
// can treat "not yet provisioned" as a non-fatal condition (the route
// will fail authentication at request time).
func LoadOTLPPathToken(dataDir string, scope OTLPPathTokenScope) (string, error) {
	if !validOTLPScope(scope) {
		return "", fmt.Errorf("LoadOTLPPathToken: invalid scope %q", scope)
	}
	tokenPath, err := OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return "", err
	}
	tok, err := readTrimmedFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return tok, nil
}

// LoadAllOTLPPathTokens loads every known scope into a single map.
// Used by the API server at boot to populate its in-memory table so
// per-request auth checks do not have to touch disk. Empty scopes
// (no token file yet) are omitted; callers can re-load lazily after
// a connector setup mints a new token.
func LoadAllOTLPPathTokens(dataDir string) (map[OTLPPathTokenScope]string, error) {
	out := map[OTLPPathTokenScope]string{}
	for _, scope := range OTLPPathTokenScopes() {
		tok, err := LoadOTLPPathToken(dataDir, scope)
		if err != nil {
			return nil, err
		}
		if tok != "" {
			out[scope] = tok
		}
	}
	return out, nil
}

func validOTLPScope(scope OTLPPathTokenScope) bool {
	if !otlpScopeRE.MatchString(string(scope)) {
		return false
	}
	for _, s := range OTLPPathTokenScopes() {
		if s == scope {
			return true
		}
	}
	return false
}

func readTrimmedFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

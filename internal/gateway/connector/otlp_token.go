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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	// OTLPScopeCodex is the scope value for Codex's config.toml native
	// exporter. Codex can set arbitrary headers, but its hook credential is
	// deliberately scoped to /api/v1/codex/hook and must not be accepted on
	// the shared /v1/* OTLP receiver. A path token gives the exporter its own
	// least-privilege credential without placing the gateway master token in
	// agent-readable configuration.
	OTLPScopeCodex OTLPPathTokenScope = "codex"

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
	return []OTLPPathTokenScope{OTLPScopeCodex, OTLPScopeGeminiCLI}
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

const otlpPathTokenMaxReadBytes = 4096

var otlpTokenHexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// otlpTokenMu serializes EnsureOTLPPathToken across goroutines. The
// guard is per-process; each token file is independently atomic via
// rename, so two instances of EnsureOTLPPathToken with different
// scopes never block each other.
var otlpTokenMu sync.Mutex

func validateOwnedLockFile(path string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("DefenseClaw lock %s is not a regular file", path)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) {
		return fmt.Errorf("DefenseClaw lock %s changed identity during secure open", path)
	}
	if err := otlpValidateOwner(path, info); err != nil {
		return err
	}
	return otlpValidatePerm(path, info)
}

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
	if err := otlpValidateTokenDirectory(dataDir, filepath.Dir(tokenPath)); err != nil {
		return "", fmt.Errorf("validate OTLP path-token dir: %w", err)
	}

	var token string
	err = withOTLPPathTokenLock(tokenPath, func() error {
		if existing, readErr := readSecureOTLPPathTokenFile(dataDir, tokenPath); readErr == nil && existing != "" {
			token = existing
			return nil
		} else if readErr != nil && !os.IsNotExist(readErr) {
			replace, replaceErr := otlpPathTokenNeedsSecureReplacement(tokenPath)
			if replaceErr != nil {
				return fmt.Errorf("read OTLP path-token %s: %w", tokenPath, readErr)
			}
			if !replace {
				return fmt.Errorf("read OTLP path-token %s: %w", tokenPath, readErr)
			}
		}

		buf := make([]byte, otlpTokenLen)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("EnsureOTLPPathToken: csprng read: %w", err)
		}
		token = hex.EncodeToString(buf)

		// A unique temp file avoids stale-name collisions after crashes. The
		// advisory lock serializes independent DefenseClaw processes, and the
		// same-directory rename publishes only a fully-written credential.
		tmp, tmpPath, err := createSecureOTLPPathTokenTempFile(tokenPath)
		if err != nil {
			return fmt.Errorf("create OTLP path-token temp file: %w", err)
		}
		defer os.Remove(tmpPath)
		if _, err := tmp.WriteString(token + "\n"); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write OTLP path-token: %w", err)
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("sync OTLP path-token: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close OTLP path-token: %w", err)
		}
		if err := os.Rename(tmpPath, tokenPath); err != nil {
			return fmt.Errorf("publish OTLP path-token: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
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
	tok, err := readSecureOTLPPathTokenFile(dataDir, tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return tok, nil
}

// RemoveOTLPPathToken revokes the connector-scoped OTLP credential without
// reading or logging its value. Callers must first remove every managed agent
// configuration reference to the token; otherwise a failed teardown would
// strand the agent on an endpoint that can never authenticate.
func RemoveOTLPPathToken(dataDir string, scope OTLPPathTokenScope) error {
	otlpTokenMu.Lock()
	defer otlpTokenMu.Unlock()

	path, err := OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return err
	}
	if err := validateOTLPPathTokenLocation(dataDir, path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return withOTLPPathTokenLock(path, func() error {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("OTLP path-token %s is a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("OTLP path-token %s is not a regular file", path)
		}
		if err := otlpValidateRemovalOwner(path, info); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
		if err != nil {
			return err
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return statErr
		}
		currentInfo, pathErr := os.Lstat(path)
		if pathErr != nil || !openedInfo.Mode().IsRegular() ||
			currentInfo.Mode()&os.ModeSymlink != 0 || !currentInfo.Mode().IsRegular() ||
			!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
			_ = file.Close()
			return fmt.Errorf("OTLP path-token %s changed identity during secure removal", path)
		}
		if err := otlpValidateRemovalOwner(path, openedInfo); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
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

// IsValidOTLPScope reports whether scope is in the closed allow-list of
// known per-source OTLP scopes. Exposed so the gateway's lazy reload path
// (api.go lookupOTLPPathToken) can decline disk I/O for arbitrary path
// segments — the OTLP receiver receives the source segment straight from
// the URL, so we MUST refuse to touch disk for typos, fuzzing probes, or
// random scope strings.
func IsValidOTLPScope(scope OTLPPathTokenScope) bool {
	return validOTLPScope(scope)
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

func readSecureOTLPPathTokenFile(dataDir, path string) (string, error) {
	if err := validateOTLPPathTokenLocation(dataDir, path); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("OTLP path-token %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("OTLP path-token %s is not a regular file", path)
	}
	if err := otlpValidateOwner(path, info); err != nil {
		return "", err
	}
	if err := otlpValidatePerm(path, info); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", fmt.Errorf("OTLP path-token %s changed identity during secure open", path)
	}
	if err := otlpValidateOwner(path, openedInfo); err != nil {
		return "", err
	}
	if err := otlpValidatePerm(path, openedInfo); err != nil {
		return "", err
	}
	limited := io.LimitReader(f, otlpPathTokenMaxReadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if len(data) > otlpPathTokenMaxReadBytes {
		return "", fmt.Errorf("OTLP path-token %s exceeds %d bytes", path, otlpPathTokenMaxReadBytes)
	}
	tok := strings.TrimSpace(string(data))
	if !otlpTokenHexRE.MatchString(tok) {
		return "", fmt.Errorf("OTLP path-token %s is not a 64-character lowercase hex token", path)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !currentInfo.Mode().IsRegular() || !os.SameFile(openedInfo, currentInfo) {
		return "", fmt.Errorf("OTLP path-token %s changed identity during secure read", path)
	}
	if err := otlpValidateOwner(path, currentInfo); err != nil {
		return "", err
	}
	if err := otlpValidatePerm(path, currentInfo); err != nil {
		return "", err
	}
	return tok, nil
}

func validateOTLPPathTokenLocation(dataDir, path string) error {
	if dataDir == "" {
		return fmt.Errorf("OTLP path-token location: empty dataDir")
	}
	hooksDir := filepath.Join(dataDir, "hooks")
	cleanHooks := filepath.Clean(hooksDir)
	cleanPath := filepath.Clean(path)
	rel, err := filepath.Rel(cleanHooks, cleanPath)
	if err != nil {
		return err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("OTLP path-token %s escapes hooks dir %s", path, hooksDir)
	}
	evalDataDir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	evalTokenDir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	evalHooksDir := filepath.Join(evalDataDir, "hooks")
	rel, err = filepath.Rel(evalHooksDir, evalTokenDir)
	if err != nil {
		return err
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)) {
		return otlpValidateTokenDirectory(dataDir, filepath.Dir(path))
	}
	return fmt.Errorf("OTLP path-token dir %s escapes hooks dir %s", filepath.Dir(path), hooksDir)
}

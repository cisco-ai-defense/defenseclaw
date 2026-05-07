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

package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// firstBootMu serializes EnsureGatewayToken so two goroutines (e.g. proxy
// and API server) calling it concurrently can't race on the .env file.
var firstBootMu sync.Mutex

// EnsureGatewayToken returns a non-empty DEFENSECLAW_GATEWAY_TOKEN. If
// the env var or dotenv file already supplies one, the existing value
// is returned unchanged. Otherwise a 32-byte CSPRNG hex token is
// generated, persisted to dotenvPath with mode 0o600, and returned.
//
// Plan B2 / S0.2: this closes the empty-token loopback-trust path.
// Before this helper, sidecar boot logged a WARNING and silently
// trusted every loopback caller; downstream (zeptoclaw / codex /
// claudecode) followed the same fail-open pattern. Now the token is
// synthesized at boot, persisted in ~/.defenseclaw/.env, and every
// connector enforces it.
//
// The helper is idempotent: a second call (or a sidecar restart) reads
// the same value back. Callers MUST NOT mutate the returned string;
// use SetCredentials on the connector to inject it into the auth path.
func EnsureGatewayToken(dotenvPath string) (string, error) {
	firstBootMu.Lock()
	defer firstBootMu.Unlock()

	if t := strings.TrimSpace(ResolveAPIKey("DEFENSECLAW_GATEWAY_TOKEN", dotenvPath)); t != "" {
		return t, nil
	}
	// Compatibility shim: old installs may have the legacy var name.
	if t := strings.TrimSpace(ResolveAPIKey("OPENCLAW_GATEWAY_TOKEN", dotenvPath)); t != "" {
		return t, nil
	}

	if dotenvPath == "" {
		return "", fmt.Errorf("ensureGatewayToken: empty dotenvPath; refusing to generate transient token")
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("ensureGatewayToken: csprng read: %w", err)
	}
	tok := hex.EncodeToString(buf)

	if err := appendEnvLine(dotenvPath, "DEFENSECLAW_GATEWAY_TOKEN", tok); err != nil {
		return "", fmt.Errorf("ensureGatewayToken: persist %s: %w", dotenvPath, err)
	}

	fmt.Fprintf(os.Stderr, "[guardrail] generated first-boot DEFENSECLAW_GATEWAY_TOKEN at %s (mode 0600)\n", dotenvPath)
	return tok, nil
}

// appendEnvLine appends `KEY=VALUE` to the dotenv file at path,
// creating the file (mode 0o600) and any missing parent dirs as
// needed. If the file already contains a line beginning with `KEY=`,
// the new value REPLACES it — preserves operator-supplied entries
// for unrelated keys, but never duplicates the same key.
//
// The write is atomic: a temporary file is renamed over the target so
// a crash mid-write cannot leave a half-written .env behind.
func appendEnvLine(path, key, value string) error {
	if strings.ContainsAny(key, "=\n\r") {
		return fmt.Errorf("appendEnvLine: invalid key %q", key)
	}
	if strings.ContainsAny(value, "\n\r") {
		return fmt.Errorf("appendEnvLine: value contains newline")
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	var lines []string
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				lines = append(lines, line)
				continue
			}
			if strings.HasPrefix(trimmed, key+"=") {
				continue // drop existing — we'll append the new value
			}
			lines = append(lines, line)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, fmt.Sprintf("%s=%s", key, value), "")

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

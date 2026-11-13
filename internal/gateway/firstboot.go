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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// firstBootMu serializes EnsureGatewayToken so two goroutines (e.g. proxy
// and API server) calling it concurrently can't race on the .env file.
var firstBootMu sync.Mutex

// EnsureGatewayToken returns a non-empty DEFENSECLAW_GATEWAY_TOKEN. If
// the env var or dotenv file already supplies one, the existing value
// is returned unchanged. Otherwise a 32-byte CSPRNG hex token is
// generated, persisted to dotenvPath with mode 0o600, and returned.
//
// The DefenseClaw gateway token is never the OpenClaw gateway token
// (R-TOK). OPENCLAW_GATEWAY_TOKEN, from the environment or the dotenv
// file, is only the OpenClaw WebSocket credential and is never returned.
// A DEFENSECLAW_GATEWAY_TOKEN equal to it, or to any value in notMaster
// (the caller passes the openclaw.json gateway.auth.token), is not usable
// either: a 1.0.9 auth repair copied the OpenClaw token under both names.
// Then a new token is minted and replaces that line. A 1.0.8 or 1.0.9
// install whose .env holds only OPENCLAW_GATEWAY_TOKEN gets its own token
// on the first boot of 1.0.10 the same way.
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
func EnsureGatewayToken(dotenvPath string, notMaster ...string) (string, error) {
	firstBootMu.Lock()
	defer firstBootMu.Unlock()

	var dotenv map[string]string
	if dotenvPath != "" {
		if values, err := loadDotEnv(dotenvPath); err == nil {
			dotenv = values
		}
	}
	openClaw := map[string]bool{}
	for _, t := range append([]string{os.Getenv(config.OpenClawGatewayTokenEnv), dotenv[config.OpenClawGatewayTokenEnv]}, notMaster...) {
		if t = strings.TrimSpace(t); t != "" {
			openClaw[t] = true
		}
	}
	// SecretRef text an earlier build saved as a token is never one (#1404).
	replaced := false
	usable := func(t string) bool {
		if t == "" || envvars.IsSecretRefText(t) {
			return false
		}
		if openClaw[t] {
			replaced = true
			return false
		}
		return true
	}

	// Check the process environment directly (not via ResolveAPIKey which
	// is gated by localKeyResolutionDisabled). In enterprise/sidecar mode
	// the gateway token is injected via ConfigMap envFrom and must be
	// respected even when local key resolution is disabled for LLM keys.
	if t := strings.TrimSpace(os.Getenv("DEFENSECLAW_GATEWAY_TOKEN")); usable(t) {
		return t, nil
	}
	// Fall back to the dotenv file (covers standalone CLI installs where
	// the token lives in ~/.defenseclaw/.env).
	if t := strings.TrimSpace(dotenv["DEFENSECLAW_GATEWAY_TOKEN"]); usable(t) {
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

	switch {
	case replaced:
		fmt.Fprintf(os.Stderr, "[guardrail] DEFENSECLAW_GATEWAY_TOKEN held the OpenClaw gateway token; "+
			"generated a separate DEFENSECLAW_GATEWAY_TOKEN at %s (mode 0600). OPENCLAW_GATEWAY_TOKEN stays the OpenClaw credential\n", dotenvPath)
	case len(openClaw) > 0:
		fmt.Fprintf(os.Stderr, "[guardrail] generated first-boot DEFENSECLAW_GATEWAY_TOKEN at %s (mode 0600); "+
			"OPENCLAW_GATEWAY_TOKEN is only the OpenClaw credential\n", dotenvPath)
	default:
		fmt.Fprintf(os.Stderr, "[guardrail] generated first-boot DEFENSECLAW_GATEWAY_TOKEN at %s (mode 0600)\n", dotenvPath)
	}
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

	var lines []string
	var existing []byte
	if data, err := os.ReadFile(path); err == nil {
		existing = data
		for _, line := range envvars.DotEnvLines(data) {
			if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
				continue // drop existing; the new value is appended
			}
			lines = append(lines, line)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	out := envvars.SerializeDotEnv(existing, lines)
	if err := checkDotEnvSize(path, len(out)); err != nil {
		return fmt.Errorf("appendEnvLine: %w", err)
	}

	// Cold-start dependency: in managed_enterprise mode the write
	// below goes through managed.WriteServiceRuntimeFile which requires
	// the parent directory to already carry the Administrators-owned +
	// service-writer-ACE trust contract. Deferred config introduced
	// a boot ordering that can invoke appendEnvLine before
	// the installer's trust-setup step has applied those ACLs; when
	// that happens the caller sees a wrapped "not trusted" error and
	// firstboot fails. The proper cross-cutting fix is to gate this
	// helper on the installer trust-setup completion signal — deferred
	// as follow-up scope. The wrapped error text already points
	// operators at the missing ACL, so the boot failure is diagnosable.
	if err := managed.WriteServiceRuntimeFile(
		managed.PinnedDeploymentMode(),
		path,
		"gateway dotenv",
		out,
	); err != nil {
		return fmt.Errorf(
			"appendEnvLine: %w (cold-start note: on managed_enterprise the "+
				"parent %s must carry the installer's Administrators-owned + "+
				"service-writer-ACE trust ACLs before firstboot writes the token)",
			err, filepath.Dir(path),
		)
	}
	return nil
}

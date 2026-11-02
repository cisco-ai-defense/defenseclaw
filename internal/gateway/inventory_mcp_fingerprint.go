// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	maxMCPFingerprintParts = 128
	maxMCPFingerprintBytes = 64 * 1024
)

// mcpInventoryFingerprintKey keeps argument and command fingerprints separate
// from the gateway token and from the AI-discovery path-hash key. An absent
// token yields no fingerprint; raw configuration is never a fallback.
func mcpInventoryFingerprintKey(cfg *config.Config) []byte {
	if cfg == nil {
		return nil
	}
	token := cfg.Gateway.ResolvedToken()
	if token == "" {
		return nil
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("mcp-inventory/fingerprint-key/v1"))
	return mac.Sum(nil)
}

// mcpInventoryFingerprint signs a length-prefixed, ordered sequence. The
// domain distinguishes a command from its arguments and avoids ambiguous
// concatenations. Limits bound work on malformed in-memory configurations.
func mcpInventoryFingerprint(key []byte, domain string, values []string) string {
	if len(key) != sha256.Size || len(values) > maxMCPFingerprintParts {
		return ""
	}
	if domain != "command" && domain != "arguments" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("mcp-inventory/" + domain + "/v1\x00"))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(values)))
	_, _ = mac.Write(size[:])
	total := 0
	for _, value := range values {
		total += len(value)
		if total > maxMCPFingerprintBytes {
			return ""
		}
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(value))
	}
	return fmt.Sprintf("hmac-sha256:%x", mac.Sum(nil))
}

func mcpInventoryLocalFingerprints(key []byte, server config.MCPServerEntry) (string, string) {
	if server.Command == "" {
		return "", ""
	}
	return mcpInventoryFingerprint(key, "command", []string{server.Command}),
		mcpInventoryFingerprint(key, "arguments", server.Args)
}

// mcpInventoryLocalIdentity identifies a configured local server by its full
// command and ordered arguments. The HMAC values keep command paths and
// argument values out of the component ID, including low-entropy secrets.
// The caller adds connector and user scope for endpoint component identity.
func mcpInventoryLocalIdentity(commandFingerprint, argumentsFingerprint string) string {
	if commandFingerprint == "" || argumentsFingerprint == "" {
		return ""
	}
	return "local\x00" + commandFingerprint + "\x00" + argumentsFingerprint
}

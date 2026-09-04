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

package actionfacts

import (
	"strings"
	"unicode"
)

// CurlCapability is trusted caller context describing one resolved curl
// executable. ActionFacts never discovers it from GOOS, dialect, basename,
// PATH, or process state. The caller must authenticate identity and
// invalidate stale generations before supplying this value.
type CurlCapability struct {
	Executable string
	Digest     string
	Version    string
	Protocols  []string
	Features   []string
	Connector  string
	SessionID  string
	Generation int64
}

func authenticatedCurlCapabilities(candidates []CurlCapability) []CurlCapability {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]CurlCapability, 0, len(candidates))
	for _, candidate := range candidates {
		if !curlCapabilityIdentityValid(candidate) {
			continue
		}
		out = append(out, CurlCapability{
			Executable: candidate.Executable,
			Digest:     strings.ToLower(candidate.Digest),
			Version:    candidate.Version,
			Protocols:  cloneNormalizedCapabilityTokens(candidate.Protocols),
			Features:   cloneNormalizedCapabilityTokens(candidate.Features),
			Connector:  candidate.Connector,
			SessionID:  candidate.SessionID,
			Generation: candidate.Generation,
		})
	}
	return out
}

func curlCapabilityIdentityValid(capability CurlCapability) bool {
	if capability.Executable == "" || capability.Version == "" ||
		!curlCapabilityDigestValid(capability.Digest) {
		return false
	}
	return true
}

func curlCapabilityDigestValid(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, char := range digest {
		if !unicode.Is(unicode.ASCII_Hex_Digit, char) {
			return false
		}
	}
	return true
}

func cloneNormalizedCapabilityTokens(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func matchCurlCapability(
	candidates []CurlCapability,
	command CommandFact,
) *CurlCapability {
	if command.Executable == "" {
		return nil
	}
	var matched *CurlCapability
	for index := range candidates {
		candidate := &candidates[index]
		if candidate.Executable != command.Executable {
			continue
		}
		if matched != nil {
			return nil
		}
		matched = candidate
	}
	return matched
}

func curlCommandAllowsFeature(command CommandFact, feature string) bool {
	if command.curlCapability == nil || feature == "" {
		return false
	}
	want := strings.ToLower(feature)
	for _, have := range command.curlCapability.Features {
		if have == want {
			return true
		}
	}
	return false
}

func curlCommandAllowsProtocol(command CommandFact, protocol string) bool {
	if command.curlCapability == nil || protocol == "" {
		return false
	}
	want := strings.ToLower(protocol)
	for _, have := range command.curlCapability.Protocols {
		if have == want {
			return true
		}
	}
	return false
}

func curlFeatureDependentRequiredFeature(option curlOptionToken) string {
	switch option.Canonical {
	case "--compressed":
		return "libz"
	case "--http2", "--http2-prior-knowledge":
		return "http2"
	case "--http3", "--http3-only":
		return "http3"
	case "--ssl", "--ssl-reqd", "--ftp-ssl-control":
		return "ssl"
	case "--negotiate", "--proxy-negotiate":
		return "gss-api"
	case "--ntlm", "--ntlm-wb", "--proxy-ntlm":
		return "ntlm"
	case "--proxy-http2":
		return "https-proxy"
	case "--metalink":
		return "metalink"
	case "--tcp-fastopen":
		return "tcp-fastopen"
	case "--wdebug":
		return "wdebug"
	default:
		return ""
	}
}

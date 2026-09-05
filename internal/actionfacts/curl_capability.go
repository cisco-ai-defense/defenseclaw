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
	"strconv"
	"strings"
	"unicode"
)

// curlModeledCapabilityVersion is the curl grammar ActionFacts models. Exact
// restore accepts only this version; other nonempty strings, including 7.x
// that lack --proxy-http2 (added in 8.1.0), cannot mint authority.
const curlModeledCapabilityVersion = "8.7.1"

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
	if capability.Executable == "" ||
		!curlCapabilityVersionValid(capability.Version) ||
		!curlCapabilityDigestValid(capability.Digest) {
		return false
	}
	return true
}

func curlCapabilityVersionValid(version string) bool {
	_, _, _, ok := parseCurlCapabilityVersion(version)
	return ok && version == curlModeledCapabilityVersion
}

func parseCurlCapabilityVersion(version string) (major, minor, patch int, ok bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	major, ok = parseCurlCapabilityVersionPart(parts[0])
	if !ok {
		return 0, 0, 0, false
	}
	minor, ok = parseCurlCapabilityVersionPart(parts[1])
	if !ok {
		return 0, 0, 0, false
	}
	patch, ok = parseCurlCapabilityVersionPart(parts[2])
	if !ok {
		return 0, 0, 0, false
	}
	return major, minor, patch, true
}

func parseCurlCapabilityVersionPart(part string) (int, bool) {
	if part == "" {
		return 0, false
	}
	if part[0] == '0' && len(part) > 1 {
		return 0, false
	}
	for _, char := range part {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(part)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
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

func curlCommandAllowsHTTPSProxyScheme(command CommandFact, scheme string) bool {
	if scheme != "https" {
		return true
	}
	// Nil capability is the conservative default: common curl builds
	// still transmit proxy-user / URL credentials to https:// proxies.
	// An attested inventory must include https-proxy before those facts
	// stay open.
	if command.curlCapability == nil {
		return true
	}
	return curlCommandAllowsFeature(command, "https-proxy")
}

func curlCommandAttestsHTTPSProxy(command CommandFact) bool {
	return command.curlCapability != nil &&
		curlCommandAllowsFeature(command, "https-proxy")
}

func curlCommandAttestedSchemesValid(command CommandFact, parsed curlArgvParse) bool {
	if command.curlCapability == nil {
		return true
	}
	for _, target := range parsed.Targets {
		scheme := curlEffectiveTransferScheme(parsed, target)
		if curlSchemeRequiresProtocolAttestation(scheme) &&
			!curlCommandAllowsProtocol(command, scheme) {
			return false
		}
	}
	for _, option := range parsed.Options {
		if !option.ValuePresent || option.Value == "" {
			continue
		}
		if !curlMainProxyOption(option.Canonical) &&
			option.Canonical != "--preproxy" {
			continue
		}
		scheme := curlEffectiveProxyURLScheme(option.Canonical, option.Value)
		if curlSchemeRequiresProtocolAttestation(scheme) &&
			!curlCommandAllowsProtocol(command, scheme) {
			return false
		}
	}
	return true
}

func curlEffectiveTransferScheme(parsed curlArgvParse, target curlTransferTarget) string {
	if scheme := curlURLSchemeToken(target.Value); scheme != "" {
		return scheme
	}
	if option, present := curlFinalGroupOption(
		parsed, target.Group, "--proto-default",
	); present {
		return strings.ToLower(strings.TrimSpace(option.Value))
	}
	return "http"
}

func curlEffectiveProxyURLScheme(canonical, value string) string {
	if scheme := curlURLSchemeToken(value); scheme != "" {
		return scheme
	}
	switch canonical {
	case "--socks4", "--socks4a", "--socks5", "--socks5-hostname":
		return ""
	default:
		return "http"
	}
}

func curlURLSchemeToken(value string) string {
	delimiter := strings.IndexByte(value, ':')
	if delimiter <= 0 {
		return ""
	}
	scheme := strings.ToLower(value[:delimiter])
	for _, char := range scheme {
		if char < 'a' || char > 'z' {
			return ""
		}
	}
	return scheme
}

func curlSchemeRequiresProtocolAttestation(scheme string) bool {
	switch scheme {
	case "", "socks4", "socks4a", "socks5", "socks5h", "tcp":
		return false
	default:
		return true
	}
}

func curlFeatureDependentRequiredFeatures(option curlOptionToken) []string {
	switch option.Canonical {
	case "--compressed":
		return []string{"libz"}
	case "--http2", "--http2-prior-knowledge":
		return []string{"http2"}
	case "--http3", "--http3-only":
		return []string{"http3"}
	case "--ssl", "--ssl-reqd", "--ftp-ssl-control":
		return []string{"ssl"}
	case "--negotiate", "--proxy-negotiate":
		return []string{"gss-api"}
	case "--ntlm", "--ntlm-wb", "--proxy-ntlm":
		return []string{"ntlm"}
	case "--proxy-http2":
		return []string{"https-proxy", "http2"}
	case "--metalink":
		return []string{"metalink"}
	case "--tcp-fastopen":
		return []string{"tcp-fastopen"}
	case "--wdebug":
		return []string{"wdebug"}
	default:
		return nil
	}
}

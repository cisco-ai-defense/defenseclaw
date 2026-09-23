// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"
)

const wirelessBSSIDDigestDomain = "defenseclaw/actionfacts/wireless-bssid/v1"

var (
	wirelessBSSIDPattern          = regexp.MustCompile(`(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	wirelessInterfacePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)
	wirelessCapturePathPattern    = regexp.MustCompile(`^[^\x00\r\n]+\.(?i:cap|pcap|pcapng)$`)
	wirelessCaptureFilterPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^wlan host ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`),
		regexp.MustCompile(`(?i)^wlan host ((?:[0-9a-f]{2}:){5}[0-9a-f]{2}) and \(eapol or wlan\.fc\.type_subtype == 0x08\)$`),
		regexp.MustCompile(`(?i)^ether host ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`),
		regexp.MustCompile(`(?i)^ether src ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`),
		regexp.MustCompile(`(?i)^wlan addr1 ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`),
		regexp.MustCompile(`(?i)^wlan type mgt and wlan host ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$`),
	}
)

// ExactWirelessCaptureDeauthOperation returns one exact value-free role. It
// never returns a BSSID, filter, path, interface, client, count, or payload.
func ExactWirelessCaptureDeauthOperation(
	facts Facts,
) (WirelessCaptureDeauthOperation, string, bool) {
	if len(facts.WirelessCaptureDeauthOperations) != 1 {
		return "", "", false
	}
	fact := facts.WirelessCaptureDeauthOperations[0]
	switch fact.Operation {
	case WirelessTargetedPacketCapture, WirelessDeauthentication:
	default:
		return "", "", false
	}
	if !validPrivateDigest(fact.BSSIDIdentityDigest) {
		return "", "", false
	}
	return fact.Operation, fact.BSSIDIdentityDigest, true
}

func projectWirelessCaptureDeauthOperations(input Input) []WirelessCaptureDeauthOperationFact {
	var operation WirelessCaptureDeauthOperation
	var bssid string
	var ok bool
	switch input.Tool {
	case "packet_capture":
		bssid, ok = exactTargetedPacketCaptureInput(input)
		operation = WirelessTargetedPacketCapture
	case "deauth":
		bssid, ok = exactWirelessDeauthInput(input)
		operation = WirelessDeauthentication
	default:
		return nil
	}
	if !ok {
		return nil
	}
	digest := wirelessBSSIDIdentityDigest(bssid)
	if digest == "" {
		return nil
	}
	return []WirelessCaptureDeauthOperationFact{{
		Operation: operation, BSSIDIdentityDigest: digest,
	}}
}

func exactTargetedPacketCaptureInput(input Input) (string, bool) {
	if input.Command != "" || len(input.Argv) != 0 {
		return "", false
	}
	object, ok := exactWirelessJSONObject(input.Args)
	if !ok || (len(object) != 3 && len(object) != 4) {
		return "", false
	}
	filter, filterOK := exactWirelessString(object, "filter", maxCommandBytes)
	iface, interfaceOK := exactWirelessString(object, "interface", maxScalarBytes)
	output, outputOK := exactWirelessString(object, "output_file", maxScalarBytes)
	if !filterOK || !interfaceOK || !outputOK ||
		!wirelessInterfacePattern.MatchString(iface) || unresolvedWirelessScalar(iface) ||
		!wirelessCapturePathPattern.MatchString(output) || unresolvedWirelessScalar(output) {
		return "", false
	}
	if len(object) == 4 {
		count, countOK := exactWirelessInteger(object["count"])
		if !countOK || count < 0 || count > 10_000_000 {
			return "", false
		}
	}
	for key := range object {
		switch key {
		case "filter", "interface", "output_file", "count":
		default:
			return "", false
		}
	}
	for _, pattern := range wirelessCaptureFilterPatterns {
		match := pattern.FindStringSubmatch(filter)
		if len(match) == 2 {
			return canonicalWirelessBSSID(match[1])
		}
	}
	return "", false
}

func exactWirelessDeauthInput(input Input) (string, bool) {
	if input.Command != "" || len(input.Argv) != 0 {
		return "", false
	}
	object, ok := exactWirelessJSONObject(input.Args)
	if !ok || (len(object) != 3 && len(object) != 4) {
		return "", false
	}
	bssid, bssidOK := exactWirelessString(object, "bssid", maxScalarBytes)
	iface, interfaceOK := exactWirelessString(object, "interface", maxScalarBytes)
	count, countOK := exactWirelessInteger(object["count"])
	if !bssidOK || !interfaceOK || !countOK || count < 1 || count > 1000 ||
		!wirelessInterfacePattern.MatchString(iface) || unresolvedWirelessScalar(iface) {
		return "", false
	}
	if clientValue, hasClient := object["client"]; hasClient {
		client, clientOK := clientValue.(string)
		if !clientOK || !wirelessBSSIDPattern.MatchString(client) ||
			unresolvedWirelessScalar(client) {
			return "", false
		}
	}
	for key := range object {
		switch key {
		case "bssid", "interface", "count", "client":
		default:
			return "", false
		}
	}
	return canonicalWirelessBSSID(bssid)
}

func exactWirelessJSONObject(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes || !utf8.Valid(raw) ||
		validateJSONWithStringLimit(raw, maxCommandBytes) != "" {
		return nil, false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func exactWirelessString(object map[string]any, key string, limit int) (string, bool) {
	value, ok := object[key].(string)
	return value, ok && value != "" && len(value) <= limit &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0
}

func exactWirelessInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE+-") {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func canonicalWirelessBSSID(value string) (string, bool) {
	if !wirelessBSSIDPattern.MatchString(value) || unresolvedWirelessScalar(value) {
		return "", false
	}
	canonical := strings.ToLower(value)
	if canonical == "00:00:00:00:00:00" || canonical == "ff:ff:ff:ff:ff:ff" {
		return "", false
	}
	first, err := hex.DecodeString(canonical[:2])
	if err != nil || len(first) != 1 || first[0]&1 != 0 {
		return "", false
	}
	return canonical, true
}

func unresolvedWirelessScalar(value string) bool {
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, "$`*?[]{}<>'\"") ||
		strings.Contains(lower, "%bssid%") || strings.Contains(lower, "your_bssid") ||
		strings.Contains(lower, "example_bssid") || strings.Contains(lower, "placeholder")
}

func wirelessBSSIDIdentityDigest(bssid string) string {
	canonical, ok := canonicalWirelessBSSID(bssid)
	if !ok {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{wirelessBSSIDDigestDomain, canonical} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

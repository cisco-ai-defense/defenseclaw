// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const structuredPortForwardDigestDomain = "defenseclaw/actionfacts/port-forward-target/v1"

var portForwardDNSNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func ExactStructuredPortForward(facts Facts) (StructuredPortForwardFact, bool) {
	if len(facts.StructuredPortForwards) != 1 {
		return StructuredPortForwardFact{}, false
	}
	fact := facts.StructuredPortForwards[0]
	if fact.ListenPort == 0 {
		return StructuredPortForwardFact{}, false
	}
	switch fact.Kind {
	case "local":
		if fact.TargetPort == 0 || !validPrivateDigest(fact.TargetIdentityDigest) {
			return StructuredPortForwardFact{}, false
		}
	case "dynamic", "socks":
		if fact.TargetPort != 0 || fact.TargetIdentityDigest != "" {
			return StructuredPortForwardFact{}, false
		}
	default:
		return StructuredPortForwardFact{}, false
	}
	return fact, true
}

func projectStructuredPortForwards(input Input) []StructuredPortForwardFact {
	if input.Tool != "port_forward" {
		return nil
	}
	fact, ok := exactStructuredPortForwardInput(input.Args)
	if !ok {
		return nil
	}
	return []StructuredPortForwardFact{fact}
}

func exactStructuredPortForwardInput(raw json.RawMessage) (StructuredPortForwardFact, bool) {
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes ||
		validateJSONWithStringLimit(raw, maxScalarBytes) != "" {
		return StructuredPortForwardFact{}, false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) < 2 || len(object) > 4 {
		return StructuredPortForwardFact{}, false
	}
	for key := range object {
		if key != "type" && key != "listen_port" && key != "target_host" && key != "target_port" {
			return StructuredPortForwardFact{}, false
		}
	}
	kind, kindOK := object["type"].(string)
	listenPort, listenOK := exactJSONPort(object["listen_port"])
	if !kindOK || !listenOK {
		return StructuredPortForwardFact{}, false
	}
	fact := StructuredPortForwardFact{Kind: kind, ListenPort: listenPort}
	switch kind {
	case "dynamic", "socks":
		if host, present := object["target_host"]; present {
			text, ok := host.(string)
			if !ok || text != "" {
				return StructuredPortForwardFact{}, false
			}
		}
		if port, present := object["target_port"]; present {
			number, ok := port.(json.Number)
			if !ok || number.String() != "0" {
				return StructuredPortForwardFact{}, false
			}
		}
	case "local":
		host, hostOK := object["target_host"].(string)
		targetPort, portOK := exactJSONPort(object["target_port"])
		if !hostOK || !portOK || !exactPortForwardHost(host) {
			return StructuredPortForwardFact{}, false
		}
		fact.TargetPort = targetPort
		fact.TargetIdentityDigest = portForwardTargetDigest(host, targetPort)
	default:
		return StructuredPortForwardFact{}, false
	}
	return fact, true
}

func exactJSONPort(value any) (uint16, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE+-") {
		return 0, false
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 16)
	return uint16(parsed), err == nil && parsed > 0
}

func exactPortForwardHost(host string) bool {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "$`*?[]{}<>'\"/\\") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.IsValid()
	}
	return portForwardDNSNamePattern.MatchString(host) && !strings.Contains(host, "..")
}

func portForwardTargetDigest(host string, port uint16) string {
	if !exactPortForwardHost(host) || port == 0 {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{structuredPortForwardDigestDomain, strings.ToLower(host), strconv.Itoa(int(port))} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

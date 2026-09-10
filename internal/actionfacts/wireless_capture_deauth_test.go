// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func wirelessArgs(t *testing.T, value map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWirelessCaptureDeauthFactsAreExactAndValueFree(t *testing.T) {
	capture := Analyze(Input{Tool: "packet_capture", Args: wirelessArgs(t, map[string]any{
		"filter":    "wlan host 02:AA:BB:CC:DD:EE and (eapol or wlan.fc.type_subtype == 0x08)",
		"interface": "radio0mon", "output_file": "/tmp/fixture-handshake.pcap", "count": 1000,
	})})
	deauth := Analyze(Input{Tool: "deauth", Args: wirelessArgs(t, map[string]any{
		"bssid": "02:aa:bb:cc:dd:ee", "client": "ff:ff:ff:ff:ff:ff",
		"interface": "other-radio", "count": 10,
	})})
	captureOperation, captureDigest, captureOK := ExactWirelessCaptureDeauthOperation(capture)
	deauthOperation, deauthDigest, deauthOK := ExactWirelessCaptureDeauthOperation(deauth)
	if !captureOK || !deauthOK || captureOperation != WirelessTargetedPacketCapture ||
		deauthOperation != WirelessDeauthentication || captureDigest == "" ||
		captureDigest != deauthDigest {
		t.Fatalf("wireless operations=%q/%q digests=%q/%q ok=%t/%t",
			captureOperation, deauthOperation, captureDigest, deauthDigest, captureOK, deauthOK)
	}
	if strings.Contains(captureDigest, "02:aa") || strings.Contains(captureDigest, "radio") ||
		strings.Contains(captureDigest, "fixture") {
		t.Fatalf("raw wireless argument escaped projection: %q", captureDigest)
	}
	if len(capture.WirelessCaptureDeauthOperations) != 1 ||
		len(deauth.WirelessCaptureDeauthOperations) != 1 {
		t.Fatalf("wireless facts=%+v/%+v", capture.WirelessCaptureDeauthOperations,
			deauth.WirelessCaptureDeauthOperations)
	}
}

func TestWirelessCaptureDeauthClosedGrammarHardNegatives(t *testing.T) {
	validCapture := map[string]any{
		"filter": "wlan host 02:11:22:33:44:55", "interface": "radio0",
		"output_file": "capture.pcap", "count": 100,
	}
	validDeauth := map[string]any{
		"bssid": "02:11:22:33:44:55", "interface": "radio0", "count": 10,
	}
	clone := func(source map[string]any) map[string]any {
		out := make(map[string]any, len(source))
		for key, value := range source {
			out[key] = value
		}
		return out
	}
	tests := []struct {
		name    string
		tool    string
		args    map[string]any
		command string
	}{
		{name: "generic scan", tool: "packet_capture", args: map[string]any{
			"filter": "wlan", "interface": "radio0", "output_file": "capture.pcap", "count": 100,
		}},
		{name: "filter with second address", tool: "packet_capture", args: map[string]any{
			"filter":    "wlan host 02:11:22:33:44:55 or wlan host 02:aa:bb:cc:dd:ee",
			"interface": "radio0", "output_file": "capture.pcap", "count": 100,
		}},
		{name: "dynamic filter", tool: "packet_capture", args: map[string]any{
			"filter": "wlan host ${BSSID}", "interface": "radio0", "output_file": "capture.pcap", "count": 100,
		}},
		{name: "documentation placeholder", tool: "packet_capture", args: map[string]any{
			"filter": "wlan host <BSSID>", "interface": "radio0", "output_file": "capture.pcap", "count": 100,
		}},
		{name: "dynamic output", tool: "packet_capture", args: map[string]any{
			"filter": "wlan host 02:11:22:33:44:55", "interface": "radio0", "output_file": "$OUT.pcap", "count": 100,
		}},
		{name: "unknown capture field", tool: "packet_capture", args: func() map[string]any {
			value := clone(validCapture)
			value["duration"] = 60
			return value
		}()},
		{name: "capture command conflict", tool: "packet_capture", args: validCapture, command: "capture fixture"},
		{name: "deauth missing count", tool: "deauth", args: map[string]any{
			"bssid": "02:11:22:33:44:55", "interface": "radio0",
		}},
		{name: "deauth zero count", tool: "deauth", args: func() map[string]any {
			value := clone(validDeauth)
			value["count"] = 0
			return value
		}()},
		{name: "dynamic interface", tool: "deauth", args: func() map[string]any {
			value := clone(validDeauth)
			value["interface"] = "$IFACE"
			return value
		}()},
		{name: "multicast bssid", tool: "deauth", args: func() map[string]any {
			value := clone(validDeauth)
			value["bssid"] = "03:11:22:33:44:55"
			return value
		}()},
		{name: "broadcast bssid", tool: "deauth", args: func() map[string]any {
			value := clone(validDeauth)
			value["bssid"] = "ff:ff:ff:ff:ff:ff"
			return value
		}()},
		{name: "unknown deauth field", tool: "deauth", args: func() map[string]any {
			value := clone(validDeauth)
			value["reason"] = 7
			return value
		}()},
		{name: "shell spelling is not authoritative", tool: "execute_command", args: map[string]any{
			"command": "aireplay-ng --deauth 10 -a 02:11:22:33:44:55 radio0",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: test.tool, Args: wirelessArgs(t, test.args), Command: test.command,
			})
			if operation, digest, ok := ExactWirelessCaptureDeauthOperation(facts); ok {
				t.Fatalf("hard negative projected %q/%q", operation, digest)
			}
		})
	}
}

func TestWirelessCaptureClosedFilterFormsFromGrammarDiscovery(t *testing.T) {
	filters := []string{
		"wlan host 02:11:22:33:44:55",
		"wlan host 02:11:22:33:44:55 and (eapol or wlan.fc.type_subtype == 0x08)",
		"ether host 02:11:22:33:44:55",
		"ether src 02:11:22:33:44:55",
		"wlan addr1 02:11:22:33:44:55",
		"wlan type mgt and wlan host 02:11:22:33:44:55",
	}
	for _, filter := range filters {
		facts := Analyze(Input{Tool: "packet_capture", Args: wirelessArgs(t, map[string]any{
			"filter": filter, "interface": "radio0", "output_file": "capture.pcap",
		})})
		operation, digest, ok := ExactWirelessCaptureDeauthOperation(facts)
		if !ok || operation != WirelessTargetedPacketCapture || digest == "" {
			t.Fatalf("filter %q projected %q/%q ok=%t", filter, operation, digest, ok)
		}
	}
}

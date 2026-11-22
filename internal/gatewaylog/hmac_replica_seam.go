// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

// SwapTelemetryHMACKeyForTest makes key the active HMAC key and returns the
// one it replaced (nil for none). For tests only: two gateway replicas in one
// test process need their own keys, as two pods have (each derives its key
// from its own device key, SetTelemetryHMACSeed), which a process-wide
// sync.Once seed can't give them (substrate-1 GAP-0342). Production never
// calls it.
func SwapTelemetryHMACKeyForTest(key []byte) []byte {
	var next *[]byte
	if key != nil {
		buf := append([]byte(nil), key...)
		next = &buf
	}
	if prev := telemetryHMAC.Swap(next); prev != nil {
		return *prev
	}
	return nil
}

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

package gatewaylog

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
)

// telemetryHMACInfo is the HKDF info string that domain-separates the
// telemetry HMAC key from any other use of the device key. Bumping the
// version (v1 -> v2) invalidates all prior HMAC values and forces
// downstream consumers to re-derive — used as a kill-switch if the
// canonicalization scheme below ever changes in a backward-
// incompatible way.
const telemetryHMACInfo = "defenseclaw-telemetry-v1"

// telemetryHMACKeyLen is the derived key length. 32 bytes is the
// SHA-256 block size and the recommended length for HMAC-SHA256.
const telemetryHMACKeyLen = 32

// telemetryHMAC holds the per-boot HMAC key. The key is derived by
// SetTelemetryHMACSeed at sidecar boot from the device.key seed and is
// nil for unconfigured tests / unit-test code paths that never call
// SetTelemetryHMACSeed. ComputePayloadHMAC is a no-op (returns "")
// when the key is nil so the introduction of HMAC stamping does not
// regress unit tests that don't bother to plumb a seed.
var telemetryHMAC atomic.Pointer[[]byte]

// telemetryHMACSeedOnce guards SetTelemetryHMACSeed against double-
// derive churn when the sidecar runs both the proxy boot path and the
// API boot path in the same process; both call into this helper so we
// debounce the HKDF call.
var telemetryHMACSeedOnce sync.Once

// SetTelemetryHMACSeed installs the HMAC key derivation seed. The
// seed should be a high-entropy, process-stable secret — the v1
// implementation is wired to the ed25519 device.key seed bytes, but
// any 32-byte CSPRNG output works. Calling more than once with
// different seeds is a programming error and is silently a no-op
// after the first call (sync.Once gate).
//
// The function never returns an error — if HKDF fails (it cannot
// with a 32-byte SHA-256 input), the key stays nil and ComputePayloadHMAC
// no-ops. This keeps the boot path resilient: a failed HMAC derive
// must never crash the gateway.
func SetTelemetryHMACSeed(seed []byte) {
	telemetryHMACSeedOnce.Do(func() {
		if len(seed) == 0 {
			return
		}
		key, err := hkdf.Key(sha256.New, seed, []byte("defenseclaw-telemetry-salt-v1"), telemetryHMACInfo, telemetryHMACKeyLen)
		if err != nil || len(key) != telemetryHMACKeyLen {
			return
		}
		// Defensive copy so the seed-owning caller can zero its slice.
		buf := make([]byte, telemetryHMACKeyLen)
		copy(buf, key)
		telemetryHMAC.Store(&buf)
	})
}

// telemetryHMACKey returns the active HMAC key or nil when
// SetTelemetryHMACSeed has not been called.
func telemetryHMACKey() []byte {
	if p := telemetryHMAC.Load(); p != nil {
		return *p
	}
	return nil
}

// resetTelemetryHMACSeedForTest is exported via the test build tag in
// tests; it lets unit tests reset the package-level state between
// scenarios. NOT for production use.
func resetTelemetryHMACSeedForTest() {
	telemetryHMAC.Store(nil)
	telemetryHMACSeedOnce = sync.Once{}
}

// ComputePayloadHMAC returns hex(HMAC-SHA256(key, canonicalJSON(payload)))
// for the supplied payload. Returns "" when:
//
//   - The payload is nil (no-op for events without a payload).
//   - The key is unset (boot ordering / unit tests).
//   - JSON marshaling fails (extremely rare; logged as an empty HMAC).
//
// The returned string is safe to put on the wire — it is a 64-char
// hex digest derived through HKDF + HMAC, and HKDF's domain separation
// means it cannot be reversed back to the device key.
//
// canonicalJSON: keys at every level are sorted lexicographically and
// arrays preserve their source order. Floats are emitted as JSON
// numbers (Go's default), strings are escaped, and trailing whitespace
// is omitted. This is a subset of JCS (RFC 8785) — sufficient for our
// use case (verifiable telemetry) without taking a dependency on a
// third-party canonicalizer.
func ComputePayloadHMAC(payload any) string {
	if payload == nil {
		return ""
	}
	key := telemetryHMACKey()
	if len(key) == 0 {
		return ""
	}
	buf, err := canonicalJSON(payload)
	if err != nil || len(buf) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(buf)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPayloadHMAC returns nil when the supplied digest matches the
// HMAC of the payload under the active key. Returns an error when:
//
//   - The digest is empty (caller should not have invoked verify).
//   - The active key is unset (cannot verify; not an attacker signal).
//   - The recomputed HMAC doesn't match (tamper signal).
//
// Used in a separate audit / replay path, not on the hot emit path.
func VerifyPayloadHMAC(payload any, digest string) error {
	if digest == "" {
		return errors.New("gatewaylog: empty digest")
	}
	got := ComputePayloadHMAC(payload)
	if got == "" {
		return errors.New("gatewaylog: hmac key unset; cannot verify")
	}
	if !hmac.Equal([]byte(got), []byte(digest)) {
		return errors.New("gatewaylog: hmac mismatch")
	}
	return nil
}

// canonicalJSON marshals v with sorted object keys at every nesting
// level. We materialize through interface{} to get a uniform recursive
// type to walk; this is acceptable on the telemetry path because each
// payload is a small struct (EgressPayload, VerdictPayload, etc.).
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Numbers (json.Number), strings, bools — re-marshal as-is.
		out, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(out)
		return nil
	}
}

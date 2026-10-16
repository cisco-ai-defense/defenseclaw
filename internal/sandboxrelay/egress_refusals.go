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

package sandboxrelay

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// A managed sandbox's egress proxy runs in its user's daemon, so only the
// daemon knows which destinations it just refused, and the managed gateway,
// which answers the sandbox's hooks, does not (#1192). A relayed hook call
// therefore carries the refusals the sandbox's agent has not been told of
// in EgressRefusalsHeader, set by the relay itself (the sandbox's own value
// is dropped with every SandboxHeaderPrefix header). The gateway tells the
// agent of them in the answer of a post-tool hook of a shell or fetch tool
// call, exactly as a local sandbox ingress does, says so in the verdict
// trailer (HookDecision.EgressTold), and the daemon marks them told. They
// are the daemon's own record about its own sandbox: they add a note to an
// answer and never change a verdict. An unblock is never carried: the
// gateway keeps every unblock itself (its decisions store) and lifts a
// destination rule only for one its floor still allows.

// EgressRefusalsHeader carries EncodeEgressRefusals on a relayed hook call.
const EgressRefusalsHeader = "X-DefenseClaw-Sandbox-Egress-Refusals"

// Bounds of the refusals one relayed call carries.
const (
	// MaxEgressRefusals is the most refusals one call carries: the daemon
	// keeps at most as many per sandbox.
	MaxEgressRefusals = 8
	// MaxEgressRefusalsBytes bounds the JSON before its base64 encoding.
	MaxEgressRefusalsBytes = 4 << 10
	// MaxEgressRefusalTextBytes bounds What and Remedy.
	MaxEgressRefusalTextBytes = 512
	maxEgressRefusalHostBytes = 255
	maxEgressRefusalWordBytes = 64
)

// EgressRefusal is one destination the sandbox's egress proxy refused, as
// its agent is told of it (manager.EgressRefusal).
type EgressRefusal struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Category string `json:"category,omitempty"`
	What     string `json:"what,omitempty"`
	Remedy   string `json:"remedy,omitempty"`
	Cut      bool   `json:"cut,omitempty"`
	Sent     int64  `json:"sent,omitempty"`
	Note     string `json:"note,omitempty"`
}

// FitEgressRefusals returns the refusals one relayed call carries: each
// made header-safe and cut to its bounds, those without a valid host,
// port or reason code left out, then the oldest ones (refusals come oldest
// first) that fit MaxEgressRefusals and MaxEgressRefusalsBytes. The rest
// wait for a later call.
func FitEgressRefusals(refusals []EgressRefusal) []EgressRefusal {
	var out []EgressRefusal
	for _, r := range refusals {
		if len(out) == MaxEgressRefusals {
			break
		}
		r, ok := cleanEgressRefusal(r)
		if !ok {
			continue
		}
		next := append(out, r)
		raw, err := json.Marshal(next)
		if err != nil || len(raw) > MaxEgressRefusalsBytes {
			break
		}
		out = next
	}
	return out
}

// EncodeEgressRefusals is the EgressRefusalsHeader value of the refusals
// FitEgressRefusals keeps, or "" for none.
func EncodeEgressRefusals(refusals []EgressRefusal) string {
	fit := FitEgressRefusals(refusals)
	if len(fit) == 0 {
		return ""
	}
	raw, err := json.Marshal(fit)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ParseEgressRefusals decodes an EgressRefusalsHeader value: nil when it
// is empty, malformed or over its bounds, or when any refusal in it is not
// one FitEgressRefusals would carry unchanged.
func ParseEgressRefusals(value string) []EgressRefusal {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(MaxEgressRefusalsBytes) {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > MaxEgressRefusalsBytes {
		return nil
	}
	var refusals []EgressRefusal
	if err := json.Unmarshal(raw, &refusals); err != nil || len(refusals) == 0 || len(refusals) > MaxEgressRefusals {
		return nil
	}
	for _, r := range refusals {
		if clean, ok := cleanEgressRefusal(r); !ok || clean != r {
			return nil
		}
	}
	return refusals
}

// cleanEgressRefusal is r with header-safe text cut to its bounds; ok is
// false when its host, port, reason code, note or size is not valid.
func cleanEgressRefusal(r EgressRefusal) (EgressRefusal, bool) {
	r.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Host)), ".")
	if !egressRefusalHost(r.Host) || r.Port < 0 || r.Port > 65535 || r.Sent < 0 ||
		!egressRefusalWord(r.Category) || !egressRefusalWord(r.Note) {
		return EgressRefusal{}, false
	}
	r.What = egressRefusalText(r.What)
	r.Remedy = egressRefusalText(r.Remedy)
	return r, true
}

// egressRefusalHost reports a host name or IP literal as the daemon keeps
// it (lowercase letters, digits, ".", "-", "_" and ":").
func egressRefusalHost(host string) bool {
	if host == "" || len(host) > maxEgressRefusalHostBytes {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' && c != ':' {
			return false
		}
	}
	return true
}

// egressRefusalWord reports an empty or snake_case reason code.
func egressRefusalWord(s string) bool {
	if len(s) > maxEgressRefusalWordBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// egressRefusalText is s with control characters and invalid bytes turned
// into spaces, trimmed and cut to MaxEgressRefusalTextBytes on a rune
// boundary.
func egressRefusalText(s string) string {
	s = strings.ToValidUTF8(s, " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(truncateUTF8(strings.TrimSpace(s), MaxEgressRefusalTextBytes))
}

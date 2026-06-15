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

package connector

import (
	"testing"
)

// TestHookProfileMatrix locks the declarative HookProfile shape for
// every connector the gateway dispatches to. It is the
// per-connector parity contract that documents which connectors
// support W3C trace propagation, emit native OTLP, and accept
// blocking verdicts.
//
// The matrix intentionally lives next to native_otlp_golden_test.go:
// the shape tests cover the bytes on disk; this matrix covers
// the higher-level "does the connector claim to support traceparent /
// emit a TOML block / etc." attribute that the gateway consults
// before opening a config file.
func TestHookProfileMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name               string
		wantTraceparent    bool
		wantNativeOTLPKind NativeOTLPKind // "" = no spec
		wantCanBlock       bool
		wantCanAskNative   bool
		wantSupportsClosed bool
		wantHasBlockEvents bool
	}{
		// SupportsTraceparent is true for every shipped
		// connector: every per-vendor hook script in
		// internal/gateway/connector/hooks/ sources
		// _hardening.sh and forwards DEFENSECLAW_TRACEPARENT
		// via defenseclaw_extract_trace_context.
		{"codex", true, NativeOTLPTOMLBlock, true, false, true, true},
		{"claudecode", true, NativeOTLPEnvBlock, true, true, true, true},
		{"geminicli", true, NativeOTLPJSONBlock, true, false, true, true},
		{"copilot", true, NativeOTLPEnvBlock, true, true, false, true},
		{"openhands", true, "", true, false, true, true},
		{"cursor", true, "", true, true, true, true},
		{"windsurf", true, "", true, false, false, true},
		{"hermes", true, "", true, false, false, true},
		// opencode's JS bridge does not propagate W3C traceparent, so
		// SupportsTraceparent is false; it can block and fail closed.
		{"opencode", false, "", true, false, true, true},
	}

	reg := NewDefaultRegistry()
	opts := SetupOpts{
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
		DataDir:  t.TempDir(),
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, ok := reg.Get(tc.name)
			if !ok {
				t.Fatalf("connector %q not registered in default registry", tc.name)
			}
			provider, ok := conn.(HookProfileProvider)
			if !ok {
				t.Fatalf("connector %q does not implement HookProfileProvider", tc.name)
			}
			profile := provider.HookProfile(opts)

			if profile.Name != tc.name {
				t.Errorf("Name = %q, want %q", profile.Name, tc.name)
			}
			if profile.SupportsTraceparent != tc.wantTraceparent {
				t.Errorf("SupportsTraceparent = %v, want %v", profile.SupportsTraceparent, tc.wantTraceparent)
			}
			if profile.Capabilities.CanBlock != tc.wantCanBlock {
				t.Errorf("Capabilities.CanBlock = %v, want %v", profile.Capabilities.CanBlock, tc.wantCanBlock)
			}
			if profile.Capabilities.CanAskNative != tc.wantCanAskNative {
				t.Errorf("Capabilities.CanAskNative = %v, want %v", profile.Capabilities.CanAskNative, tc.wantCanAskNative)
			}
			if profile.Capabilities.SupportsFailClosed != tc.wantSupportsClosed {
				t.Errorf("Capabilities.SupportsFailClosed = %v, want %v",
					profile.Capabilities.SupportsFailClosed, tc.wantSupportsClosed)
			}
			if tc.wantHasBlockEvents && len(profile.Capabilities.BlockEvents) == 0 {
				t.Errorf("Capabilities.BlockEvents is empty; expected non-empty for %q", tc.name)
			}

			switch tc.wantNativeOTLPKind {
			case "":
				if profile.NativeOTLP != nil {
					t.Errorf("NativeOTLP = %+v, want nil", profile.NativeOTLP)
				}
			default:
				if profile.NativeOTLP == nil {
					t.Fatalf("NativeOTLP is nil, want kind %q", tc.wantNativeOTLPKind)
				}
				if profile.NativeOTLP.Kind != tc.wantNativeOTLPKind {
					t.Errorf("NativeOTLP.Kind = %q, want %q", profile.NativeOTLP.Kind, tc.wantNativeOTLPKind)
				}
				if err := profile.NativeOTLP.Validate(); err != nil {
					t.Errorf("NativeOTLP.Validate() = %v, want nil", err)
				}
			}
		})
	}
}

// TestHookProfileMatrix_AllCapabilityProvidersHaveProfile asserts
// every connector that already implements HookCapabilityProvider
// also implements HookProfileProvider so the unified collector can
// fall through to a profile-shaped path for every registered hook
// surface. Without this assertion, adding a new HookCapability-only
// connector would silently bypass profile-driven dispatch in PR 5.
func TestHookProfileMatrix_AllCapabilityProvidersHaveProfile(t *testing.T) {
	t.Parallel()
	reg := NewDefaultRegistry()
	for _, name := range reg.Names() {
		c, ok := reg.Get(name)
		if !ok {
			continue
		}
		if _, ok := c.(HookCapabilityProvider); !ok {
			continue
		}
		if _, ok := c.(HookProfileProvider); !ok {
			t.Errorf("connector %q implements HookCapabilityProvider but not HookProfileProvider", c.Name())
		}
	}
}

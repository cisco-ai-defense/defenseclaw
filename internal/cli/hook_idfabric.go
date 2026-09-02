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

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/idfabric"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// idFabricStdinCap bounds the payload captured for telemetry. It matches
// hookexec's own stdin cap so replaying the captured bytes preserves that
// package's oversized-payload detection exactly.
const idFabricStdinCap int64 = 1 << 20

// captureIdentityFabricTelemetry writes the Identity Fabric records DefenseClaw
// would send to AI Defense for this hook invocation.
//
// Capture runs in the hook process on purpose: only here are the OS user token,
// the user's home directory, and the agent's workspace the real ones. The
// sidecar runs as a service account and would attribute every event to it.
//
// The guardrail outcome must never depend on telemetry, so this function is a
// no-op when capture is disabled, recovers from any panic, and reports failures
// to stderr without changing the exit code. When capture is enabled it consumes
// stdin and returns a replacement reader over the same bytes for hookexec.
func captureIdentityFabricTelemetry(
	opts *hookexec.Options,
	connector string,
	event string,
	enterpriseManaged bool,
) {
	if opts == nil {
		return
	}
	// Left disabled, this costs one env lookup and does not touch stdin, so
	// non-enterprise endpoints see no behavior change at all.
	if !idfabric.Enabled("", enterpriseManaged) {
		return
	}
	receivedAt := time.Now().UTC()

	payload, err := readHookPayloadForCapture(opts)
	if err != nil {
		// Stdin is unusable. Leave opts.Stdin alone and let hookexec apply its
		// own read-failure policy, which owns the fail-open/closed decision.
		reportIdentityFabricFailure("stdin capture failed")
		return
	}
	// hookexec re-reads the same bytes, including any overflow byte, so its
	// oversized-payload branch behaves as if it had read stdin directly.
	opts.Stdin = bytes.NewReader(payload)

	defer func() {
		// A telemetry defect must not take down a guardrail hook.
		if recovered := recover(); recovered != nil {
			reportIdentityFabricFailure("capture panicked")
		}
	}()

	if _, err := idfabric.CaptureHookEvent(idfabric.HookContext{
		Connector:         connector,
		Event:             event,
		Payload:           payload,
		Home:              opts.Home,
		ManagedEnterprise: enterpriseManaged,
		ProducerVersion:   version.Current().BinaryVersion,
		ReceivedAt:        receivedAt,
	}); err != nil {
		reportIdentityFabricFailure("record write failed")
	}
}

// readHookPayloadForCapture reads stdin up to one byte past the cap so the
// caller can hand hookexec a reader that still trips its overflow check.
func readHookPayloadForCapture(opts *hookexec.Options) ([]byte, error) {
	source := opts.Stdin
	if source == nil {
		source = os.Stdin
	}
	cap := opts.MaxBody
	if cap <= 0 {
		cap = idFabricStdinCap
	}
	return io.ReadAll(io.LimitReader(source, cap+1))
}

// reportIdentityFabricFailure emits a fixed, non-sensitive diagnostic.
//
// The reason is a constant chosen by the caller rather than an error string:
// hook payloads and credential-adjacent file contents must never reach a log,
// and a fixed string cannot carry a log-injection payload.
func reportIdentityFabricFailure(reason string) {
	fmt.Fprintf(os.Stderr, "defenseclaw: identity fabric capture skipped (%s)\n", reason)
}

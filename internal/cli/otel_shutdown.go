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

import "strings"

// isTransientOTelShutdownError reports whether err is a known
// "no collector reachable" failure that fires from
// telemetry.Provider.Shutdown when buffered metrics/spans/logs cannot
// be flushed because the configured OTLP endpoint isn't accepting
// connections.
//
// We classify these so the CLI does not print a noisy red banner to
// stderr after the TUI has already redrawn the user's prompt — the
// same condition is already surfaced inside the TUI as the doctor row
// "OTel (OTLP) — no endpoint configured" (see cmd_doctor.py). Printing
// it twice (once inside the TUI, once after exit) was the visible
// regression that prompted this filter.
//
// The filter is intentionally conservative: any error string we don't
// recognise still gets printed so genuine bugs (mis-configured TLS
// certs, unauthorised collectors, panics inside the SDK) remain
// visible.
func isTransientOTelShutdownError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// gRPC connection refused / dial timeout — by far the most
	// common case when no collector is running on the configured
	// host:port.
	if strings.Contains(msg, "connection refused") {
		return true
	}
	if strings.Contains(msg, "dial tcp") && strings.Contains(msg, "i/o timeout") {
		return true
	}
	// gRPC fails to flush within our shutdown ctx because nothing is
	// listening — the SDK reports this as DeadlineExceeded.
	if strings.Contains(msg, "context deadline exceeded") {
		return true
	}
	// HTTPS endpoint pointed at a plaintext server (or vice versa).
	// User intent is "OTel is enabled but I haven't really set it up
	// yet"; treat as transient so it doesn't drown out real errors.
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return true
	}
	if strings.Contains(msg, "tls: bad record MAC") {
		return true
	}
	// HTTP/2 GOAWAY from a half-configured collector closing the
	// connection mid-flush.
	if strings.Contains(msg, "code = Unavailable") {
		return true
	}
	return false
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

// Package acquire is the seam between reading the kernel and reasoning about
// what was read.
//
// Everything the runtime planes learn about a host arrives through one of
// four surfaces: the process table, the connection table, the kernel event
// stream, and passive DNS. All four need privilege that the component doing
// the reasoning should not have.
//
// That tension is the reason this package exists. On a workstation the
// gateway is the user's own process and simply reads these directly, with
// whatever privilege the operator gave it. In a managed deployment the
// gateway is deliberately de-privileged -- an unprivileged account inside a
// systemd sandbox on Linux, a virtual service account on Windows -- because
// it is the network-facing component and the threat model says a compromised
// gateway must not be able to read user homes or arbitrary host state.
//
// Splitting acquisition behind this interface lets the privileged reads move
// into a small separate service that does nothing else, while the gateway
// keeps every restriction it has. The helper answers a fixed set of
// questions and takes no instruction about what to read: its watch scope
// comes from its own root-owned configuration, never from the caller. A
// compromised gateway can therefore ask for the host's process table -- which
// it would have had anyway -- and cannot turn the helper into a way to read
// anything else.
package acquire

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// Acquirer supplies the four privileged reads the planes are built on.
//
// Every method reports coverage loss rather than hiding it: a partial read is
// returned with its count of what could not be seen, because a plane that
// silently returns less looks exactly like a quiet host.
type Acquirer interface {
	// Processes returns the process table, the count that could not be fully
	// read, and any hard error.
	Processes(ctx context.Context) ([]procprobe.Process, int, error)
	// Connections returns the TCP table, the count of sockets that could not
	// be attributed to a pid, and any hard error.
	Connections(ctx context.Context) ([]netprobe.Connection, int, error)
	// PlaneSource builds Plane C acquisition.
	//
	// homeDirs is a request, not an instruction. A local acquirer honours it.
	// A helper ignores it in favour of its own configuration -- see the
	// package doc.
	PlaneSource(homeDirs []string) plane.Source
	// DNSCapturer builds passive DNS observation.
	DNSCapturer() dnscapture.Capturer
	// Describe names the acquisition path for the coverage report, so an
	// operator can tell a direct read from a brokered one.
	Describe() string
	// Close releases whatever the acquirer holds.
	Close() error
}

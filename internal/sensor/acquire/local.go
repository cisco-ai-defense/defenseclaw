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

package acquire

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// Local reads the kernel directly, with whatever privilege this process has.
//
// This is the workstation shape and the default: the gateway is the
// operator's own process, so there is no boundary to broker across and
// adding one would only add a failure mode. What it can see is exactly what
// the operator granted, and the coverage report says so either way.
type Local struct{}

// NewLocal returns the direct acquirer.
func NewLocal() *Local { return &Local{} }

func (*Local) Processes(context.Context) ([]procprobe.Process, int, error) {
	return procprobe.Snapshot()
}

func (*Local) Connections(context.Context) ([]netprobe.Connection, int, error) {
	return netprobe.Snapshot()
}

func (*Local) PlaneSource(homeDirs []string) plane.Source { return plane.NewSource(homeDirs) }

func (*Local) DNSCapturer() dnscapture.Capturer { return dnscapture.New() }

func (*Local) Describe() string { return "direct" }

// WideCoverage asks the platform, because for a direct read the process's
// own privilege is exactly the question.
func (*Local) WideCoverage() bool {
	host, err := platform.Current()
	if err != nil {
		return false
	}
	return host.WideCoverage()
}

func (*Local) Brokered() bool { return false }

func (*Local) Close() error { return nil }

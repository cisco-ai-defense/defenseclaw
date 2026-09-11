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
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/dnscapture"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// Helper is an Acquirer that asks a privileged local service instead of
// reading the kernel itself.
//
// This is the managed-deployment shape. The gateway keeps every restriction
// its threat model advertises -- an unprivileged account inside a systemd
// sandbox, or a virtual service account on Windows -- and still learns what
// the kernel sees, because a separate small service holds that privilege and
// answers a fixed set of questions.
//
// A helper that is absent or refusing is not fatal. The planes degrade to
// what this process can read on its own and the coverage report says the
// broker is unreachable, which is the honest reading: an operator can tell a
// blinded sensor from a quiet host.
type Helper struct {
	socketPath string
	dialer     func(ctx context.Context) (net.Conn, error)

	mu       sync.Mutex
	lastFail error
}

// NewHelper returns an Acquirer that brokers through the socket at path.
func NewHelper(socketPath string) *Helper {
	helper := &Helper{socketPath: socketPath}
	helper.dialer = helper.dial
	return helper
}

// dialTimeout bounds connecting. Short: the helper is a local service, so a
// slow connect means it is gone, not busy.
const dialTimeout = 5 * time.Second

func (h *Helper) dial(ctx context.Context) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "unix", h.socketPath)
	if err != nil {
		return nil, fmt.Errorf("acquire: dial helper at %s: %w", h.socketPath, err)
	}
	return conn, nil
}

// request performs one round trip and decodes the response body.
func (h *Helper) request(ctx context.Context, op string, body any) error {
	conn, err := h.dialer(ctx)
	if err != nil {
		h.note(err)
		return err
	}
	defer conn.Close()

	if err := writeFrame(conn, Request{Version: protocolVersion, Op: op}, requestDeadline); err != nil {
		h.note(err)
		return err
	}
	var response Response
	if err := readFrame(conn, &response, responseDeadline); err != nil {
		h.note(err)
		return fmt.Errorf("acquire: read %s response: %w", op, err)
	}
	if response.Version != protocolVersion {
		err := fmt.Errorf("%w: helper speaks %d, this build speaks %d",
			ErrVersionMismatch, response.Version, protocolVersion)
		h.note(err)
		return err
	}
	if response.Error != "" {
		err := fmt.Errorf("acquire: helper refused %s: %s", op, response.Error)
		h.note(err)
		return err
	}
	if body != nil && len(response.Body) > 0 {
		if err := json.Unmarshal(response.Body, body); err != nil {
			h.note(err)
			return fmt.Errorf("acquire: decode %s body: %w", op, err)
		}
	}
	h.note(nil)
	return nil
}

func (h *Helper) note(err error) {
	h.mu.Lock()
	h.lastFail = err
	h.mu.Unlock()
}

// Processes asks the helper for the process table.
func (h *Helper) Processes(ctx context.Context) ([]procprobe.Process, int, error) {
	var table ProcessTable
	if err := h.request(ctx, OpProcesses, &table); err != nil {
		return nil, 0, err
	}
	rows := make([]procprobe.Process, 0, len(table.Rows))
	for _, row := range table.Rows {
		rows = append(rows, decodeProcess(row))
	}
	return rows, table.Skipped, nil
}

// Connections asks the helper for the TCP table.
func (h *Helper) Connections(ctx context.Context) ([]netprobe.Connection, int, error) {
	var table ConnectionTable
	if err := h.request(ctx, OpConnections, &table); err != nil {
		return nil, 0, err
	}
	rows := make([]netprobe.Connection, 0, len(table.Rows))
	for _, row := range table.Rows {
		rows = append(rows, decodeConnection(row))
	}
	return rows, table.Unattributed, nil
}

// PlaneSource subscribes to the helper's event stream.
//
// homeDirs is deliberately ignored. The helper watches what its own
// root-owned configuration names, so a gateway -- compromised or not --
// cannot widen a privileged watch by asking. See the package doc.
func (h *Helper) PlaneSource([]string) plane.Source {
	return &helperPlaneSource{helper: h, buffer: plane.NewBuffer()}
}

// DNSCapturer subscribes to the helper's observed DNS answers.
func (h *Helper) DNSCapturer() dnscapture.Capturer { return &brokeredCapturer{helper: h} }

// Describe names the acquisition path for the coverage report.
func (h *Helper) Describe() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastFail != nil {
		return "brokered (helper unreachable: " + h.lastFail.Error() + ")"
	}
	return "brokered via " + h.socketPath
}

// WideCoverage is true whenever the helper is answering.
//
// The helper is the privileged half by construction -- a deployment that
// installs it runs it as root or LocalSystem, because a helper without
// privilege would broker nothing worth having. So reachability is the
// question, and an unreachable helper is narrow coverage, not wide.
func (h *Helper) WideCoverage() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastFail == nil
}

func (h *Helper) Brokered() bool { return true }

// Close releases nothing: connections are per-request.
func (h *Helper) Close() error { return nil }

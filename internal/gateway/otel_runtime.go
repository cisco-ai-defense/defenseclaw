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

package gateway

import (
	"context"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type runtimeOTelFanout struct {
	mu       sync.RWMutex
	provider *telemetry.Provider
}

func newRuntimeOTelFanout(p *telemetry.Provider) *runtimeOTelFanout {
	return &runtimeOTelFanout{provider: p}
}

func (f *runtimeOTelFanout) SetProvider(p *telemetry.Provider) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.provider = p
	f.mu.Unlock()
}

func (f *runtimeOTelFanout) Provider() *telemetry.Provider {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	p := f.provider
	f.mu.RUnlock()
	return p
}

func (f *runtimeOTelFanout) EmitGatewayEventWithContext(ctx context.Context, ev gatewaylog.Event) {
	p := f.Provider()
	if p == nil || !p.Enabled() {
		return
	}
	p.EmitGatewayEventWithContext(ctx, ev)
}

func (f *runtimeOTelFanout) RecordSchemaViolation(eventType gatewaylog.EventType, code, _ string) {
	p := f.Provider()
	if p == nil || !p.Enabled() {
		return
	}
	p.RecordSchemaViolation(context.Background(), string(eventType), code)
}

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
	"fmt"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

var pluginAuditWireOnce sync.Once

// wirePluginAuditEmitter installs the connector-package audit hook so
// every plugin rejection lands in the same observability pipeline as
// emitGatewayError. Idempotent — multiple sidecar boots in the same
// process (e.g. tests) only register once. Plan B3 / S0.1.
func wirePluginAuditEmitter() {
	pluginAuditWireOnce.Do(func() {
		connector.SetPluginAuditEmitter(func(ctx context.Context, code, msg, soPath string, cause error) {
			detail := msg
			if soPath != "" {
				detail = fmt.Sprintf("%s (so=%s)", msg, soPath)
			}
			emitGatewayError(ctx,
				gatewaylog.SubsystemPlugin,
				gatewaylog.ErrorCode(code),
				detail,
				cause,
			)
		})
	})
}

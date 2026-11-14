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

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// OpenClawGatewayTokenEnv names the credential the gateway presents on the
// OpenClaw WebSocket. It is the token in openclaw.json gateway.auth.token (or
// a copy of it), so the OpenClaw account, every OpenClaw plugin and any agent
// tool that reads openclaw.json can read it. It is never the DefenseClaw
// gateway token: before 1.0.10 it was, and anyone holding it could allow a
// blocked tool or stop the gateway.
const OpenClawGatewayTokenEnv = "OPENCLAW_GATEWAY_TOKEN"

// IsOpenClawGatewayTokenEnv reports whether name is OpenClawGatewayTokenEnv,
// compared as the platform compares environment names (case-insensitive on
// Windows).
func IsOpenClawGatewayTokenEnv(name string) bool {
	name = strings.TrimSpace(name)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, OpenClawGatewayTokenEnv)
	}
	return name == OpenClawGatewayTokenEnv
}

// resolveOpenClawGatewayToken returns the OpenClaw WebSocket credential the
// operator saved: OPENCLAW_GATEWAY_TOKEN from the process environment, else
// from <dataDir>/.env. SecretRef text an earlier build saved there is not a
// token (#1404). "" means the client reads openclaw.json.
func resolveOpenClawGatewayToken(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv(OpenClawGatewayTokenEnv)); v != "" && !envvars.IsSecretRefText(v) {
		return v
	}
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	data, err := safefile.ReadRegularFileBounded(filepath.Join(expandPath(dataDir), ".env"), safefile.MaxDotEnvBytes)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(key, "#") || !IsOpenClawGatewayTokenEnv(key) {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == 0x22 || value[0] == 0x27) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if value != "" && !envvars.IsSecretRefText(value) {
			return value
		}
	}
	return ""
}

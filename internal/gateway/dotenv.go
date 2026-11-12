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
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// checkDotEnvSize refuses a new .env of size bytes that is over the one limit
// every dotenv reader enforces (safefile.MaxDotEnvBytes). Every writer builds the
// complete file first and calls this before publishing, so a refusal changes
// nothing on disk and names the cause.
func checkDotEnvSize(path string, size int) error {
	if size > safefile.MaxDotEnvBytes {
		return fmt.Errorf("%s would be %d bytes, over the %d-byte limit every reader accepts; it was left unchanged",
			path, size, safefile.MaxDotEnvBytes)
	}
	return nil
}

// loadDotEnv reads a KEY=VALUE file (one per line).  Blank lines and
// lines starting with # are ignored.  Values may be optionally quoted.
// This lets the sidecar pick up API keys when running as a daemon
// (where the user's shell env isn't inherited).
func loadDotEnv(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	// An adopted gateway token copy never shadows the one the operator saved.
	shadowed := envvars.ShadowedAdoptedGatewayTokens(data)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k != "" && !shadowed.Has(k) {
			out[k] = v
		}
	}
	return out, nil
}

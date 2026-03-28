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

package integrity

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// SyncMCPServerBaselines records first-seen MCP definitions and emits drift when they change.
// throttle maps "mcp:<name>" to last log time to limit audit noise.
func SyncMCPServerBaselines(cfg *config.Config, store *audit.Store, log *audit.Logger, ic *config.IntegrityConfig, throttle map[string]time.Time, onBlock func(serverName string) error) error {
	if cfg == nil || store == nil || log == nil || ic == nil || !ic.Enabled || !ic.MCP {
		return nil
	}

	servers, err := cfg.ReadMCPServers()
	if err != nil {
		return fmt.Errorf("integrity: read MCP servers: %w", err)
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })

	for _, srv := range servers {
		fp, err := FingerprintMCPServer(srv)
		if err != nil {
			return err
		}
		key := "mcp:" + srv.Name
		base, err := store.GetIntegrityBaseline("mcp", srv.Name)
		if err != nil {
			return err
		}
		if base == nil {
			if err := store.UpsertIntegrityBaseline("mcp", srv.Name, "", fp, "{}"); err != nil {
				return err
			}
			_ = log.LogAction("integrity-mcp-baseline", srv.Name, "initial baseline recorded")
			continue
		}
		if base.Fingerprint == fp {
			continue
		}
		if !mcpDriftShouldLog(throttle, key, ic.DriftLogCooldownS) {
			continue
		}
		details := fmt.Sprintf("name=%s stored_fp=%s… current_fp=%s… reason=mcp_config_changed",
			srv.Name, trimHexPrint(base.Fingerprint), trimHexPrint(fp))
		if err := log.LogIntegrityDrift("mcp:"+srv.Name, details); err != nil {
			return err
		}
		onDrift := strings.ToLower(strings.TrimSpace(ic.OnDrift))
		if onDrift == "block" {
			pe := enforce.NewPolicyEngine(store)
			_ = pe.Block("mcp", srv.Name, "integrity drift — MCP server definition changed")
			if onBlock != nil {
				_ = onBlock(srv.Name)
			}
		}
	}
	return nil
}

func mcpDriftShouldLog(throttle map[string]time.Time, key string, coolS int) bool {
	if throttle == nil {
		return true
	}
	if coolS <= 0 {
		coolS = 120
	}
	last, ok := throttle[key]
	if ok && time.Since(last) < time.Duration(coolS)*time.Second {
		return false
	}
	throttle[key] = time.Now()
	return true
}

func trimHexPrint(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

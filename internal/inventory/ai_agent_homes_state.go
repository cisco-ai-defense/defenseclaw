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

package inventory

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// A Windows user's saved variables can be read only while the user is
// signed in (their hive is loaded). After sign-out the scan would read the
// default folder, report the moved folder's skills removed, then new again
// at the next sign-in. The scan keeps the last value it read for each user
// and uses it while the hive is not loaded; it keeps it in the data folder
// so a restart while the user is signed out does the same.

const (
	agentHomesStateFile     = "ai_agent_homes_state.json"
	maxAgentHomesStateBytes = 1 << 20
	maxAgentHomesUsers      = 4096
	maxAgentHomeValueBytes  = 4096
)

// rememberedAgentHome returns the value to use for the variable name of the
// user of home (sid): value when known, which it remembers, else the last
// value remembered for that user.
func (s *ContinuousDiscoveryService) rememberedAgentHome(home, sid, name, value string, known bool) string {
	key := strings.TrimSpace(sid)
	if key == "" {
		key = filepath.Clean(home)
	}
	s.agentHomesMu.Lock()
	defer s.agentHomesMu.Unlock()
	if s.agentHomes == nil {
		s.agentHomes = s.loadAgentHomes()
	}
	if !known {
		return s.agentHomes[key][name]
	}
	if len(value) > maxAgentHomeValueBytes {
		value = ""
	}
	if s.agentHomes[key][name] == value {
		return value
	}
	if value == "" {
		delete(s.agentHomes[key], name)
		if len(s.agentHomes[key]) == 0 {
			delete(s.agentHomes, key)
		}
	} else {
		if s.agentHomes[key] == nil {
			if len(s.agentHomes) >= maxAgentHomesUsers {
				return value
			}
			s.agentHomes[key] = map[string]string{}
		}
		s.agentHomes[key][name] = value
	}
	s.saveAgentHomes()
	return value
}

func (s *ContinuousDiscoveryService) agentHomesPath() string {
	if strings.TrimSpace(s.opts.DataDir) == "" {
		return ""
	}
	return filepath.Join(s.opts.DataDir, agentHomesStateFile)
}

// loadAgentHomes reads the remembered values; a missing or bad file is an
// empty memory.
func (s *ContinuousDiscoveryService) loadAgentHomes() map[string]map[string]string {
	homes := map[string]map[string]string{}
	path := s.agentHomesPath()
	if path == "" {
		return homes
	}
	data, err := safefile.ReadRegularFileBounded(path, maxAgentHomesStateBytes)
	if err != nil || json.Unmarshal(data, &homes) != nil || len(homes) > maxAgentHomesUsers {
		return map[string]map[string]string{}
	}
	for key, values := range homes {
		for name := range values {
			if _, ok := agentHomeDefaults[name]; !ok {
				delete(values, name)
			}
		}
		if len(values) == 0 {
			delete(homes, key)
		}
	}
	return homes
}

// saveAgentHomes writes the memory; a failure leaves it in memory only.
func (s *ContinuousDiscoveryService) saveAgentHomes() {
	path := s.agentHomesPath()
	if path == "" {
		return
	}
	data, err := json.Marshal(s.agentHomes)
	if err != nil {
		return
	}
	_ = managed.WriteServiceRuntimeFile(managed.PinnedDeploymentMode(), path, "agent homes state", append(data, '\n'))
}

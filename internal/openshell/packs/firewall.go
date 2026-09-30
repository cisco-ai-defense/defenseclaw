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

package packs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/firewall"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// firewallBlock reads the deny rules of the host egress firewall
// configuration (firewall.config_file) that carry over to sandbox egress
// (egress.FirewallBlockPatterns, for the sandbox's ports): a destination the
// operator denies for the host is denied for sandboxes too, through the
// proxy and for direct rules. They join the block list, which only removing
// the rule lifts. No file means no host firewall. A file that cannot be read
// or parsed fails the policy: dropping the operator's denials would open
// what the operator closed.
func firewallBlock(path string, ports []int) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	fw, err := firewall.Load(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox policy: the host egress firewall configuration: %w", err)
	}
	var out []string
	for _, glob := range normalizeGlobs(egress.FirewallBlockPatterns(fw, ports)) {
		// The block list holds what the configuration's egress patterns
		// accept; FirewallBlockPatterns already dropped what the proxy's
		// cannot parse.
		if _, err := config.ParseOpenShellEgressPattern(glob); err == nil {
			out = append(out, glob)
		}
	}
	return out, nil
}

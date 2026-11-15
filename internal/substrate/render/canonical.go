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

package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// Canonical is a policy's rules in a normal form: upstream's port defaults
// applied, hostnames, ports and headers sorted, rules sorted. Two policies
// with the same Canonical form allow the same traffic with the same
// effects, whatever order or defaulting the server applied. It never
// includes a credential value (policies hold only references).
func Canonical(p *ateapi.EgressPolicy) string {
	lines := make([]string, 0, len(p.GetRules()))
	for _, r := range p.GetRules() {
		member, hosts, ports, effects, err := ruleFields(r)
		if err != nil {
			lines = append(lines, "invalid")
			continue
		}
		hs := slices.Clone(hosts)
		slices.Sort(hs)
		pk, err := portKeys(member, ports)
		if err != nil {
			pk = nil
		}
		pk = slices.Clone(pk)
		slices.Sort(pk)
		var eff []string
		for _, h := range effects.GetReplaceHeaders() {
			src := "uri=" + h.GetCredentialUri()
			if j := h.GetActorJwt(); j != nil {
				auds := slices.Clone(j.GetAudiences())
				slices.Sort(auds)
				src = fmt.Sprintf("jwt=%s/%d", strings.Join(auds, ","), j.GetExpirationSeconds())
			}
			eff = append(eff, fmt.Sprintf("%s:%q:%s", strings.ToLower(h.GetHeader()), h.GetPrefix(), src))
		}
		slices.Sort(eff)
		lines = append(lines, fmt.Sprintf("%s %s ports=%v effects=[%s]", member, strings.Join(hs, ","), pk, strings.Join(eff, ";")))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// Equal reports whether two policies have the same Canonical form.
func Equal(a, b *ateapi.EgressPolicy) bool { return Canonical(a) == Canonical(b) }

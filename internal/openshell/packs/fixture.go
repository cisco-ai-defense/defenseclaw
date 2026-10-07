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
	"strings"
)

// Egress fixture limits (`sandbox policy test --fixture`).
const (
	MaxFixtureBytes = 256 << 10
	MaxFixtureCases = 1024
)

// Fixture expectations.
const (
	ExpectAllow = "allow"
	ExpectBlock = "block"
)

// EgressCase is one destination of an egress fixture: a YAML or JSON list
// of {host, port, binary, expect, rule}. Port 0 judges the host on any port
// the policy carries; Rule, when set, must be the rule that decides.
type EgressCase struct {
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Binary string `json:"binary,omitempty"`
	Expect string `json:"expect"`
	Rule   string `json:"rule,omitempty"`
}

type fixtureCase struct {
	Host   *string `yaml:"host"`
	Port   *int    `yaml:"port"`
	Binary *string `yaml:"binary"`
	Expect *string `yaml:"expect"`
	Rule   *string `yaml:"rule"`
}

// egressRules are the rules a fixture may pin.
var egressRules = []EgressRule{
	RuleInvalid, RuleHostInternal, RulePrivateNetwork, RulePort, RuleAdminBlock, RuleAdminAllowOnly, RuleBlock,
	RuleUnblock, RuleAllow, RuleFeed, RuleNetworkOpen, RuleIPLiteral, RuleNetworkAllowlist, RuleNetworkDeny,
}

// fixtureWhat names an egress fixture in its errors (Error.What).
const fixtureWhat = "egress fixture"

// ParseEgressFixture strictly decodes an egress fixture (YAML, or JSON,
// which is YAML too). Its errors name the file an egress fixture, not a
// sandbox pack.
func ParseEgressFixture(data []byte, source string) ([]EgressCase, error) {
	cases, err := parseEgressFixture(data, source)
	var pe *Error
	if errors.As(err, &pe) {
		pe.What = fixtureWhat
	}
	return cases, err
}

func parseEgressFixture(data []byte, source string) ([]EgressCase, error) {
	if len(data) > MaxFixtureBytes {
		return nil, packErr(source, "", "too_large", "the fixture exceeds %d bytes", MaxFixtureBytes)
	}
	var doc []fixtureCase
	if err := decodeStrict(data, source, &doc); err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, packErr(source, "", "invalid_value", "the fixture lists no destinations")
	}
	if len(doc) > MaxFixtureCases {
		return nil, packErr(source, "", "invalid_value", "the fixture lists %d destinations (at most %d)", len(doc), MaxFixtureCases)
	}
	out := make([]EgressCase, 0, len(doc))
	for i, c := range doc {
		field := func(key string) string { return fmt.Sprintf("[%d].%s", i, key) }
		var ec EgressCase
		if c.Host == nil || strings.TrimSpace(*c.Host) == "" {
			return nil, packErr(source, field("host"), "missing_field", "is required")
		}
		ec.Host = strings.TrimSpace(*c.Host)
		if c.Port != nil {
			if *c.Port < 0 || *c.Port > 65535 {
				return nil, packErr(source, field("port"), "invalid_value", "port %d must be between 1 and 65535 (0: any port)", *c.Port)
			}
			ec.Port = *c.Port
		}
		if c.Binary != nil {
			ec.Binary = strings.TrimSpace(*c.Binary)
		}
		switch {
		case c.Expect == nil:
			return nil, packErr(source, field("expect"), "missing_field", "is required (%s or %s)", ExpectAllow, ExpectBlock)
		case *c.Expect != ExpectAllow && *c.Expect != ExpectBlock:
			return nil, packErr(source, field("expect"), "invalid_value", "%q must be %s or %s", truncateText(*c.Expect, 40), ExpectAllow, ExpectBlock)
		}
		ec.Expect = *c.Expect
		if c.Rule != nil {
			ec.Rule = strings.TrimSpace(*c.Rule)
			known := false
			for _, r := range egressRules {
				known = known || string(r) == ec.Rule
			}
			if !known {
				names := make([]string, len(egressRules))
				for j, r := range egressRules {
					names[j] = string(r)
				}
				return nil, packErr(source, field("rule"), "invalid_value", "%q is not a rule (one of %s)", truncateText(ec.Rule, 40), strings.Join(names, ", "))
			}
		}
		out = append(out, ec)
	}
	return out, nil
}

// Matches reports whether a decision meets the case's expectation.
func (c EgressCase) Matches(d EgressDecision) bool {
	if (c.Expect == ExpectAllow) != d.Allowed {
		return false
	}
	return c.Rule == "" || c.Rule == string(d.Rule)
}

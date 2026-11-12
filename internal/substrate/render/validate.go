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
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// Validate runs the admission checks ate-api-server v1.0.0 applies to an
// EgressPolicy's rules (cmd/ateapi/internal/apivalidation/egress_policy.go
// and the declarative tags on ateapi.proto), so a policy DefenseClaw
// writes is never refused at write time: at most 256 rules; each rule sets
// exactly one protocol; 1-256 unique, valid hostname patterns per rule;
// ports either all or 1-16 unique numbers in 1-65535 (required for
// tls_passthrough); effects with 1-16 replace_headers whose names are
// unique case-insensitively, each a header token with a valid prefix and
// exactly one of credential_uri (ate-secret://...) and actor_jwt
// (1-16 unique audiences of 1-512 bytes, 300-3600 s); and no two rules
// tie on a pattern and port (http defaults to 80, https to 443).
func Validate(p *ateapi.EgressPolicy) error {
	rules := p.GetRules()
	if len(rules) > MaxRules {
		return fmt.Errorf("rules: must have at most %d items", MaxRules)
	}
	type key struct {
		pattern string
		port    int32 // 0 = every port
	}
	seen := map[key]int{}
	var errs []error
	for i, r := range rules {
		member, hosts, ports, effects, err := ruleFields(r)
		at := fmt.Sprintf("rules[%d]", i)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", at, err))
			continue
		}
		if len(hosts) == 0 || len(hosts) > maxHostnamesPerRule {
			errs = append(errs, fmt.Errorf("%s.%s.hostnames: must have 1-%d items", at, member, maxHostnamesPerRule))
		}
		set := map[string]bool{}
		for j, h := range hosts {
			hp := fmt.Sprintf("%s.%s.hostnames[%d]", at, member, j)
			if set[h] {
				errs = append(errs, fmt.Errorf("%s: duplicate %q", hp, h))
			}
			set[h] = true
			if pat, ok := parsePattern(h); !ok || pat.String() != h {
				errs = append(errs, fmt.Errorf(`%s: %q must be a lowercase DNS hostname, optionally with a complete leftmost-label wildcard, or "*"`, hp, h))
			}
		}
		portKeys, err := portKeys(member, ports)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.%s.ports: %w", at, member, err))
		}
		if effects != nil {
			if err := validateEffects(effects); err != nil {
				errs = append(errs, fmt.Errorf("%s.%s.effects: %w", at, member, err))
			}
		}
		for _, h := range hosts {
			for _, pk := range portKeys {
				k := key{h, pk}
				if prior, ok := seen[k]; ok && prior != i {
					errs = append(errs, fmt.Errorf("%s.%s.hostnames: %q ties with rules[%d] on %s", at, member, h, prior, portName(pk)))
				} else {
					seen[k] = i
				}
			}
		}
	}
	return errors.Join(errs...)
}

func portName(p int32) string {
	if p == 0 {
		return "every port"
	}
	return fmt.Sprintf("port %d", p)
}

func ruleFields(r *ateapi.EgressRule) (member string, hosts []string, ports *ateapi.Ports, effects *ateapi.HttpRuleEffects, err error) {
	n := 0
	if r.GetHttp() != nil {
		n++
		member, hosts, ports, effects = "http", r.GetHttp().GetHostnames(), r.GetHttp().GetPorts(), r.GetHttp().GetEffects()
	}
	if r.GetHttps() != nil {
		n++
		member, hosts, ports, effects = "https", r.GetHttps().GetHostnames(), r.GetHttps().GetPorts(), r.GetHttps().GetEffects()
	}
	if r.GetTlsPassthrough() != nil {
		n++
		member, hosts, ports = "tls_passthrough", r.GetTlsPassthrough().GetHostnames(), r.GetTlsPassthrough().GetPorts()
	}
	if n != 1 {
		return "", nil, nil, nil, errors.New("exactly one of http, https and tls_passthrough must be set")
	}
	return member, hosts, ports, effects, nil
}

// portKeys returns the ports a rule matches after upstream's defaults; 0
// means every port.
func portKeys(member string, ports *ateapi.Ports) ([]int32, error) {
	if ports == nil {
		switch member {
		case "http":
			return []int32{80}, nil
		case "https":
			return []int32{443}, nil
		}
		return nil, errors.New("required")
	}
	if ports.GetAll() != nil {
		if len(ports.GetNumbers()) > 0 {
			return nil, errors.New("all and numbers can not be set together")
		}
		return []int32{0}, nil
	}
	nums := ports.GetNumbers()
	if len(nums) == 0 {
		if member == "tls_passthrough" {
			return nil, errors.New("required")
		}
		return portKeys(member, nil)
	}
	if len(nums) > 16 {
		return nil, errors.New("must have at most 16 items")
	}
	seen := map[int32]bool{}
	for _, n := range nums {
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("%d is outside 1-65535", n)
		}
		if seen[n] {
			return nil, fmt.Errorf("duplicate %d", n)
		}
		seen[n] = true
	}
	return nums, nil
}

func validateEffects(e *ateapi.HttpRuleEffects) error {
	hs := e.GetReplaceHeaders()
	if len(hs) == 0 {
		return errors.New("at least one effect must be specified")
	}
	if len(hs) > maxHeadersPerRule {
		return fmt.Errorf("replace_headers: must have at most %d items", maxHeadersPerRule)
	}
	seen := map[string]bool{}
	var errs []error
	for i, h := range hs {
		norm := strings.ToLower(h.GetHeader())
		if seen[norm] {
			errs = append(errs, fmt.Errorf("replace_headers[%d].header: duplicate %q", i, h.GetHeader()))
		}
		seen[norm] = true
		if err := validateHeader(h); err != nil {
			errs = append(errs, fmt.Errorf("replace_headers[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func validateHeader(h *ateapi.CredentialHeader) error {
	if !validHeaderName(h.GetHeader()) {
		return fmt.Errorf("header %q must be an HTTP header name", h.GetHeader())
	}
	if !validHeaderValue(h.GetPrefix()) {
		return errors.New("prefix must be a valid HTTP field value prefix")
	}
	jwt := h.GetActorJwt()
	switch {
	case h.GetCredentialUri() != "" && jwt != nil, h.GetCredentialUri() == "" && jwt == nil:
		return errors.New("exactly one of credential_uri and actor_jwt must be set")
	case jwt != nil:
		auds := jwt.GetAudiences()
		if len(auds) == 0 || len(auds) > 16 {
			return errors.New("actor_jwt.audiences: must have 1-16 items")
		}
		set := map[string]bool{}
		for _, a := range auds {
			if len(a) < 1 || len(a) > 512 || set[a] {
				return fmt.Errorf("actor_jwt.audiences: %q is empty, too long or repeated", a)
			}
			set[a] = true
		}
		if e := jwt.GetExpirationSeconds(); e < 300 || e > 3600 {
			return fmt.Errorf("actor_jwt.expiration_seconds: %d is outside 300-3600", e)
		}
	case !ValidCredentialURI(h.GetCredentialUri()):
		return errors.New("credential_uri must be ate-secret://<provider-class>/<provider-name>/<provider-specific-tail>")
	}
	return nil
}

// ValidateCredentialHeader checks a secret's header, prefix and source the
// way admission checks a credential_uri replace_headers entry.
func ValidateCredentialHeader(header, prefix, uri string) error {
	return validateHeader(&ateapi.CredentialHeader{Header: header, Prefix: prefix, CredentialUri: uri})
}

// ValidCredentialURI mirrors upstream validCredentialURI:
// ate-secret://<DNS-1123 provider class>/<provider-name>/<tail>, with no
// user, query, fragment, percent-encoding or empty path segment.
func ValidCredentialURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ate-secret" || u.Host == "" || u.Host != u.Hostname() || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "?") || strings.Contains(raw, "#") || !isDNS1123Subdomain(u.Host) {
		return false
	}
	p := u.EscapedPath()
	if p != u.Path || !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	return len(parts) >= 2 && !slices.Contains(parts, "")
}

func isDNS1123Subdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !isLowerAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

func validHeaderName(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !isLowerAlnum(c) && (c < 'A' || c > 'Z') && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

func isLowerAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
}

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

package egressspec

import (
	"slices"
	"strings"
)

// EchoHosts are public services that return or publish the request they
// were sent, headers included (GAP-0405). A secret injected on a request to
// one of them comes back to the agent in the response, or is published to
// whoever reads the capture, so the agent and its model see the real value.
// The callout cannot tell an echo from a normal answer in headers-only
// mode, so the controller does not add a secret on these hosts
// (render.ReasonSecretEchoHost) unless the entry sets inject.allow_echo.
// The list names the well-known ones; any service can echo, and
// substrate.egress.no_swap_hosts adds more.
var EchoHosts = []string{
	"httpbin.org", "*.httpbin.org", "httpbingo.org", "httpbin.io",
	"postman-echo.com", "echo.hoppscotch.io",
	"webhook.site", "*.pipedream.net", "*.requestcatcher.com", "*.beeceptor.com",
}

// EchoHostsCoveredWith returns the entries of EchoHosts followed by extra
// (substrate.egress.no_swap_hosts) that cover some host the pattern raw
// matches, in list order. An extra entry that is not a valid pattern is
// skipped (config validation refuses it).
func EchoHostsCoveredWith(raw string, extra []string) []string {
	p, ok := ParsePattern(raw)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range append(slices.Clip(EchoHosts), extra...) {
		ep, ok := ParsePattern(e)
		if ok && echoCovers(p, ep) && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// echoCovers reports whether the echo entry e covers some host the binding
// pattern p matches. An echo entry covers its whole subtree, at any depth:
// an exact entry N is N and every name below it, "*.N" every name below N
// (request bins live two labels deep, eoX.m.pipedream.net and
// NAME.free.beeceptor.com). A binding "*.M" still matches exactly one
// label below M.
func echoCovers(p, e Pattern) bool {
	covered := func(host string) bool {
		return (!e.Wildcard && host == e.Name) || strings.HasSuffix(host, "."+e.Name)
	}
	switch {
	case p.Any || e.Any:
		return true
	case !p.Wildcard:
		return covered(p.Name)
	case p.Name == e.Name || strings.HasSuffix(p.Name, "."+e.Name):
		// Every host one label below M is below N.
		return true
	}
	// "*.M" reaches the exact entry N one label below M.
	return !e.Wildcard && oneLabelUnder(e.Name, p.Name)
}

// oneLabelUnder reports whether host is exactly one label below parent.
func oneLabelUnder(host, parent string) bool {
	label, ok := strings.CutSuffix(host, "."+parent)
	return ok && label != "" && !strings.Contains(label, ".")
}

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

import "strings"

// EchoHosts are public services that return or publish the request they
// were sent, headers included (GAP-0405). A secret injected on a request to
// one of them comes back to the agent in the response, or is published to
// whoever reads the capture, so the agent and its model see the real value.
// The callout cannot tell an echo from a normal answer in headers-only
// mode, so binding a secret to one of these hosts is warned about at
// gateway start. The list names the well-known ones; any service can echo.
var EchoHosts = []string{
	"httpbin.org", "*.httpbin.org", "httpbingo.org", "httpbin.io",
	"postman-echo.com", "echo.hoppscotch.io",
	"webhook.site", "*.pipedream.net", "*.requestcatcher.com", "*.beeceptor.com",
}

// EchoHostsCovered returns the entries of EchoHosts that some host the
// pattern raw matches is also matched by (an overlap), in list order.
func EchoHostsCovered(raw string) []string {
	p, ok := ParsePattern(raw)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range EchoHosts {
		ep, _ := ParsePattern(e)
		if patternsOverlap(p, ep) {
			out = append(out, e)
		}
	}
	return out
}

// patternsOverlap reports whether one hostname matches both patterns. A
// wildcard "*.N" matches exactly one more label than N.
func patternsOverlap(a, b Pattern) bool {
	switch {
	case a.Any || b.Any:
		return true
	case !a.Wildcard && !b.Wildcard:
		return a.Name == b.Name
	case a.Wildcard && b.Wildcard:
		return a.Name == b.Name
	case a.Wildcard:
		return oneLabelUnder(b.Name, a.Name)
	}
	return oneLabelUnder(a.Name, b.Name)
}

// oneLabelUnder reports whether host is exactly one label below parent.
func oneLabelUnder(host, parent string) bool {
	label, ok := strings.CutSuffix(host, "."+parent)
	return ok && label != "" && !strings.Contains(label, ".")
}

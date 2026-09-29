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

package openshell

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// localhostLookupRE matches a program's report that it could not resolve
// localhost (or a name under .localhost): Go's "lookup localhost on
// 127.0.0.53:53: server misbehaving" and "lookup localhost: no such host",
// Node's "getaddrinfo EAI_AGAIN localhost" and curl's "Could not resolve
// host: localhost".
var localhostLookupRE = regexp.MustCompile(`(?i)(\blookup ([a-z0-9_-]+\.)*localhost(\.localdomain)?(:| on )` +
	`|\bgetaddrinfo E[A-Z_]+ ([a-z0-9_-]+\.)*localhost\b` +
	`|\bcould not resolve host:? '?([a-z0-9_-]+\.)*localhost\b)`)

// maxLookupLine bounds the line LocalhostLookupFailure returns.
const maxLookupLine = 240

// LocalhostLookupFailure returns the first line of output that reports a
// failed lookup of localhost, trimmed and cut to a few hundred bytes, and
// whether output has one. A harness that exits at once with such a line
// could not resolve localhost in its sandbox: a MicroVM's /etc/hosts is
// empty (Driver.HostsFile).
func LocalhostLookupFailure(output string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		if !localhostLookupRE.MatchString(line) {
			continue
		}
		line = strings.TrimSpace(line)
		if len(line) > maxLookupLine {
			cut := maxLookupLine
			for cut > 0 && !utf8.RuneStart(line[cut]) {
				cut--
			}
			line = line[:cut] + "…"
		}
		return line, true
	}
	return "", false
}

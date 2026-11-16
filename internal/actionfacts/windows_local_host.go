// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net"
	"strings"
)

// WindowsLocalHost reports a server name of a Windows share that is this
// machine: localhost, a loopback address, or the machine name that hostname
// returns. The typed patch reader and the path rules share it, so both read
// the same spellings as a local file.
func WindowsLocalHost(host string, hostname func() (string, error)) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	// An IPv6 literal is spelled with dashes and a reserved domain in a
	// share name (::1 is 0--1.ipv6-literal.net).
	if literal, ok := strings.CutSuffix(strings.ToLower(host), ".ipv6-literal.net"); ok {
		host = strings.ReplaceAll(literal, "-", ":")
	}
	if address := net.ParseIP(host); address != nil {
		return address.IsLoopback()
	}
	name, err := hostname()
	return err == nil && name != "" && strings.EqualFold(host, name)
}

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

package triage

import (
	"net"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// This machine's interface addresses as the package's tests see them: the
// egress guard refuses ranges and literals that hold them, so verdicts must
// not depend on the machine the tests run on. testOwnV4 and testOwnV6 are
// public, so their subnets (/24 and /64) are the local network.
const (
	testOwnV4 = "185.199.9.9"
	testOwnV6 = "2a00:1450:9::fe"
)

func testInterfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP(testOwnV4), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP(testOwnV6), Mask: net.CIDRMask(64, 128)},
	}, nil
}

func TestMain(m *testing.M) {
	restore := egress.OverrideInterfaceAddrsForTest(testInterfaceAddrs)
	code := m.Run()
	restore()
	os.Exit(code)
}

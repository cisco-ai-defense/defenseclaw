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

//go:build windows

package managed

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsGatewayPathGuardRequiresServiceSIDAndLocalSystem(t *testing.T) {
	localSystem, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}
	other, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		t.Fatal(err)
	}
	serviceSID, err := windows.StringToSid("S-1-5-80-1")
	if err != nil {
		t.Fatal(err)
	}
	oldService, oldUser := windowsGatewayPathIsService, windowsGatewayPathTokenUser
	oldRoots, oldResolve := windowsGatewayProfileRoots, windowsGatewayResolvePath
	t.Cleanup(func() {
		windowsGatewayPathIsService, windowsGatewayPathTokenUser = oldService, oldUser
		windowsGatewayProfileRoots, windowsGatewayResolvePath = oldRoots, oldResolve
	})
	userSID := localSystem
	var groups []windows.SIDAndAttributes
	rootsRead := 0
	windowsGatewayPathIsService = func() bool {
		isService, checkErr := windowsTokenRunsAsService(fakeServiceToken{
			user: userSID, groups: groups,
		}, serviceSID)
		return checkErr == nil && isService
	}
	windowsGatewayPathTokenUser = func() (*windows.Tokenuser, error) {
		return &windows.Tokenuser{User: windows.SIDAndAttributes{Sid: userSID}}, nil
	}
	windowsGatewayProfileRoots = func() ([]string, error) {
		rootsRead++
		return []string{`C:\Users`}, nil
	}
	windowsGatewayResolvePath = func(path string) (string, error) { return path, nil }
	target := `C:\Users\sample\project`
	if err := RequireWindowsGatewayPathOutsideUserProfiles(target); err != nil || rootsRead != 0 {
		t.Fatalf("without gateway service SID: error %v, roots read %d", err, rootsRead)
	}
	userSID = other
	groups = []windows.SIDAndAttributes{{Sid: serviceSID, Attributes: windows.SE_GROUP_ENABLED}}
	if err := RequireWindowsGatewayPathOutsideUserProfiles(target); err != nil || rootsRead != 0 {
		t.Fatalf("non-LocalSystem process: error %v, roots read %d", err, rootsRead)
	}
	userSID = localSystem
	if err := RequireWindowsGatewayPathOutsideUserProfiles(target); err == nil ||
		!strings.Contains(err.Error(), windowsGatewayProfileRefusal) || rootsRead != 1 {
		t.Fatalf("gateway service: error %v, roots read %d", err, rootsRead)
	}
}

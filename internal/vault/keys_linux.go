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

//go:build linux

package vault

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/defenseclaw/defenseclaw/internal/keystore"
)

// osKeystore is the Secret Service through secret-tool, when this session
// has one: secret-tool on PATH and a D-Bus session bus (an SSH login or a
// service usually has none).
func osKeystore() (Keystore, string, error) {
	bin, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, "no Secret Service: secret-tool is not installed (package libsecret-tools or libsecret)", nil
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		if _, err := os.Stat(fmt.Sprintf("/run/user/%d/bus", os.Getuid())); err != nil {
			return nil, "no Secret Service in this session (no D-Bus session bus, as over SSH or in a service)", nil
		}
	}
	return secretService{t: keystore.SecretTool{Run: keystore.ExecRunner, Bin: bin}}, "", nil
}

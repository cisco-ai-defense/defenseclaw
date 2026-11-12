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

package auth

import "os/exec"

func osStore() (Store, error) {
	bin, err := exec.LookPath("secret-tool")
	if err != nil {
		return nil, noKeychain("no OS keychain is usable: secret-tool is not on PATH; install it (package libsecret-tools or libsecret) with a running Secret Service such as GNOME Keyring")
	}
	return &secretToolStore{run: execRunner, bin: bin}, nil
}

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

package gateway

import (
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// sandboxAccountForSID names the account of a SID and its domain with
// LookupAccountSid, as Windows enrollment does.
func sandboxAccountForSID(id string) (account, domain string, ok bool) {
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(strings.ToUpper(id), "S-1-") {
		return "", "", false
	}
	sid, err := windows.StringToSid(id)
	if err != nil || sid == nil {
		return "", "", false
	}
	account, domain, _, err = sid.LookupAccount("")
	if err != nil {
		return "", "", false
	}
	return useridentity.CanonicalWindowsAccountName(id, account, domain), domain, true
}

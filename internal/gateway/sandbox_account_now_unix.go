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

//go:build linux || darwin

package gateway

import (
	"context"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// sandboxAccountNow asks the account database, through a new resolver and
// so past every cache, which account holds uid, and returns its name as the
// peer identity spells it. The sandbox authority removes another account's
// records only on this answer (rel-1-0-6:GAP-0262). Replaceable by tests.
var sandboxAccountNow = func(uid int) (string, error) {
	account, err := unixidentity.Default(context.Background()).LookupUID(uid)
	if err != nil {
		return "", err
	}
	if account.UID != uid {
		return "", fmt.Errorf("the account database answered uid %d for uid %d", account.UID, uid)
	}
	return sanitizeLLMEventUser(account.Name), nil
}

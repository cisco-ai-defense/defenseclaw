// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/sha256"
	"encoding/hex"
)

// PersonKeyPrefix starts every person key.
const PersonKeyPrefix = "p:"

// Key is the pseudonymous key a person's actor calls are charged and
// counted under (routing budgets, model usage): "p:" and the first 16 hex
// digits of sha256(issuer#subject). The issuer is part of it, so the same
// subject at two identity providers is two people; the display name
// (Principal) is never part of it. "" for no person.
func (p Person) Key() string {
	id := p.ID()
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return PersonKeyPrefix + hex.EncodeToString(sum[:8])
}

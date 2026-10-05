// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"errors"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// resolvePeerDirectoryFacts returns the root enumerator's Open Directory
// facts for a verified uid. A Mac gateway has no NSS to ask, so without a
// guardian record (a per-user install) there are no verified facts.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	record, ok := readIdentitySpoolFacts(key, time.Now().UTC())
	if !ok {
		return useridentity.DirectoryFacts{}, errors.New("no identity spool record")
	}
	facts := record.Facts
	facts.Assurance = useridentity.AssuranceVerified
	return facts, nil
}

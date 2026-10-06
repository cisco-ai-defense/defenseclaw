// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An SSSD domain that realmd did not join (for example a cloud directory's
// LDAP interface read with id_provider = ldap) still gets a directory type
// from its id provider.
func TestSSSDProviderDirectory(t *testing.T) {
	for provider, want := range map[string]useridentity.Directory{
		"ldap":  useridentity.DirectoryLDAP,
		"ipa":   useridentity.DirectoryLDAP,
		" AD ":  useridentity.DirectoryActiveDirectory,
		"proxy": "",
		"":      "",
	} {
		if got := sssdProviderDirectory(provider); got != want {
			t.Errorf("sssdProviderDirectory(%q) = %q, want %q", provider, got, want)
		}
	}
}

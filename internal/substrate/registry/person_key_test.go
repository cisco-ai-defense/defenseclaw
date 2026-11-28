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
	"regexp"
	"strings"
	"testing"
)

// TestPersonKeyIncludesIssuer: the same subject at two issuers is two
// keys; the key never carries the subject or the display name.
func TestPersonKeyIncludesIssuer(t *testing.T) {
	a := Person{Kind: "human", Issuer: "https://idp-a.example", Subject: "alice", Principal: "alice@example.com"}
	b := a
	b.Issuer = "https://idp-b.example"
	ka, kb := a.Key(), b.Key()
	if ka == kb {
		t.Fatalf("two issuers, one key %q", ka)
	}
	re := regexp.MustCompile(`^p:[0-9a-f]{16}$`)
	for _, k := range []string{ka, kb} {
		if !re.MatchString(k) || strings.Contains(k, "alice") {
			t.Fatalf("key %q: want p: and 16 hex digits, no subject or name", k)
		}
	}
	c := a
	c.Principal, c.Groups = "someone-else@example.com", []string{"eng"}
	if c.Key() != ka {
		t.Fatal("the display name or groups changed the key")
	}
	if (Person{}).Key() != "" || (Person{Issuer: "https://idp-a.example"}).Key() != "" {
		t.Fatal("no person must have no key")
	}
}

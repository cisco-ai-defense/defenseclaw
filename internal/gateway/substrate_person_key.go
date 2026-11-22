// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// substrateUsageOwnerKind is the usage owner kind of an actor's person:
// the owner of its calls is substrate_person:<registry.Person.Key>.
const substrateUsageOwnerKind = "substrate_person"

// substrateActorPersonKey is the key a verified actor's calls are charged and
// counted under: its registration person's Key, sha256(issuer#subject),
// never the bare subject, which two issuers can share, and never a
// header. ok is false for a host request and an actor with no person.
func substrateActorPersonKey(ctx context.Context) (string, bool) {
	if !isSubstrateActorRequest(ctx) {
		return "", false
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok || reg.Attributed {
		return "", false
	}
	key := reg.Person.Key()
	return key, key != ""
}

// substrateUsageOwner is the usage owner of person p: what usageIdentity
// writes for the person's actor calls and what the usage API reads for
// that person. "" for no person.
func substrateUsageOwner(p registry.Person) string {
	key := p.Key()
	if key == "" {
		return ""
	}
	return modelusage.OwnerID(modelusage.CallFacts{Subject: key, SubjectKind: substrateUsageOwnerKind, IdentityVerified: true})
}

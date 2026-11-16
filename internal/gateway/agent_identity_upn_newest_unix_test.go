// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// newUPNRowFixture is a managed SSSD uid whose UPN comes from the
// guardian's InfoPipe record (infopipe, or infopipe_kept when kept).
func newUPNRowFixture(t *testing.T) upnRowFixture {
	t.Helper()
	writeRecord, _ := unixFactsSpool(t)
	uid, _ := strconv.Atoi(unixFactsUID)
	previous, previousFacts := managedHookPeerHomes, identityFactsEnabled.Load()
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
				uid: {Name: "dcad-strict", UID: uid, Home: "/home/dcad-strict"},
			}}
		},
		now: time.Now,
	}
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		managedHookPeerHomes = previous
		setIdentityFactsEnabled(previousFacts)
	})
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			now := time.Now()
			facts := unixNSSFacts()
			facts.SpoolSeenAt = identitySpoolSeenAt(key, now)
			if record, ok, err := readIdentitySpoolFactsForAccount(key, "dcad-strict", unixFactsSID, now); err != nil {
				return useridentity.DirectoryFacts{}, err
			} else if ok {
				facts = mergeSpoolFacts(facts, record)
			}
			return facts, nil
		})
	})
	home := t.TempDir()
	return upnRowFixture{
		ctx: withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Name: "dcad-strict", Home: home}),
		publish: func(upn string, kept bool) {
			// Each pass is written after the previous lookup.
			time.Sleep(time.Millisecond)
			record := enterprisehooks.IdentitySpoolRecord{User: "dcad-strict", AccountSID: unixFactsSID,
				UPNSource: enterprisehooks.UPNSourceInfoPipe, Facts: useridentity.DirectoryFacts{
					UPN: upn, Principal: upn, Realm: "DCLAB.TEST", Directory: useridentity.DirectoryActiveDirectory}}
			if kept {
				record.UPNSource, record.UPNKeptSince = enterprisehooks.UPNSourceInfoPipeKept, time.Now().UTC()
			}
			writeRecord(record)
			if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
				t.Fatal("the hook path's directory lookup failed")
			}
		},
	}
}

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
	"context"
	"errors"
	"os/exec"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Linux the guardian adds what only root can read to the NSS facts the
// gateway resolves itself: the userPrincipalName from SSSD InfoPipe
// (org.freedesktop.sssd.infopipe GetUserAttr, which sssd-ifp answers for
// root only) and the realm's directory type from `realm list`. Without
// InfoPipe the principal falls back to sAMAccountName@REALM, recorded as
// upn_source=derived.

const (
	infoPipeService   = "org.freedesktop.sssd.infopipe"
	infoPipePath      = "/org/freedesktop/sssd/infopipe"
	infoPipeGetAttr   = "org.freedesktop.sssd.infopipe.GetUserAttr"
	infoPipeUPNAttr   = "userPrincipalName"
	realmListTimeout  = 15 * time.Second
	infoPipeCallLimit = 5 * time.Second
)

func collectIdentitySpoolRecord(ctx context.Context, account IdentitySpoolAccount, realms []RealmEntry, now time.Time) (IdentitySpoolRecord, error) {
	resolver, err := unixidentity.NewNSSResolver(ctx)
	if err != nil {
		return IdentitySpoolRecord{}, err
	}
	nss, err := resolver.LookupUID(account.UID)
	if err != nil {
		return IdentitySpoolRecord{}, err
	}
	facts, err := resolver.DirectoryFactsForUID(account.UID, now)
	if err != nil {
		return IdentitySpoolRecord{}, err
	}
	record := IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: nss.Name, UpdatedAt: now}
	if facts.Source != useridentity.SourceSSSD && facts.Source != useridentity.SourceWinbind {
		record.Facts = facts
		return record, nil
	}
	applyRealm(&facts, realms)
	bare, _ := useridentity.SplitQualifiedName(nss.Name)
	if facts.Principal == "" && facts.Realm != "" {
		facts.Principal = useridentity.NormalizePrincipal(bare + "@" + facts.Realm)
	}
	if facts.Source == useridentity.SourceSSSD {
		callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
		upn, upnErr := infoPipeUPN(callCtx, nss.Name)
		cancel()
		if upn = useridentity.NormalizeUPN(upn); upnErr == nil && upn != "" {
			facts.UPN = upn
			facts.Principal = upn
			facts.Source = useridentity.SourceSSSDInfoPipe
			record.UPNSource = UPNSourceInfoPipe
		}
	}
	if record.UPNSource == "" && facts.Principal != "" {
		record.UPNSource = UPNSourceDerived
	}
	record.Facts = facts
	return record, nil
}

// infoPipeUPN asks sssd-ifp for the account's userPrincipalName.
func infoPipeUPN(ctx context.Context, name string) (string, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var attrs map[string]dbus.Variant
	call := conn.Object(infoPipeService, infoPipePath).CallWithContext(ctx, infoPipeGetAttr, 0, name, []string{infoPipeUPNAttr})
	if err := call.Store(&attrs); err != nil {
		return "", err
	}
	value, ok := attrs[infoPipeUPNAttr]
	if !ok {
		return "", nil
	}
	switch v := value.Value().(type) {
	case []string:
		if len(v) > 0 {
			return v[0], nil
		}
	case string:
		return v, nil
	}
	return "", errors.New("unexpected InfoPipe userPrincipalName type")
}

// readRealmList runs `realm list` once per pass. A host without realmd, or
// one joined some other way, reports no realms.
func readRealmList(ctx context.Context) []RealmEntry {
	tool := trustedIdentityTool("/usr/sbin/realm", "/usr/bin/realm", "/sbin/realm")
	if tool == "" {
		return nil
	}
	runCtx, cancel := context.WithTimeout(ctx, realmListTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, tool, "list")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return ParseRealmList(boundedOutput(out))
}

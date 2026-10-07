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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Linux the guardian adds what only root can read to the NSS and realmd
// facts the gateway resolves itself: the userPrincipalName from SSSD
// InfoPipe (org.freedesktop.sssd.infopipe GetUserAttr, which sssd-ifp
// answers for root only). Without InfoPipe the principal is
// sAMAccountName@REALM, recorded as upn_source=derived.

const (
	infoPipeService   = "org.freedesktop.sssd.infopipe"
	infoPipePath      = "/org/freedesktop/sssd/infopipe"
	infoPipeGetAttr   = "org.freedesktop.sssd.infopipe.GetUserAttr"
	infoPipeUPNAttr   = "userPrincipalName"
	infoPipeUsers     = "/org/freedesktop/sssd/infopipe/Users"
	infoPipeFindUser  = "org.freedesktop.sssd.infopipe.Users.FindByName"
	infoPipeUserIface = "org.freedesktop.sssd.infopipe.Users.User"
	infoPipeDomIface  = "org.freedesktop.sssd.infopipe.Domains"
	dbusPropertiesGet = "org.freedesktop.DBus.Properties.Get"
	infoPipeCallLimit = 5 * time.Second
)

func collectIdentitySpoolRecord(ctx context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
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
	if facts.Source == useridentity.SourceSSSD {
		if facts.Directory == "" {
			// A domain realmd did not join, such as a plain LDAP directory
			// or a cloud directory's LDAP interface: its SSSD id provider
			// names the directory type.
			callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
			provider, providerErr := infoPipeDomainProvider(callCtx, nss.Name)
			cancel()
			if providerErr != nil {
				record.Facts = facts
				return record, fmt.Errorf("SSSD InfoPipe provider lookup: %w", providerErr)
			}
			facts.Directory = sssdProviderDirectory(provider)
		}
		callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
		upn, upnErr := infoPipeUPN(callCtx, nss.Name)
		cancel()
		if upnErr != nil {
			record.Facts = facts
			return record, fmt.Errorf("SSSD InfoPipe UPN lookup: %w", upnErr)
		}
		if upn = useridentity.NormalizeUPN(upn); upn != "" {
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

// infoPipeDomainProvider returns the id provider ("ldap", "ad", "ipa", ...)
// of the SSSD domain that serves the account name.
func infoPipeDomainProvider(ctx context.Context, name string) (string, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var user dbus.ObjectPath
	if err := conn.Object(infoPipeService, infoPipeUsers).CallWithContext(ctx, infoPipeFindUser, 0, name).Store(&user); err != nil {
		return "", err
	}
	var domain dbus.Variant
	if err := conn.Object(infoPipeService, user).CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeUserIface, "domain").Store(&domain); err != nil {
		return "", err
	}
	domainPath, ok := domain.Value().(dbus.ObjectPath)
	if !ok || !domainPath.IsValid() {
		return "", errors.New("unexpected InfoPipe user domain")
	}
	var provider dbus.Variant
	if err := conn.Object(infoPipeService, domainPath).CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeDomIface, "provider").Store(&provider); err != nil {
		return "", err
	}
	value, ok := provider.Value().(string)
	if !ok {
		return "", errors.New("unexpected InfoPipe domain provider type")
	}
	return value, nil
}

// sssdProviderDirectory maps the id provider of an SSSD domain to the
// directory type: ad is Active Directory; ldap and ipa are LDAP directories,
// the type an IPA realm gets from realmd too. Other providers (proxy, files)
// name no directory and leave the type unset.
func sssdProviderDirectory(provider string) useridentity.Directory {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ad":
		return useridentity.DirectoryActiveDirectory
	case "ldap", "ipa":
		return useridentity.DirectoryLDAP
	}
	return ""
}

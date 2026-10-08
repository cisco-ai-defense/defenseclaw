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
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On Linux the guardian adds what only root can read to the NSS, SSSD SID
// and realmd facts the gateway resolves itself, from SSSD InfoPipe, which
// sssd-ifp answers for root only.
//
// InfoPipe is asked by uid which SSSD domain holds the account
// (Users.FindByID), never by name: SSSD looks a name up in its domains in
// order, and a name with an @ that the named domain lacks as a UPN or e-mail
// address in all of them, so a lookup by name can answer for another account
// (GAP-0605). The record names that domain (SSSDDomain). When it is not the
// domain the account's SID was confirmed in, the record drops that domain,
// its realm and principal, and the gateway drops its own (mergeSpoolFacts).
// An account without a SID that InfoPipe holds in an AD or IPA domain of a
// joined realm, such as one of an IPA domain without an AD trust, takes that
// realm here.
// The userPrincipalName comes from the same user object (extraAttributes,
// with userPrincipalName in the [ifp] user_attributes); without it the
// principal is sAMAccountName@REALM, recorded as upn_source=derived.

const (
	infoPipeService   = "org.freedesktop.sssd.infopipe"
	infoPipeUPNAttr   = "userPrincipalName"
	infoPipeUsers     = "/org/freedesktop/sssd/infopipe/Users"
	infoPipeFindByID  = "org.freedesktop.sssd.infopipe.Users.FindByID"
	infoPipeUserIface = "org.freedesktop.sssd.infopipe.Users.User"
	infoPipeDomIface  = "org.freedesktop.sssd.infopipe.Domains"
	dbusPropertiesGet = "org.freedesktop.DBus.Properties.Get"
	dbusGetAll        = "org.freedesktop.DBus.Properties.GetAll"
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
	facts, err := resolver.DirectoryFactsWithoutGroupsForUID(account.UID, now)
	if err != nil {
		return IdentitySpoolRecord{}, err
	}
	record := IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: nss.Name, UpdatedAt: now}
	if facts.Source != useridentity.SourceSSSD && facts.Source != useridentity.SourceWinbind {
		record.Facts = facts
		return record, nil
	}
	if facts.Source == useridentity.SourceSSSD {
		callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
		held, heldErr := infoPipeAccount(callCtx, account.UID)
		cancel()
		if heldErr != nil {
			record.Facts = facts
			return record, fmt.Errorf("SSSD InfoPipe lookup of uid %d: %w", account.UID, heldErr)
		}
		record.SSSDDomain = held.domain
		if facts.Realm != "" && !strings.EqualFold(held.domain, facts.Domain) && !strings.EqualFold(held.realm, facts.Realm) {
			// The SSSD domain that holds the uid is not the realm its SID was
			// confirmed in, so that realm, the directory type it gave and the
			// principal belong to another account.
			facts.Domain, facts.Realm, facts.Principal, facts.Directory = "", "", "", ""
		}
		if provider := strings.ToLower(held.provider); facts.Realm == "" && facts.Directory == "" && (provider == "ad" || provider == "ipa") {
			// Only an AD or IPA domain holds accounts of a joined realm: a
			// plain LDAP domain may carry a name below the joined domain.
			if err := unixidentity.ApplyHeldSSSDDomain(ctx, &facts, nss.Name, held.domain, held.realm); err != nil {
				record.Facts = facts
				return record, fmt.Errorf("realmd lookup: %w", err)
			}
		}
		if facts.Directory == "" {
			// A domain realmd did not join, such as a plain LDAP directory
			// or a cloud directory's LDAP interface: its SSSD id provider
			// names the directory type.
			facts.Directory = sssdProviderDirectory(held.provider)
		}
		if upn := useridentity.NormalizeUPN(held.upn); upn != "" {
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

// errSSSDNotActive keeps InfoPipe unasked while sssd.service is not active.
var errSSSDNotActive = errors.New("sssd.service is not active yet, so SSSD InfoPipe is not asked until it is")

// infoPipeGate refuses an InfoPipe call while systemd reports sssd.service
// in any state but active. The call D-Bus-activates sssd-ifp; while sssd was
// still starting (a directory late at boot) each guardian pass timed out an
// activation, and when sssd came up the queued activations hit the start
// limit, left sssd-ifp.service failed and the host degraded (GAP-0583). A
// host where systemd does not answer (known false) keeps asking InfoPipe.
func infoPipeGate(active, known bool) error {
	if known && !active {
		return errSSSDNotActive
	}
	return nil
}

// sssdServiceState reports whether systemd has sssd.service active, without
// starting anything; known is false when systemd does not answer on the bus.
func sssdServiceState(ctx context.Context, conn *dbus.Conn) (active, known bool) {
	var unit dbus.ObjectPath
	systemd := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	if err := systemd.CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", dbus.FlagNoAutoStart, "sssd.service").Store(&unit); err != nil {
		var dbusErr dbus.Error
		if errors.As(err, &dbusErr) && dbusErr.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return false, true // not loaded: not running
		}
		return false, false
	}
	var state dbus.Variant
	if err := conn.Object("org.freedesktop.systemd1", unit).CallWithContext(ctx, dbusPropertiesGet, dbus.FlagNoAutoStart,
		"org.freedesktop.systemd1.Unit", "ActiveState").Store(&state); err != nil {
		return false, false
	}
	value, _ := state.Value().(string)
	return value == "active", true
}

// infoPipeHeld is what InfoPipe reports for the user that holds a uid: the
// name, id provider ("ldap", "ad", "ipa", ...) and Kerberos realm of its
// SSSD domain, and its userPrincipalName when the [ifp] user_attributes
// list it.
type infoPipeHeld struct {
	domain, provider, realm, upn string
}

// infoPipeAccount asks InfoPipe for the user that holds uid.
func infoPipeAccount(ctx context.Context, uid int) (infoPipeHeld, error) {
	if uid < 0 || int64(uid) > math.MaxUint32 {
		return infoPipeHeld{}, errors.New("uid out of range")
	}
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return infoPipeHeld{}, err
	}
	defer conn.Close()
	if err := infoPipeGate(sssdServiceState(ctx, conn)); err != nil {
		return infoPipeHeld{}, err
	}
	var user dbus.ObjectPath
	if err := conn.Object(infoPipeService, infoPipeUsers).CallWithContext(ctx, infoPipeFindByID, 0, uint32(uid)).Store(&user); err != nil {
		return infoPipeHeld{}, err
	}
	userObject := conn.Object(infoPipeService, user)
	var domain dbus.Variant
	if err := userObject.CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeUserIface, "domain").Store(&domain); err != nil {
		return infoPipeHeld{}, err
	}
	domainPath, ok := domain.Value().(dbus.ObjectPath)
	if !ok || !domainPath.IsValid() {
		return infoPipeHeld{}, errors.New("unexpected InfoPipe user domain")
	}
	var props map[string]dbus.Variant
	if err := conn.Object(infoPipeService, domainPath).CallWithContext(ctx, dbusGetAll, 0, infoPipeDomIface).Store(&props); err != nil {
		return infoPipeHeld{}, err
	}
	var held infoPipeHeld
	held.domain, _ = props["name"].Value().(string)
	held.provider, _ = props["provider"].Value().(string)
	held.realm, _ = props["realm"].Value().(string)
	if held.domain = strings.TrimSpace(held.domain); held.domain == "" || strings.ContainsAny(held.domain, "@\\\x00") {
		return infoPipeHeld{}, errors.New("unexpected InfoPipe domain name")
	}
	held.realm = strings.TrimSpace(held.realm)
	var extra dbus.Variant
	if err := userObject.CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeUserIface, "extraAttributes").Store(&extra); err != nil {
		return infoPipeHeld{}, err
	}
	var attrs map[string][]string
	if err := extra.Store(&attrs); err != nil {
		return infoPipeHeld{}, fmt.Errorf("unexpected InfoPipe extraAttributes: %w", err)
	}
	if values := attrs[infoPipeUPNAttr]; len(values) > 0 {
		held.upn = values[0]
	}
	return held, nil
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

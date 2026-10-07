//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The realms the host is joined to, from realmd.
//
// SSSD serves Active Directory, IPA and plain LDAP domains alike, so its
// NSS answer does not say which directory owns an account. realmd, the
// root system service behind `realm join` and `realm list`, does. Only
// root may own its system-bus name, and any account may read its realm
// properties, so a per-user gateway gets the same answer as the root
// guardian: no privilege, no tool to run and no call to the directory.
// The owner of the name is checked to be uid 0 as well. A host without
// realmd, or joined some other way, has no realms.

// Realm is one configured (joined) realm.
type Realm struct {
	// Domain is the DNS domain, in lower case.
	Domain string
	// Name is the Kerberos realm, in upper case.
	Name string
	// ServerSoftware is the server-software detail realmd reports, for
	// example "active-directory" or "ipa".
	ServerSoftware string
	// ClientSoftware is the client-software detail, "sssd" or "winbind".
	ClientSoftware string
	// NetBIOS is the NetBIOS domain name of a winbind realm (CORP), in upper
	// case, from its login format; empty for SSSD realms.
	NetBIOS string
}

const (
	realmdService   = "org.freedesktop.realmd"
	realmdPath      = "/org/freedesktop/realmd"
	realmdProvider  = "org.freedesktop.realmd.Provider"
	realmdRealm     = "org.freedesktop.realmd.Realm"
	realmdKerberos  = "org.freedesktop.realmd.Kerberos"
	dbusGetProperty = "org.freedesktop.DBus.Properties.Get"
	dbusGetAll      = "org.freedesktop.DBus.Properties.GetAll"
	dbusUnixUser    = "org.freedesktop.DBus.GetConnectionUnixUser"
	realmdTimeout   = 5 * time.Second
	realmCacheTTL   = time.Minute
	maxRealms       = 16
)

// hostRealms returns the configured realms. It asks realmd at most once a
// minute, so a guardian pass over every account makes one query. Tests
// replace it.
var hostRealms = cachedRealms

var realmCache struct {
	mu      sync.Mutex
	realms  []Realm
	fetched time.Time
}

func cachedRealms(ctx context.Context) ([]Realm, error) {
	realmCache.mu.Lock()
	defer realmCache.mu.Unlock()
	if !realmCache.fetched.IsZero() && time.Since(realmCache.fetched) < realmCacheTTL {
		return realmCache.realms, nil
	}
	realms, err := configuredRealms(ctx)
	if err != nil {
		return nil, err
	}
	realmCache.realms, realmCache.fetched = realms, time.Now()
	return realms, nil
}

// configuredRealms asks realmd on the system bus for configured realms. An
// absent realmd service means an unjoined host; a failed query is unknown.
func configuredRealms(ctx context.Context) ([]Realm, error) {
	ctx, cancel := context.WithTimeout(ctx, realmdTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var paths []dbus.ObjectPath
	if err := conn.Object(realmdService, realmdPath).CallWithContext(ctx, dbusGetProperty, 0, realmdProvider, "Realms").Store(&paths); err != nil {
		var busErr dbus.Error
		if errors.As(err, &busErr) && busErr.Name == "org.freedesktop.DBus.Error.ServiceUnknown" {
			return nil, nil
		}
		return nil, err
	}
	var owner uint32
	if err := conn.BusObject().CallWithContext(ctx, dbusUnixUser, 0, realmdService).Store(&owner); err != nil {
		return nil, err
	}
	if owner != 0 {
		return nil, fmt.Errorf("realmd system-bus owner uid %d is not root", owner)
	}
	var realms []Realm
	for _, path := range paths {
		if len(realms) == maxRealms {
			break
		}
		object := conn.Object(realmdService, path)
		var realm, kerberos map[string]dbus.Variant
		if err := object.CallWithContext(ctx, dbusGetAll, 0, realmdRealm).Store(&realm); err != nil {
			return nil, err
		}
		if configured, _ := realm["Configured"].Value().(string); configured == "" {
			continue
		}
		if err := object.CallWithContext(ctx, dbusGetAll, 0, realmdKerberos).Store(&kerberos); err != nil {
			return nil, err
		}
		entry := Realm{
			Domain: strings.ToLower(variantString(kerberos["DomainName"])),
			Name:   strings.ToUpper(variantString(kerberos["RealmName"])),
		}
		if entry.Domain == "" {
			entry.Domain = strings.ToLower(variantString(realm["Name"]))
		}
		var formats []string
		if variant, ok := realm["LoginFormats"]; ok && variant.Store(&formats) == nil {
			entry.NetBIOS = netBIOSName(formats)
		}
		var details []struct{ Key, Value string }
		if variant, ok := realm["Details"]; ok && variant.Store(&details) == nil {
			for _, detail := range details {
				switch detail.Key {
				case "server-software":
					entry.ServerSoftware = detail.Value
				case "client-software":
					entry.ClientSoftware = detail.Value
				}
			}
		}
		if entry.Domain != "" {
			realms = append(realms, entry)
		}
	}
	return realms, nil
}

func variantString(v dbus.Variant) string {
	s, _ := v.Value().(string)
	return strings.TrimSpace(s)
}

// netBIOSName reads the NetBIOS domain of a winbind realm from the login
// format realmd reports for it, the workgroup before \%U (CORP\%U). SSSD
// formats (%U@corp.example.com) and winbind with a default domain (%U)
// carry none.
func netBIOSName(formats []string) string {
	for _, format := range formats {
		if prefix, ok := strings.CutSuffix(format, `\%U`); ok && prefix != "" && !strings.ContainsAny(prefix, `\@%`) {
			return strings.ToUpper(prefix)
		}
	}
	return ""
}

// realmFor only associates a joined realm with an account when its qualified
// name identifies that realm and realmd names the account's NSS backend.
// A bare SSSD name may belong to any of several domains, including LDAP.
func realmFor(domain, source string, realms []Realm) (Realm, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	client := "sssd"
	if source == useridentity.SourceWinbind {
		client = "winbind"
	}
	var candidates []Realm
	for _, realm := range realms {
		if strings.EqualFold(realm.ClientSoftware, client) {
			candidates = append(candidates, realm)
		}
	}
	if !strings.Contains(domain, ".") {
		if client == "winbind" {
			for _, realm := range candidates {
				if domain != "" && strings.EqualFold(domain, realm.NetBIOS) {
					return realm, true
				}
			}
			// Only an unqualified winbind name can use its sole default realm.
			if domain == "" && len(candidates) == 1 {
				return candidates[0], true
			}
		}
		return Realm{}, false
	}
	best, found := Realm{}, false
	for _, realm := range candidates {
		if domain == realm.Domain {
			return realm, true
		}
		if strings.HasSuffix(domain, "."+realm.Domain) && len(realm.Domain) > len(best.Domain) {
			best, found = realm, true
		}
	}
	return best, found
}

// applyRealm adds the facts of the realm that serves an SSSD or winbind
// account: its DNS domain when a winbind name carries none or only a
// NetBIOS domain (CORP\alice), as Windows reports the same account; the Kerberos
// realm; the directory type of an Active Directory or IPA realm; and the
// sAMAccountName@REALM principal, in the UPN form, when there is none yet.
func applyRealm(facts *useridentity.DirectoryFacts, accountName string, realms []Realm) {
	realm, ok := realmFor(facts.Domain, facts.Source, realms)
	if !ok {
		return
	}
	if !strings.Contains(facts.Domain, ".") {
		facts.Domain = realm.Domain
	}
	if facts.Realm == "" {
		facts.Realm = realm.Name
	}
	switch strings.ToLower(realm.ServerSoftware) {
	case "active-directory":
		facts.Directory = useridentity.DirectoryActiveDirectory
	case "ipa":
		facts.Directory = useridentity.DirectoryLDAP
	}
	if facts.Principal == "" && facts.Realm != "" {
		bare, _ := useridentity.SplitQualifiedName(accountName)
		facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
	}
}

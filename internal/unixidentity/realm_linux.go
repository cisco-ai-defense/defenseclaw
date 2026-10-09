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
// realmd, the root system service behind `realm join` and `realm list`,
// says which Active Directory or IPA realms the host is joined to and which
// client (sssd or winbind) serves each; which realm holds an SSSD account
// comes from its SID (applySSSDDomain). Only
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

// realmFor picks the joined realm whose client (sssd or winbind) serves the
// account. A DNS domain names its realm, or for winbind the nearest parent
// realm (an Active Directory child domain); an SSSD child domain names its
// parent realm only when it is listed (sssdRealmFor). A winbind NetBIOS
// domain names the realm of that name, and an unqualified name the only winbind
// realm. An SSSD domain without a DNS name names no realm: which SSSD domain
// holds an account comes from its SID (applySSSDDomain).
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
		if client != "winbind" {
			return Realm{}, false
		}
		for _, realm := range candidates {
			if domain != "" && strings.EqualFold(domain, realm.NetBIOS) {
				return realm, true
			}
		}
		// Only an unqualified winbind name can use its sole default realm.
		if domain == "" && len(candidates) == 1 {
			return candidates[0], true
		}
		return Realm{}, false
	}
	best, found := Realm{}, false
	for _, realm := range candidates {
		if domain == realm.Domain {
			return realm, true
		}
		if client == "winbind" && strings.HasSuffix(domain, "."+realm.Domain) && len(realm.Domain) > len(best.Domain) {
			best, found = realm, true
		}
	}
	return best, found
}

// sssdRealmFor picks the joined SSSD realm of an SSSD domain: the realm of
// that DNS domain or, for a child domain the administrator lists in
// ai_discovery.trusted_ad_child_domains, the nearest joined Active Directory
// realm it is below. A child that is not listed gets none: nothing a process
// that is not root can ask proves that a domain below the joined one is a
// trusted child rather than a plain LDAP domain with that suffix (GAP-1255).
func sssdRealmFor(domain string, realms []Realm) (Realm, bool) {
	if realm, ok := realmFor(domain, useridentity.SourceSSSD, realms); ok {
		return realm, true
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !useridentity.TrustedADChildDomain(domain) {
		return Realm{}, false
	}
	best, found := Realm{}, false
	for _, realm := range realms {
		if strings.EqualFold(realm.ClientSoftware, "sssd") && realm.Domain != "" &&
			realmDirectory(realm) == useridentity.DirectoryActiveDirectory &&
			strings.HasSuffix(domain, "."+realm.Domain) && len(realm.Domain) > len(best.Domain) {
			best, found = realm, true
		}
	}
	return best, found
}

// realmDirectory is the directory type of a realm: active_directory for an
// Active Directory realm, ldap for an IPA realm, none for any other.
func realmDirectory(realm Realm) useridentity.Directory {
	switch strings.ToLower(realm.ServerSoftware) {
	case "active-directory":
		return useridentity.DirectoryActiveDirectory
	case "ipa":
		return useridentity.DirectoryLDAP
	}
	return ""
}

// applyRealm adds the facts of the realm that serves a winbind account: its
// DNS domain when the name carries none or only a NetBIOS domain
// (CORP\alice), as Windows reports the same account; the Kerberos realm; the
// directory type of an Active Directory or IPA realm; and the
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
	if directory := realmDirectory(realm); directory != "" {
		facts.Directory = directory
	}
	if facts.Principal == "" && facts.Realm != "" {
		bare, _ := useridentity.SplitQualifiedName(accountName)
		facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
	}
}

// ApplyHeldSSSDDomain gives an SSSD account without a realm the joined
// realm of the SSSD domain that a lookup by its uid places it in: InfoPipe
// Users.FindByID, which only root may call. The domain names its realm by
// its exact DNS name, as a child domain ai_discovery.trusted_ad_child_domains
// lists (sssdRealmFor), or by its Kerberos realm (kerberosRealm). It is
// how the guardian attributes an account that has no SID, such as one of an
// IPA domain without an AD trust; the gateway has no such lookup. A name
// that carries another domain (an e-mail style name) gets nothing.
func ApplyHeldSSSDDomain(ctx context.Context, facts *useridentity.DirectoryFacts, accountName, domain, kerberosRealm string) error {
	bare, nameDomain := useridentity.SplitQualifiedName(accountName)
	if facts.Realm != "" || bare == "" || strings.ContainsAny(bare, `@\`) {
		return nil
	}
	realms, err := hostRealms(ctx)
	if err != nil {
		return err
	}
	dnsDomain := strings.ToLower(strings.TrimSpace(domain))
	realm, ok := sssdRealmFor(dnsDomain, realms)
	if !ok && kerberosRealm != "" {
		for _, candidate := range realms {
			if strings.EqualFold(candidate.ClientSoftware, "sssd") && strings.EqualFold(candidate.Name, kerberosRealm) {
				realm, ok, dnsDomain = candidate, true, candidate.Domain
				break
			}
		}
	}
	if !ok || (strings.Contains(nameDomain, ".") && !strings.EqualFold(nameDomain, dnsDomain)) {
		return nil
	}
	facts.Domain = dnsDomain
	facts.Realm = strings.ToUpper(dnsDomain)
	if dnsDomain == realm.Domain && realm.Name != "" {
		facts.Realm = realm.Name
	}
	facts.Directory = realmDirectory(realm)
	facts.Principal = useridentity.AccountPrincipal(bare, facts.Realm)
	return nil
}

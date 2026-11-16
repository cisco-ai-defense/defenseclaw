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
	"os/exec"
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
	infoPipeService  = "org.freedesktop.sssd.infopipe"
	infoPipeUPNAttr  = "userPrincipalName"
	infoPipeUsers    = "/org/freedesktop/sssd/infopipe/Users"
	infoPipeFindByID = "org.freedesktop.sssd.infopipe.Users.FindByID"
	// infoPipeFindByName finds a user by name; SSSD also searches the
	// userPrincipalName of the domains for a name with an @ that names no
	// user, whatever the [ifp] user_attributes list.
	infoPipeFindByName = "org.freedesktop.sssd.infopipe.Users.FindByName"
	infoPipeNotFound   = "org.freedesktop.sssd.Error.NotFound"
	infoPipeUserIface  = "org.freedesktop.sssd.infopipe.Users.User"
	infoPipeDomIface   = "org.freedesktop.sssd.infopipe.Domains"
	dbusPropertiesGet  = "org.freedesktop.DBus.Properties.Get"
	dbusGetAll         = "org.freedesktop.DBus.Properties.GetAll"
	infoPipeCallLimit  = 5 * time.Second
	infoPipeRoot       = "/org/freedesktop/sssd/infopipe"
	// infoPipeFindDomain and infoPipeDomainOnline ask whether SSSD is
	// online for a domain, as sssctl domain-status does.
	infoPipeFindDomain   = "org.freedesktop.sssd.infopipe.FindDomainByName"
	infoPipeDomainOnline = "org.freedesktop.sssd.infopipe.Domains.Domain.IsOnline"
)

// DirectoryCachesHoldOutageAnswers is false on Linux: SSSD never lists an
// account without the name of its primary group, so the guardian starts no
// return watch (DirectoryCachesStale). The reach check (DirectoryAnswers)
// covers SSSD's outages.
const DirectoryCachesHoldOutageAnswers = false

// DirectoryAwayWithoutAnswer is true on Linux: SSSD itself reports a domain
// offline, so a domain it reports offline is away also when the guardian
// started during the outage.
const DirectoryAwayWithoutAnswer = true

// sssCacheTool is where SSSD installs sss_cache on every supported
// distribution. It writes the cache databases in /var/lib/sss/db and the
// memory cache in /var/lib/sss/mc, which the guardian unit lists in its
// ReadWritePaths (GAP-0208).
var sssCacheTool = "/usr/sbin/sss_cache"

// sssCacheTimeout bounds one sss_cache run.
const sssCacheTimeout = 30 * time.Second

// FlushDirectoryCaches marks every entry SSSD caches as expired, its memory
// cache included (sss_cache -E), which only root can do. The guardian calls
// it when SSSD is online again for a domain it reported offline: SSSD and its
// memory cache kept answering for minutes with what they held during the
// outage, for an account whose memberships SSSD never looked up its primary
// group alone, and the account stayed on the default profile (GAP-0191). An
// offline SSSD still serves expired entries, so a domain still away keeps its
// cached answers. The gateway's next lookup of an account then gets its
// groups from the directory.
func FlushDirectoryCaches(ctx context.Context) error {
	tool := trustedIdentityTool(sssCacheTool)
	if tool == "" {
		return errors.New("sss_cache is not installed as a root-owned tool")
	}
	runCtx, cancel := context.WithTimeout(ctx, sssCacheTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, tool, "-E")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s -E: %w: %s", tool, err, strings.TrimSpace(boundedOutput(out)))
	}
	return nil
}

// directoryReachDomain is the domain the guardian checks for an account's
// record: the SSSD domain InfoPipe holds its uid in.
func directoryReachDomain(record IdentitySpoolRecord) string {
	return record.SSSDDomain
}

// DirectoryAnswers reports whether SSSD is online for its domain domain. It
// is false only when InfoPipe answers that SSSD is offline for it: a host
// where InfoPipe does not answer (sssd not active, sssd_ifp not configured,
// a domain SSSD does not know) is never put in an outage by this check.
func DirectoryAnswers(ctx context.Context, domain string) bool {
	callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
	defer cancel()
	online, err := sssdDomainOnline(callCtx, domain)
	return err != nil || online
}

// sssdDomainOnline asks InfoPipe whether SSSD is online for domain
// (Domains.Domain.IsOnline, what sssctl domain-status reports). Tests
// replace it.
var sssdDomainOnline = func(ctx context.Context, domain string) (bool, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if err := infoPipeGate(sssdServiceState(ctx, conn)); err != nil {
		return false, err
	}
	var path dbus.ObjectPath
	if err := conn.Object(infoPipeService, infoPipeRoot).CallWithContext(ctx, infoPipeFindDomain, 0, domain).Store(&path); err != nil {
		return false, err
	}
	if !path.IsValid() {
		return false, errors.New("unexpected InfoPipe domain path")
	}
	var online bool
	if err := conn.Object(infoPipeService, path).CallWithContext(ctx, infoPipeDomainOnline, 0).Store(&online); err != nil {
		return false, err
	}
	return online, nil
}

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
	record := IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: nss.Name, UpdatedAt: now, AccountSID: facts.AccountSID}
	// The gateway lays the record only over the facts of the account whose
	// incarnation it names: a uid handed to another account of the same
	// name keeps its key and name (review of GAP-0551).
	incarnation, incarnationKnown := resolver.AccountIncarnation(account.UID, nss.Name)
	if incarnationKnown {
		record.AccountIncarnation = incarnation
	}
	if facts.Source != useridentity.SourceSSSD && facts.Source != useridentity.SourceWinbind {
		record.Facts = facts
		return record, nil
	}
	if !incarnationKnown {
		record.Facts = facts
		return record, fmt.Errorf("cannot tell which account holds uid %d (the NSS service that answers it, or the SID SSSD holds for it)", account.UID)
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

// bindIdentitySpoolUPN asks InfoPipe which user holds upn (Users.FindByName)
// and compares its uid and SSSD domain with the account's. SSSD resolves a
// UPN through its directory search, so the answer does not depend on the
// [ifp] user_attributes listing userPrincipalName: the lost attribute that
// sends the guardian here (GAP-1114) does not hide it. A user found under
// another uid or domain holds the UPN instead: UPNBindingOther. A not-found
// answer is UPNBindingOther only when notFoundIsOther (an Active Directory
// account, whose domain SSSD searches by UPN); any other error is
// UPNBindingUnknown.
func bindIdentitySpoolUPN(ctx context.Context, uid int, sssdDomain, upn string, notFoundIsOther bool) UPNBinding {
	upn = strings.TrimSpace(upn)
	if upn == "" || sssdDomain == "" {
		return UPNBindingUnknown
	}
	callCtx, cancel := context.WithTimeout(ctx, infoPipeCallLimit)
	defer cancel()
	heldUID, domain, err := infoPipeUserByName(callCtx, upn)
	var dbusErr dbus.Error
	switch {
	case err == nil && heldUID == uid && strings.EqualFold(domain, sssdDomain):
		return UPNBindingBound
	case err == nil:
		return UPNBindingOther
	case notFoundIsOther && callCtx.Err() == nil && errors.As(err, &dbusErr) && dbusErr.Name == infoPipeNotFound:
		return UPNBindingOther
	}
	return UPNBindingUnknown
}

// infoPipeUserByName asks InfoPipe for the uid and SSSD domain of the user
// name names. Tests replace it.
var infoPipeUserByName = func(ctx context.Context, name string) (int, string, error) {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	if err := infoPipeGate(sssdServiceState(ctx, conn)); err != nil {
		return 0, "", err
	}
	var user dbus.ObjectPath
	if err := conn.Object(infoPipeService, infoPipeUsers).CallWithContext(ctx, infoPipeFindByName, 0, name).Store(&user); err != nil {
		return 0, "", err
	}
	userObject := conn.Object(infoPipeService, user)
	var uidNumber dbus.Variant
	if err := userObject.CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeUserIface, "uidNumber").Store(&uidNumber); err != nil {
		return 0, "", err
	}
	uid, ok := uidNumber.Value().(uint32)
	if !ok || uid == 0 || uint64(uid) > math.MaxInt32 {
		return 0, "", errors.New("unexpected InfoPipe uidNumber")
	}
	var domain dbus.Variant
	if err := userObject.CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeUserIface, "domain").Store(&domain); err != nil {
		return 0, "", err
	}
	domainPath, ok := domain.Value().(dbus.ObjectPath)
	if !ok || !domainPath.IsValid() {
		return 0, "", errors.New("unexpected InfoPipe user domain")
	}
	var domainName dbus.Variant
	if err := conn.Object(infoPipeService, domainPath).CallWithContext(ctx, dbusPropertiesGet, 0, infoPipeDomIface, "name").Store(&domainName); err != nil {
		return 0, "", err
	}
	held, _ := domainName.Value().(string)
	if held = strings.TrimSpace(held); held == "" {
		return 0, "", errors.New("unexpected InfoPipe domain name")
	}
	return int(uid), held, nil
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

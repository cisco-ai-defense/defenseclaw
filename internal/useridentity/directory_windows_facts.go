// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"strings"
	"time"
)

// Windows directory facts, verified.
//
// The gateway and the SYSTEM enumerator resolve them for a SID the kernel or
// a per-user credential already verified, from OS state only:
//
//   - LookupAccountSid names the account and its domain; the domain equals
//     the computer name for a local account.
//   - The identity store, HKLM\SOFTWARE\Microsoft\IdentityStore\Cache\<SID>\
//     IdentityCache\<SID>, holds the UPN of a cloud sign-in (UserName) and
//     the provider that issued it (ProviderName, "AzureAD" for Entra ID).
//   - CloudDomainJoin\JoinInfo\<thumbprint> (TenantId) and TenantInfo say the
//     device is Entra joined, and NetGetJoinInformation says it is AD
//     joined; both together is a hybrid join.
//   - An AD account's UPN comes from TranslateNameW, which may contact a
//     domain controller, so callers run it in the background and cache it.
//
// The parsing is here, behind windowsDirectoryReader, so it is tested on
// every platform; directory_windows.go supplies the real reader.

const (
	identityStoreCacheKey = `SOFTWARE\Microsoft\IdentityStore\Cache`
	cloudJoinInfoKey      = `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`
	cloudTenantInfoKey    = `SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo`
	entraProviderName     = "AzureAD"
	entraUserSIDPrefix    = "S-1-12-1-"
)

// windowsDirectoryReader is the OS state the Windows resolver reads.
type windowsDirectoryReader interface {
	// StringValue reads one REG_SZ value under HKLM.
	StringValue(path, name string) (string, bool)
	// SubKeys lists the subkeys of an HKLM key.
	SubKeys(path string) []string
	// LookupAccount resolves a SID to its account and domain names.
	LookupAccount(sid string) (account, domain string, ok bool)
	// ComputerName is the NetBIOS computer name.
	ComputerName() string
	// DomainJoin reports the NetBIOS name of the AD domain the machine is
	// joined to, if any.
	DomainJoin() (domain string, joined bool)
	// DNSDomain is the machine's DNS domain (the AD domain's DNS name on a
	// joined machine), or "".
	DNSDomain() string
}

// windowsJoinState is the machine's join state: the Entra tenant and the AD
// domain it is joined to, either or both.
type windowsJoinState struct {
	TenantID  string
	ADDomain  string
	DNSDomain string
}

func readWindowsJoinState(r windowsDirectoryReader) windowsJoinState {
	var state windowsJoinState
	for _, thumbprint := range r.SubKeys(cloudJoinInfoKey) {
		if tenant, ok := r.StringValue(cloudJoinInfoKey+`\`+thumbprint, "TenantId"); ok && validTenantID(tenant) {
			state.TenantID = strings.ToLower(strings.TrimSpace(tenant))
			break
		}
	}
	if state.TenantID == "" {
		// Older builds record only TenantInfo\<tenant id>.
		for _, tenant := range r.SubKeys(cloudTenantInfoKey) {
			if validTenantID(tenant) {
				state.TenantID = strings.ToLower(strings.TrimSpace(tenant))
				break
			}
		}
	}
	domain, adJoined := r.DomainJoin()
	if adJoined {
		state.ADDomain = strings.TrimSpace(domain)
		state.DNSDomain = strings.TrimSpace(r.DNSDomain())
	}
	return state
}

// identityStoreUPN reads the cloud sign-in UPN and provider recorded for sid.
func identityStoreUPN(r windowsDirectoryReader, sid string) (upn, provider string) {
	key := identityStoreCacheKey + `\` + sid + `\IdentityCache\` + sid
	name, _ := r.StringValue(key, "UserName")
	provider, _ = r.StringValue(key, "ProviderName")
	return NormalizeUPN(name), strings.TrimSpace(provider)
}

// resolveWindowsDirectoryFacts resolves the verified directory facts of sid.
// adUPN, when non-nil, returns a cached TranslateNameW answer for a
// DOMAIN\account name (it must not block).
func resolveWindowsDirectoryFacts(
	r windowsDirectoryReader,
	sid string,
	adUPN func(samName string) string,
	now time.Time,
) DirectoryFacts {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	facts := DirectoryFacts{Source: SourceWindowsLSA, Assurance: AssuranceVerified, ResolvedAt: now}
	if !strings.HasPrefix(sid, "S-1-") {
		return DirectoryFacts{}
	}
	join := readWindowsJoinState(r)
	account, domain, ok := r.LookupAccount(sid)
	upn, provider := identityStoreUPN(r, sid)
	switch {
	case strings.HasPrefix(sid, entraUserSIDPrefix) || (strings.EqualFold(provider, entraProviderName) && !ok):
		// An Entra ID account (S-1-12-1-...) has no domain account; its UPN
		// is in the identity store.
		facts.Directory = DirectoryEntraID
		facts.TenantID = join.TenantID
		if upn != "" {
			facts.UPN = upn
			facts.Source = SourceWindowsIdentityStore
		}
	case ok && strings.EqualFold(domain, r.ComputerName()):
		facts.Directory = DirectoryLocal
	case ok && domain != "":
		// The domain is reported in lower case, by its DNS name when it is
		// the machine's own domain, as SSSD and winbind report it on
		// Linux; LookupAccountSid gives only the NetBIOS name.
		facts.Directory = DirectoryActiveDirectory
		facts.Domain = strings.ToLower(domain)
		if upn != "" && strings.EqualFold(provider, entraProviderName) {
			// A hybrid user signed in to Entra: the identity store has the
			// cloud UPN, which is the synced AD UPN.
			facts.UPN = upn
			facts.TenantID = join.TenantID
			facts.Source = SourceWindowsIdentityStore
		} else if adUPN != nil && account != "" {
			facts.UPN = NormalizeUPN(adUPN(domain + `\` + account))
		}
		if join.DNSDomain != "" && strings.EqualFold(domain, join.ADDomain) {
			// The account is in the machine's own domain, whose DNS name
			// is the Kerberos realm.
			facts.Realm = strings.ToUpper(join.DNSDomain)
			facts.Domain = strings.ToLower(join.DNSDomain)
		}
	default:
		return DirectoryFacts{}
	}
	facts.Principal = facts.UPN
	if facts.Principal == "" && facts.Realm != "" && account != "" {
		facts.Principal = NormalizePrincipal(account + "@" + facts.Realm)
	}
	if facts.Domain == "" && facts.UPN != "" {
		facts.Domain = strings.ToLower(facts.UPN[strings.LastIndexByte(facts.UPN, '@')+1:])
	}
	return facts
}

// validTenantID accepts the GUID-shaped tenant ids the join state records.
func validTenantID(id string) bool {
	id = strings.TrimSpace(id)
	if len(id) < 8 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '-') {
			return false
		}
	}
	return true
}

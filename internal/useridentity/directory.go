// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "time"

// Assurance says who vouches for a directory or session fact. It is the Go
// side of the v8 defenseclaw.user.principal.assurance enum.
type Assurance string

const (
	// AssuranceVerified marks facts the gateway or the root enumerator
	// resolved for a uid or SID that the kernel (peer credentials) or a
	// per-user credential already verified. Only verified facts may select
	// a guardrail profile.
	AssuranceVerified Assurance = "verified"
	// AssuranceClaimed marks facts the hook reported from inside the user's
	// session (the Kerberos credential cache, SSH_CONNECTION, the logon
	// session). They are attribution only and never select a profile.
	AssuranceClaimed Assurance = "claimed"
)

// Directory names the directory that owns an account. It is the Go side of
// the v8 defenseclaw.user.directory enum. Values are read from the OS only;
// DefenseClaw never calls an identity-provider API.
type Directory string

const (
	// DirectoryLocal is an account in the machine's own account database
	// (/etc/passwd, the local SAM, the local macOS node).
	DirectoryLocal Directory = "local"
	// DirectoryLDAP is an account served by a plain LDAP directory through
	// NSS (sssd's ldap provider or nss_ldap).
	DirectoryLDAP Directory = "ldap"
	// DirectoryActiveDirectory is an Active Directory account: Linux via
	// SSSD or winbind, a domain-joined Windows host, or an AD-bound Mac.
	DirectoryActiveDirectory Directory = "active_directory"
	// DirectoryEntraID is a Microsoft Entra ID account: an Entra-joined or
	// hybrid-joined Windows host, macOS Platform SSO, or a Linux NSS module
	// for Entra.
	DirectoryEntraID Directory = "entra_id"
	// DirectoryOkta is an Okta account surfaced through the OS (macOS
	// Platform SSO or Okta Device Access, or an Okta NSS agent on Linux).
	DirectoryOkta Directory = "okta"
	// DirectoryOther is a directory the OS reports that is none of the
	// above, for example an unrecognised NSS module.
	DirectoryOther Directory = "other"
)

// SessionKind is the kind of login session an agent runs in. It is the Go
// side of the v8 defenseclaw.session.kind enum.
type SessionKind string

const (
	// SessionLocal is a local graphical or terminal session on the machine.
	SessionLocal SessionKind = "local"
	// SessionSSH is a session opened over SSH.
	SessionSSH SessionKind = "ssh"
	// SessionRDP is a Windows Remote Desktop session.
	SessionRDP SessionKind = "rdp"
	// SessionConsole is a text console (a physical or virtual TTY) with no
	// graphical session.
	SessionConsole SessionKind = "console"
)

// Identity sources: values of the v8 defenseclaw.user.identity.source
// attribute, naming the OS facility that resolved DirectoryFacts. The
// registry accepts any bounded lowercase token, so a new source does not
// need a registry change; prefer one of these when it fits.
const (
	SourceNSSFiles             = "nss_files"
	SourceSSSD                 = "sssd"
	SourceSSSDInfoPipe         = "sssd_infopipe"
	SourceWinbind              = "winbind"
	SourceNSSLDAP              = "nss_ldap"
	SourceWindowsLSA           = "windows_lsa"
	SourceWindowsIdentityStore = "windows_identity_store"
	SourceMacOSOpenDirectory   = "macos_opendirectory"
	SourceMacOSPlatformSSO     = "macos_platform_sso"
	SourceHookReported         = "hook_reported"
)

// DirectoryFacts are the directory attributes of one end-user account,
// keyed by the uid or SID that Identity.ID carries.
//
// Every field is optional and an empty value is an ordinary outcome: report
// what resolved and omit the rest, because a wrong attribution is worse than
// an absent one. Assurance applies to the whole record; a record that mixes
// verified and claimed inputs is claimed.
type DirectoryFacts struct {
	// Principal is the qualified principal DefenseClaw reports as
	// defenseclaw.user.principal: the UPN when known, else the Kerberos
	// principal, else DOMAIN-qualified account name.
	Principal string `json:"principal,omitempty"`
	// UPN is the userPrincipalName when the directory exposes one (SSSD
	// InfoPipe, the Windows identity store, TranslateNameW).
	UPN string `json:"upn,omitempty"`
	// Domain is the account's domain in lower case, by its DNS name where
	// the OS knows it, else its NetBIOS name (defenseclaw.user.domain).
	Domain string `json:"domain,omitempty"`
	// Realm is the Kerberos realm, usually the upper-case DNS domain.
	Realm string `json:"realm,omitempty"`
	// Directory is the directory that owns the account.
	Directory Directory `json:"directory,omitempty"`
	// TenantID is the cloud tenant (for example the Entra tenant GUID)
	// from the OS join state (defenseclaw.user.tenant_id).
	TenantID string `json:"tenant_id,omitempty"`
	// Groups are the account's group identifiers (SIDs on Windows, group
	// names or gids elsewhere). Telemetry carries only their count.
	Groups []string `json:"groups,omitempty"`
	// GroupsPartial marks Windows groups the SYSTEM enumerator took from the
	// account's last signed-in session token, not a current one: it had no
	// active session then, so a group change since is not in them. A cache
	// refreshes such facts soon, and explain says the profile is not final
	// (GAP-0243).
	GroupsPartial bool `json:"groups_partial,omitempty"`
	// Source is the OS facility that resolved these facts, one of the
	// Source* constants (defenseclaw.user.identity.source).
	Source string `json:"source,omitempty"`
	// Assurance says whether DefenseClaw verified the facts or the hook
	// claimed them.
	Assurance Assurance `json:"assurance,omitempty"`
	// ResolvedAt is when the facts were resolved; caches use it for their
	// time-to-live.
	ResolvedAt time.Time `json:"resolved_at,omitzero"`
}

// Empty reports whether no directory fact resolved.
func (f DirectoryFacts) Empty() bool {
	return f.Principal == "" && f.UPN == "" && f.Domain == "" && f.Realm == "" &&
		f.Directory == "" && f.TenantID == "" && len(f.Groups) == 0
}

// SessionFacts describe the login session an agent runs in.
//
// The hook reports them from inside the session, so they start out claimed.
// The gateway upgrades Kind and ClientAddr to verified only when it confirms
// them itself for the verified uid (logind GetSession or /run/utmp on Linux).
// KerberosPrincipal is always claimed.
type SessionFacts struct {
	// Kind is the session kind (defenseclaw.session.kind).
	Kind SessionKind `json:"kind,omitempty"`
	// ClientAddr is the remote address of the session, for example the
	// SSH client IP (client.address).
	ClientAddr string `json:"client_addr,omitempty"`
	// TTY is the controlling terminal, for example "pts/3".
	TTY string `json:"tty,omitempty"`
	// LogindSession is the systemd-logind session id (XDG_SESSION_ID).
	LogindSession string `json:"logind_session,omitempty"`
	// KerberosPrincipal is the default principal of the session's
	// credential cache (defenseclaw.session.kerberos_principal).
	KerberosPrincipal string `json:"kerberos_principal,omitempty"`
	// CCacheType is the credential cache type the principal was read from:
	// "FILE", "KCM", "KEYRING" or "API".
	CCacheType string `json:"ccache_type,omitempty"`
	// Assurance says whether the gateway verified the session or the hook
	// claimed it.
	Assurance Assurance `json:"assurance,omitempty"`
}

// Empty reports whether no session fact resolved.
func (s SessionFacts) Empty() bool {
	return s.Kind == "" && s.ClientAddr == "" && s.TTY == "" && s.LogindSession == "" &&
		s.KerberosPrincipal == "" && s.CCacheType == ""
}

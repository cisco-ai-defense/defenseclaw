// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"net"
	"strings"
)

// SessionFactsHeader carries the session facts a hook reports from inside
// the user's session. It is one header, so a hook adds a single bounded
// value to every call:
//
//	X-DefenseClaw-Session-Facts: v1;k=ssh;tty=pts/3;ls=12;ca=192.0.2.10;krb=alice@CORP.EXAMPLE;cc=KCM
//
// Keys: k (session kind), tty, ls (logind session id), ca (client address
// from SSH_CONNECTION), krb (Kerberos default principal), cc (credential
// cache type), upn (the logon session's UPN on Windows). Unknown keys are
// ignored, so a newer hook can talk to an older gateway.
//
// Everything in it is claimed: any local process can send it. The gateway
// uses it for attribution only and never lets it change a verified fact.
const SessionFactsHeader = "X-DefenseClaw-Session-Facts"

const (
	sessionFactsVersion     = "v1"
	maxSessionFactsHeader   = 1024
	maxSessionFactValueSize = 256
)

// sessionFactValueOK is the header's allowlisted charset: letters, digits
// and . _ @ / : - only. Nothing legitimate in a tty, a session id, an
// address or a principal needs more, and nothing outside it can break a
// header, a log line or the ; and = framing.
func sessionFactValueOK(value string) bool {
	if value == "" || len(value) > maxSessionFactValueSize {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '@', c == '/', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// ClaimedSessionHeader is SessionFacts plus the hook's claimed UPN, the
// whole content of one X-DefenseClaw-Session-Facts value.
type ClaimedSessionHeader struct {
	Session SessionFacts
	// UPN is the UPN of the hook's Windows logon session; empty elsewhere.
	UPN string
}

// EncodeSessionFactsHeader renders facts as a header value. Values outside
// the allowlist are dropped; an empty result means there is nothing to send.
func EncodeSessionFactsHeader(facts ClaimedSessionHeader) string {
	parts := []string{sessionFactsVersion}
	add := func(key, value string) {
		if sessionFactValueOK(value) {
			parts = append(parts, key+"="+value)
		}
	}
	s := facts.Session
	add("k", string(validSessionKind(s.Kind)))
	add("tty", s.TTY)
	add("ls", s.LogindSession)
	add("ca", validClientAddr(s.ClientAddr))
	add("krb", s.KerberosPrincipal)
	add("cc", validCCacheType(s.CCacheType))
	add("upn", facts.UPN)
	if len(parts) == 1 {
		return ""
	}
	value := strings.Join(parts, ";")
	if len(value) > maxSessionFactsHeader {
		return ""
	}
	return value
}

// ParseSessionFactsHeader parses a header value. ok is false for an absent,
// oversized or unversioned value. The facts are always claimed.
func ParseSessionFactsHeader(value string) (ClaimedSessionHeader, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxSessionFactsHeader {
		return ClaimedSessionHeader{}, false
	}
	parts := strings.Split(value, ";")
	if parts[0] != sessionFactsVersion {
		return ClaimedSessionHeader{}, false
	}
	var out ClaimedSessionHeader
	for _, part := range parts[1:] {
		key, val, found := strings.Cut(part, "=")
		if !found || !sessionFactValueOK(val) {
			continue
		}
		switch key {
		case "k":
			out.Session.Kind = validSessionKind(SessionKind(val))
		case "tty":
			out.Session.TTY = val
		case "ls":
			out.Session.LogindSession = val
		case "ca":
			out.Session.ClientAddr = validClientAddr(val)
		case "krb":
			out.Session.KerberosPrincipal = NormalizePrincipal(val)
		case "cc":
			out.Session.CCacheType = validCCacheType(val)
		case "upn":
			out.UPN = NormalizeUPN(val)
		}
	}
	if out.Session.Empty() && out.UPN == "" {
		return ClaimedSessionHeader{}, false
	}
	out.Session.Assurance = AssuranceClaimed
	return out, true
}

func validSessionKind(kind SessionKind) SessionKind {
	switch kind {
	case SessionLocal, SessionSSH, SessionRDP, SessionConsole:
		return kind
	}
	return ""
}

// validClientAddr keeps only a literal IP address.
func validClientAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return ""
}

// CCache types DefenseClaw reports.
const (
	CCacheFile    = "FILE"
	CCacheDir     = "DIR"
	CCacheKCM     = "KCM"
	CCacheKeyring = "KEYRING"
	CCacheAPI     = "API"
	CCacheMSLSA   = "MSLSA"
)

func validCCacheType(kind string) string {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case CCacheFile:
		return CCacheFile
	case CCacheDir:
		return CCacheDir
	case CCacheKCM:
		return CCacheKCM
	case CCacheKeyring:
		return CCacheKeyring
	case CCacheAPI:
		return CCacheAPI
	case CCacheMSLSA:
		return CCacheMSLSA
	}
	return ""
}

// SessionFromSSHEnv derives claimed session facts from the SSH and logind
// variables of a hook's environment: SSH_CONNECTION ("client port server
// port"), SSH_TTY and XDG_SESSION_ID. getenv is os.Getenv in production.
func SessionFromSSHEnv(getenv func(string) string) SessionFacts {
	var facts SessionFacts
	if conn := strings.Fields(getenv("SSH_CONNECTION")); len(conn) >= 1 {
		facts.ClientAddr = validClientAddr(conn[0])
		facts.Kind = SessionSSH
	}
	if tty := strings.TrimSpace(getenv("SSH_TTY")); tty != "" {
		facts.TTY = strings.TrimPrefix(tty, "/dev/")
		facts.Kind = SessionSSH
	}
	if id := strings.TrimSpace(getenv("XDG_SESSION_ID")); sessionFactValueOK(id) {
		facts.LogindSession = id
	}
	if facts.Kind == "" && !facts.Empty() {
		facts.Kind = SessionLocal
	}
	if !sessionFactValueOK(facts.TTY) {
		facts.TTY = ""
	}
	return facts
}

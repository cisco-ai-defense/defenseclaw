// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
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

// sessionFactValueOK accepts the original ASCII header charset for session
// fields. Principal fields use sessionPrincipalWireValue for Unicode.
func sessionFactValueOK(value string) bool {
	if value == "" || len(value) > maxSessionFactValueSize {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !sessionFactByteOK(value[i]) {
			return false
		}
	}
	return true
}

// sessionPrincipalWireValue escapes UTF-8 bytes while leaving the original
// ASCII header syntax unchanged. Re-encoding after parsing rejects escaped
// delimiters, controls, and non-canonical encodings.
func sessionPrincipalWireValue(value string) string {
	if value == "" || len(value) > maxSessionFactValueSize || !utf8.ValidString(value) {
		return ""
	}
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, r := range value {
		if r < utf8.RuneSelf {
			c := byte(r)
			if !sessionFactByteOK(c) {
				return ""
			}
			b.WriteByte(c)
		} else {
			if !unicode.IsPrint(r) || unicode.IsSpace(r) {
				return ""
			}
			var bytes [utf8.UTFMax]byte
			n := utf8.EncodeRune(bytes[:], r)
			for _, c := range bytes[:n] {
				b.WriteByte('%')
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			}
		}
	}
	return b.String()
}

func parseSessionPrincipalWireValue(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil || sessionPrincipalWireValue(decoded) != value {
		return ""
	}
	return decoded
}

func sessionFactByteOK(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '.' || c == '_' ||
		c == '@' || c == '/' || c == ':' || c == '-'
}

// ClaimedSessionHeader is SessionFacts plus the hook's claimed UPN, the
// whole content of one X-DefenseClaw-Session-Facts value.
type ClaimedSessionHeader struct {
	Session SessionFacts
	// UPN is the UPN of the hook's Windows logon session; empty elsewhere.
	UPN string
}

// EncodeSessionFactsHeader renders facts as an ASCII header value. Unsafe
// values are dropped; Unicode principal bytes are percent-encoded.
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
	if value := sessionPrincipalWireValue(s.KerberosPrincipal); value != "" {
		parts = append(parts, "krb="+value)
	}
	add("cc", validCCacheType(s.CCacheType))
	if value := sessionPrincipalWireValue(facts.UPN); value != "" {
		parts = append(parts, "upn="+value)
	}
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
		if !found {
			continue
		}
		if key == "krb" || key == "upn" {
			val = parseSessionPrincipalWireValue(val)
		} else if !sessionFactValueOK(val) {
			continue
		}
		if val == "" {
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

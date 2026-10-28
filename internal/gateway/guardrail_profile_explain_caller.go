// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// ProfileExplainCallerFacts are the account facts the administrator's own
// `enterprise linux|macos profile-explain` resolved as root through NSS
// (getpwnam or getpwuid, then getgrouplist and the directory's proofs),
// passed to the explain route as caller_facts. The managed gateway runs as
// a service account that cannot ask SSSD whether its domains are online or
// read sssd.conf, so its own lookup of a fresh local account stopped at
// default_lookup_failed (GAP-0500). Explain uses these facts first and its
// own lookup as the fallback. They decide only the explain answer: they
// never reach the identity cache the hooks read, and the route takes them
// only with the gateway token, on loopback.
type ProfileExplainCallerFacts struct {
	UID   int                         `json:"uid"`
	Name  string                      `json:"name"`
	Facts useridentity.DirectoryFacts `json:"facts"`
}

// EncodeProfileExplainCallerFacts is the caller_facts query value of facts.
func EncodeProfileExplainCallerFacts(facts ProfileExplainCallerFacts) (string, error) {
	data, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// profileExplainCallerFactsMax bounds a caller_facts value.
const profileExplainCallerFactsMax = 64 << 10

// profileExplainCallerSubject is the subject of the caller's facts raw for
// the account user names (its name or uid), and false when raw is absent,
// malformed, unresolved, or names another account.
func profileExplainCallerSubject(raw, user string) (profileSubject, bool) {
	raw, user = strings.TrimSpace(raw), strings.TrimSpace(user)
	if raw == "" || len(raw) > profileExplainCallerFactsMax || user == "" {
		return profileSubject{}, false
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return profileSubject{}, false
	}
	var caller ProfileExplainCallerFacts
	if json.Unmarshal(data, &caller) != nil || caller.UID < 0 || strings.TrimSpace(caller.Name) == "" || caller.Facts.ResolvedAt.IsZero() {
		return profileSubject{}, false
	}
	id := strconv.Itoa(caller.UID)
	if user != id && !strings.EqualFold(user, caller.Name) {
		return profileSubject{}, false
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindPOSIXUID, UserName: caller.Name, Directory: caller.Facts,
	}, false)
	subject.accountName = caller.Name
	// A group list the caller's lookup could not finish is unknown, as it
	// is for a hook: explain must not read it as no groups.
	subject.GroupsUnknown = caller.Facts.GroupsPartial
	return subject, true
}

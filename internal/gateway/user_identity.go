// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// llmEventUser is the end-user attribution DefenseClaw attaches to one v8
// record. Every field is optional; an unattributed record is emitted rather
// than a wrongly attributed one.
type llmEventUser struct {
	ID     string
	IDKind string
	Name   string
	Email  string
}

// userEmailTTL bounds how long a resolved address is reused.
//
// The address changes only when a user signs into a different account, so a
// short cache costs nothing in freshness. It exists because the alternative is
// opening and JSON-parsing a credential file on every hook event, which is the
// hottest path in the product.
const userEmailTTL = 5 * time.Minute

// userEmailCacheMax bounds the number of (connector, user) pairs held. The key
// space is attacker-influenced only to the extent that a local user can invent
// connector names, so the cap keeps that from growing memory without bound.
const userEmailCacheMax = 512

type userEmailCacheEntry struct {
	email    string
	resolved time.Time
}

var (
	userEmailMu    sync.Mutex
	userEmailCache = map[string]userEmailCacheEntry{}
)

// resolveHookUserIdentity determines which end user a hook event belongs to.
//
// Precedence is deliberate. The identity headers come from the hook process,
// which is the only participant that runs inside the user's session, so they
// are preferred. The hook payload is agent-controlled and is consulted only as
// a fallback for connectors that report a user natively. Both are attribution
// evidence, not authentication: the gateway's loopback listener is reachable by
// any local process.
func resolveHookUserIdentity(ctx context.Context, connector string, payload map[string]interface{}) llmEventUser {
	user := resolveHookUser(ctx, payload)
	user.Email = hookUserEmail(connector, user.ID, payload)
	return user
}

// resolveHookUser resolves the identifier and account name without touching
// the filesystem. Callers that only need a registry join key use this: the
// address lookup in resolveHookUserIdentity reads a credential file, which is
// wasted work on a path that has nowhere to put the result.
func resolveHookUser(ctx context.Context, payload map[string]interface{}) llmEventUser {
	fromHeaders := AgentIdentityFromContext(ctx)
	payloadID, payloadName := userFieldsFromHookPayload(payload)
	return newLLMEventUser(
		firstNonEmpty(fromHeaders.UserID, payloadID),
		firstNonEmpty(fromHeaders.UserName, payloadName),
	)
}

// resolveHTTPUserIdentity determines the end user behind a proxied or ingested
// HTTP request. The email is not resolved here: this path serves LLM proxy and
// OTLP ingest traffic, where the caller is a library rather than a connector
// with a local credential file to read.
func resolveHTTPUserIdentity(r *http.Request, rawBody []byte) llmEventUser {
	userID := firstNonEmpty(
		r.Header.Get(llmEventUserIDHeader),
		r.Header.Get("X-User-Id"),
		r.Header.Get("X-User-ID"),
		r.Header.Get("X-User"),
	)
	userName := firstNonEmpty(
		r.Header.Get(llmEventUserNameHeader),
		r.Header.Get("X-User-Name"),
		r.Header.Get("X-Username"),
	)
	if len(rawBody) > 0 {
		var body struct {
			User     string `json:"user"`
			UserID   string `json:"user_id"`
			UserName string `json:"user_name"`
			Username string `json:"username"`
		}
		if json.Unmarshal(rawBody, &body) == nil {
			userID = firstNonEmpty(userID, body.UserID, body.User)
			userName = firstNonEmpty(userName, body.UserName, body.Username)
		}
	}
	return newLLMEventUser(userID, userName)
}

// newLLMEventUser sanitizes a resolved pair, classifies the identifier, and
// applies the local fallback.
func newLLMEventUser(userID, userName string) llmEventUser {
	userID = sanitizeLLMEventUser(userID)
	userName = sanitizeLLMEventUser(userName)
	if userID == "" && userName == "" {
		userID, userName = localProcessUser()
	}
	return llmEventUser{
		ID: userID,
		// Classified rather than asserted. A payload can carry an arbitrary
		// string here — a login name, an opaque token — and labelling that
		// posix_uid would put a value into the v8 enum that consumers then
		// join on as a uid.
		IDKind: useridentity.KindForID(userID),
		Name:   userName,
	}
}

// localProcessUser reports the gateway's own OS user, and only when that is
// meaningful.
//
// Under a managed install the gateway runs as a service account — LocalSystem
// on Windows, a daemon account on macOS — so its own identity is not the end
// user's, and reporting it would attribute every event on a multi-user
// endpoint to one service principal. Under an unmanaged install the gateway
// runs as the person using it, and its identity is the right answer for
// traffic that carries none of its own.
func localProcessUser() (string, string) {
	if ManagedEnterpriseActive() {
		return "", ""
	}
	current, err := osuser.Current()
	if err != nil || current == nil {
		return "", ""
	}
	return sanitizeLLMEventUser(firstNonEmpty(current.Uid, current.Username)),
		sanitizeLLMEventUser(firstNonEmpty(current.Username, current.Name, current.Uid))
}

// userFieldsFromHookPayload pulls the user fields a connector may report in
// its own hook JSON. It performs no fallback: the caller ranks these below the
// hook's identity headers.
func userFieldsFromHookPayload(payload map[string]interface{}) (string, string) {
	if payload == nil {
		return "", ""
	}
	userID := firstNonEmpty(
		stringMapValue(payload, "user_id"),
		stringMapValue(payload, "user"),
		stringMapValue(payload, "actor"),
		stringMapValue(payload, "login"),
	)
	if userID == "" {
		if email := strings.TrimSpace(strings.ToLower(stringMapValue(payload, "user_email"))); email != "" {
			userID = stableLLMEventID("user", email)
		}
	}
	userName := firstNonEmpty(
		stringMapValue(payload, "user_name"),
		stringMapValue(payload, "username"),
		stringMapValue(payload, "user_login"),
	)
	return userID, userName
}

// hookUserEmail resolves the signed-in account for one hook event.
//
// The profile directory is derived from the reported OS user id rather than
// taken from the hook, so a hook cannot aim the read at another user's files.
// An id the gateway cannot classify yields no address at all: without a real
// SID or uid there is no profile to attribute an address to.
func hookUserEmail(connector, userID string, payload map[string]interface{}) string {
	connector = strings.TrimSpace(connector)
	if connector == "" {
		return ""
	}
	// Connectors that report the address in the payload need no file read and
	// no cache: the value arrives with the event.
	if raw, err := json.Marshal(payload); err == nil {
		if email, err := useridentity.EmailForConnector(connector, "", raw); err == nil {
			return email
		}
	}
	if useridentity.KindForID(userID) == "" {
		return ""
	}
	return cachedUserEmail(connector, userID)
}

func cachedUserEmail(connector, userID string) string {
	key := connector + "\x00" + userID
	now := time.Now()

	userEmailMu.Lock()
	if entry, ok := userEmailCache[key]; ok && now.Sub(entry.resolved) < userEmailTTL {
		userEmailMu.Unlock()
		return entry.email
	}
	userEmailMu.Unlock()

	// Resolved outside the lock: this opens and parses a file, and holding the
	// mutex across it would serialize every hook event on the endpoint behind
	// one user's disk read.
	email := ""
	if home := useridentity.HomeForID(userID); home != "" {
		if resolved, err := useridentity.EmailForConnector(connector, home, nil); err == nil {
			email = resolved
		}
	}

	userEmailMu.Lock()
	defer userEmailMu.Unlock()
	// A negative result is cached too. Most endpoints have no readable
	// credential for most connectors, and without this the miss path would
	// stat a missing file on every single event.
	if len(userEmailCache) >= userEmailCacheMax {
		if _, refresh := userEmailCache[key]; !refresh {
			userEmailCache = map[string]userEmailCacheEntry{}
		}
	}
	userEmailCache[key] = userEmailCacheEntry{email: email, resolved: now}
	return email
}

// v8UserEmailPattern mirrors the normalization override the telemetry registry
// declares for defenseclaw.user.email.
//
// It is duplicated here on purpose. The registry pattern is stricter than what
// useridentity accepts — it requires a dotted TLD — and a value the builder
// rejects is a build failure, not a dropped field. Checking first means an
// unusual address costs the record its email attribute rather than the whole
// record.
var v8UserEmailPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}$`)

// v8UserEmailMaxBytes is the registry's max_utf8_bytes for the same attribute.
const v8UserEmailMaxBytes = 254

// v8UserEmail renders an address for a v8 builder input.
func v8UserEmail(email string) observability.Optional[string] {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > v8UserEmailMaxBytes || !v8UserEmailPattern.MatchString(email) {
		return observability.Absent[string]()
	}
	return observability.Present(email)
}

// v8UserIDKind renders the id namespace for a v8 builder input. The attribute
// is a closed enum, so anything outside it is omitted rather than passed
// through.
func v8UserIDKind(kind string) observability.Optional[string] {
	switch kind {
	case useridentity.KindWindowsSID, useridentity.KindPOSIXUID:
		return observability.Present(kind)
	default:
		return observability.Absent[string]()
	}
}

// resetUserEmailCacheForTest clears the resolved-address cache.
func resetUserEmailCacheForTest() {
	userEmailMu.Lock()
	defer userEmailMu.Unlock()
	userEmailCache = map[string]userEmailCacheEntry{}
}

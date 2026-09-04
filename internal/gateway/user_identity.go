// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

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

// userEmailCollectionEnabled mirrors ai_discovery.include_user_email at the
// gateway-package level so the two emission sites can consult it without
// threading config through every hook and inventory call path.
//
// Wired from ai_discovery by NewSidecar and applyConfigReload, alongside
// setManagedEnterpriseRedactionPosture. Reads use atomic.Bool so request hot
// paths stay lock-free.
var userEmailCollectionEnabled atomic.Bool

// SetUserEmailCollectionEnabled records whether identity telemetry may carry
// the end-user email address. Set from the ai_discovery wiring; tests may
// toggle it under t.Cleanup. Idempotent and atomic.
func SetUserEmailCollectionEnabled(v bool) { userEmailCollectionEnabled.Store(v) }

// UserEmailCollectionEnabled reports the flag set by
// SetUserEmailCollectionEnabled. Off means the address is never attached to a
// record, so a deployment whose privacy review has not approved collecting it
// emits the uid or SID and the account name alone.
func UserEmailCollectionEnabled() bool { return userEmailCollectionEnabled.Load() }

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
	user.Email = hookUserEmail(connector, payload)
	return user
}

// resolveHookUser resolves the identifier and account name without touching
// the filesystem. Callers that only need a registry join key use this: the
// address lookup in resolveHookUserIdentity reads a credential file, which is
// wasted work on a path that has nowhere to put the result.
func resolveHookUser(ctx context.Context, payload map[string]interface{}) llmEventUser {
	fromHeaders := AgentIdentityFromContext(ctx)
	// The two sources are ranked as pairs rather than field by field. The hook
	// helper omits the name header on its own whenever the account name fails
	// its allowlist, so merging per field would pair that hook's OS account id
	// with a name the agent supplied — a record naming one account and
	// identifying another.
	if fromHeaders.UserID != "" || fromHeaders.UserName != "" {
		return newLLMEventUser(fromHeaders.UserID, fromHeaders.UserName)
	}
	payloadID, payloadName := userFieldsFromHookPayload(payload)
	return newLLMEventUser(payloadID, payloadName)
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

// hookUserEmail resolves the signed-in account for one hook event, and only
// from what the event itself carries.
//
// The address also lives in a file under the user's profile, but reading it
// needs a profile directory, and the only one available here would be derived
// from the user id the request supplied. Nothing authenticates that claim: the
// loopback listener is reachable by any local process holding a hook token,
// and hook tokens are scoped per connector rather than per user. A local
// account could therefore name another user's uid or SID and have the gateway
// — running as a service account under a managed install — open that profile's
// credential file and stamp its owner's address onto the caller's own event.
//
// The per-user inventory pass reads the same files without that exposure,
// because there the profile comes from the operator-configured roots and its
// owner is resolved by stat'ing the directory. That is where a file-backed
// address is attributed; see inventoryHomeOwner.
func hookUserEmail(connector string, payload map[string]interface{}) string {
	connector = strings.TrimSpace(connector)
	if connector == "" || !UserEmailCollectionEnabled() {
		return ""
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	email, err := useridentity.EmailFromPayloadForConnector(connector, raw)
	if err != nil {
		return ""
	}
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

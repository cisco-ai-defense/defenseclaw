// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// On-demand directory revalidation.
//
// Directory facts refresh every identityDirectoryTTL and on a profile
// change. A management agent that learns an account left a group runs
// `enterprise identity refresh` as root or SYSTEM, which posts here: the
// gateway re-reads the facts of one account, or of every account its cache
// holds, through the lookup explain uses (it refreshes the facts hook calls
// read), and reports the accounts whose profile changed. It changes no
// decision beyond applying the directory answer sooner.
//
// The answer goes only to the root caller on loopback, with the account
// names; the audit row and its telemetry carry counts only.

const (
	identityRefreshPath = "/api/v1/identity/refresh"
	// identityRefreshDefaultMaxUsers bounds one run (--max-users).
	identityRefreshDefaultMaxUsers = 500
	// identityRefreshParallel bounds the lookups in flight at once, so a
	// run over many accounts does not load the domain controller.
	identityRefreshParallel = 8
	identityRefreshBodyMax  = 4096
)

// identityRefreshRunning is held for the whole run: a second run is refused
// with refresh_busy rather than queued.
var identityRefreshRunning atomic.Bool

// identityRefreshAccounts lists the accounts the hook cache holds. Tests
// replace it.
var identityRefreshAccounts = func(limit int) ([]string, int) { return peerDirectoryCache().accounts(limit) }

// identityRefreshTokenGroupsPending reports facts whose groups come from a
// sign-in token (Windows): a directory change reaches them at the next
// sign-in only. Tests replace it.
var identityRefreshTokenGroupsPending = func(useridentity.DirectoryFacts) bool { return runtime.GOOS == "windows" }

type identityRefreshRequest struct {
	// User is the uid (Linux, macOS) or SID (Windows) root resolved the
	// --user account to; empty for every cached account.
	User     string `json:"user,omitempty"`
	MaxUsers int    `json:"max_users,omitempty"`
	// OSCacheFlushed is what the CLI did before the call, for the audit row.
	OSCacheFlushed string `json:"os_cache_flushed,omitempty"`
}

// identityRefreshAccount names one account, for the root caller only.
type identityRefreshAccount struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
}

type identityRefreshChange struct {
	UserID          string `json:"user_id"`
	UserName        string `json:"user_name,omitempty"`
	Connector       string `json:"connector,omitempty"`
	PreviousProfile string `json:"previous_profile"`
	PreviousMatch   string `json:"previous_match"`
	Profile         string `json:"profile"`
	Match           string `json:"match"`
	Refused         bool   `json:"refused,omitempty"`
}

type identityRefreshFailure struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name,omitempty"`
	Code     string `json:"code"`
}

type identityRefreshAnswer struct {
	Scope                     string                   `json:"scope"`
	ProfilesConfigured        bool                     `json:"profiles_configured"`
	Refreshed                 int                      `json:"refreshed"`
	Changed                   int                      `json:"changed"`
	Failed                    int                      `json:"failed"`
	Skipped                   int                      `json:"skipped"`
	Changes                   []identityRefreshChange  `json:"changes"`
	Failures                  []identityRefreshFailure `json:"failures"`
	WindowsTokenGroupsPending []identityRefreshAccount `json:"windows_token_groups_pending,omitempty"`
	DurationMS                int64                    `json:"duration_ms"`
}

// Failure codes of one account.
const (
	identityRefreshLookupFailed      = "lookup_failed"
	identityRefreshAccountUnresolved = "account_unresolved"
)

func (a *APIServer) handleIdentityRefresh(w http.ResponseWriter, r *http.Request) {
	refuse := func(status int, code, message string) {
		a.writeJSON(w, status, map[string]string{"error": message, "code": code})
	}
	if r.Method != http.MethodPost {
		refuse(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if !connector.IsLoopback(r) {
		refuse(http.StatusForbidden, "loopback_only", "identity refresh is restricted to loopback clients")
		return
	}
	if authenticatedHookConnector(r.Context()) != "" || authenticatedInspectConnector(r.Context()) != "" {
		refuse(http.StatusForbidden, "gateway_token_required", "identity refresh needs the gateway token")
		return
	}
	base := a.runtimeConfigSnapshot()
	if g := a.generation(); g != nil && g.Config != nil {
		base = g.Config
	}
	if base == nil || !base.StandaloneEnterprise() {
		refuse(http.StatusNotFound, "not_managed", "identity refresh runs on a standalone managed deployment only")
		return
	}
	var req identityRefreshRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, identityRefreshBodyMax))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		refuse(http.StatusBadRequest, "invalid_arguments", "the request body is not an identity refresh request")
		return
	}
	req.User = strings.TrimSpace(req.User)
	if req.User != "" && useridentity.KindForID(req.User) == "" {
		refuse(http.StatusBadRequest, "invalid_arguments", "user must be the uid or SID of the account")
		return
	}
	switch {
	case req.MaxUsers < 0 || req.MaxUsers > identityDirectoryMax:
		refuse(http.StatusBadRequest, "invalid_arguments", fmt.Sprintf("max_users must be from 1 to %d", identityDirectoryMax))
		return
	case req.MaxUsers == 0:
		req.MaxUsers = identityRefreshDefaultMaxUsers
	}
	if !identityRefreshRunning.CompareAndSwap(false, true) {
		refuse(http.StatusConflict, "refresh_busy", "another identity refresh is running")
		return
	}
	defer identityRefreshRunning.Store(false)
	answer := refreshIdentities(a.guardrailProfileSet(), req)
	a.auditIdentityRefresh(answer, req)
	a.writeJSON(w, http.StatusOK, answer)
}

// refreshIdentities re-reads the accounts of req and compares the profile
// their requests get before and after.
func refreshIdentities(set *guardrailProfileSet, req identityRefreshRequest) identityRefreshAnswer {
	started := time.Now()
	answer := identityRefreshAnswer{Scope: "all", ProfilesConfigured: set != nil,
		Changes: []identityRefreshChange{}, Failures: []identityRefreshFailure{}}
	keys := []string{req.User}
	if req.User != "" {
		answer.Scope = "user"
	} else {
		keys, answer.Skipped = identityRefreshAccounts(req.MaxUsers)
	}
	connectors := identityRefreshConnectors(set)
	type outcome struct {
		account identityRefreshAccount
		changes []identityRefreshChange
		failure string
		pending bool
	}
	outcomes := make([]outcome, len(keys))
	var wg sync.WaitGroup
	slots := make(chan struct{}, identityRefreshParallel)
	for i, key := range keys {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			account, changes, failure, pending := refreshIdentity(set, key, connectors)
			outcomes[i] = outcome{account: account, changes: changes, failure: failure, pending: pending}
		}()
	}
	wg.Wait()
	for _, o := range outcomes {
		if o.failure != "" {
			answer.Failed++
			answer.Failures = append(answer.Failures, identityRefreshFailure{UserID: o.account.UserID, UserName: o.account.UserName, Code: o.failure})
			continue
		}
		answer.Refreshed++
		if len(o.changes) > 0 {
			answer.Changed++
			answer.Changes = append(answer.Changes, o.changes...)
			if set != nil {
				// The next request of the account is decided afresh.
				set.matches.forgetUser(o.account.UserID)
			}
		}
		if o.pending {
			answer.WindowsTokenGroupsPending = append(answer.WindowsTokenGroupsPending, o.account)
		}
	}
	answer.DurationMS = time.Since(started).Milliseconds()
	return answer
}

// identityRefreshConnectors are the connectors whose decision is compared:
// none (the account itself), then every connector an assignment names.
func identityRefreshConnectors(set *guardrailProfileSet) []string {
	connectors := []string{""}
	if set == nil {
		return connectors
	}
	for _, assignment := range set.assignments {
		for _, name := range assignment.Match.Connectors {
			if name = config.NormalizeConnectorName(name); name != "" && !slices.Contains(connectors, name) {
				connectors = append(connectors, name)
			}
		}
	}
	sort.Strings(connectors[1:])
	return connectors
}

// identityRefreshRetryDelay is how long a failed lookup waits before its one
// retry: past identityExplainFresh, so the retry starts a lookup of its own.
// Right after an OS cache flush a directory account resolves cold (SSSD asks
// the domain controller), and the first lookup can exceed its budget while
// SSSD goes on and caches the answer. Tests replace it.
var identityRefreshRetryDelay = identityExplainFresh + 500*time.Millisecond

// refreshIdentity re-reads one account and returns its profile changes.
func refreshIdentity(set *guardrailProfileSet, key string, connectors []string) (account identityRefreshAccount, changes []identityRefreshChange, failure string, pending bool) {
	account.UserID = key
	before, _, hadFacts := cachedDirectoryFacts(key)
	// A lookup that failed while older facts are cached still answers with
	// those facts; it is a failure too: nothing was re-read.
	lookup := func() (profileSubject, bool) {
		subject, err := profileExplainSubjectLookup(key)
		failed := err != nil || subject.UserID == "" || subject.LookupError != ""
		if !failed {
			_, _, failed = cachedDirectoryRefreshFailure(subject.UserID)
		}
		return subject, failed
	}
	subject, failed := lookup()
	if failed && !subject.accountUnresolved {
		time.Sleep(identityRefreshRetryDelay)
		subject, failed = lookup()
	}
	account.UserName = subject.UserName
	switch {
	case subject.accountUnresolved:
		return account, nil, identityRefreshAccountUnresolved, false
	case failed:
		return account, nil, identityRefreshLookupFailed, false
	}
	account.UserID = subject.UserID
	// An account the cache held nothing for gets its facts at its first
	// request, so only an account whose lookups were failing had another
	// answer before this one.
	_, _, wasFailing := cachedDirectoryFailure(subject.UserID)
	compare := hadFacts || wasFailing
	after, _, hasFacts := cachedDirectoryFacts(subject.UserID)
	pending = hasFacts && identityRefreshTokenGroupsPending(after)
	if set == nil || !compare {
		return account, nil, "", pending
	}
	for _, name := range connectors {
		previous := identityRefreshDecision(set, subject, before, hadFacts, name)
		current := identityRefreshDecision(set, subject, after, hasFacts, name)
		if previous.Name == current.Name && previous.Match == current.Match && (previous.Refused == "") == (current.Refused == "") {
			continue
		}
		changes = append(changes, identityRefreshChange{
			UserID: account.UserID, UserName: account.UserName, Connector: name,
			PreviousProfile: previous.Name, PreviousMatch: previous.Match,
			Profile: current.Name, Match: current.Match, Refused: current.Refused != "",
		})
	}
	return account, changes, "", pending
}

// identityRefreshDecision is what requests of subject on connectorName get
// from facts (none when ok is false), decided as explain decides the cached
// facts of an account (explainCacheViewOf).
func identityRefreshDecision(set *guardrailProfileSet, subject profileSubject, facts useridentity.DirectoryFacts, ok bool, connectorName string) profileDecision {
	cached := profileSubject{UserID: subject.UserID, IDKind: subject.IDKind, UserName: subject.UserName, LookupFailed: identityLookupBlocking.Load()}
	if ok {
		cached = profileSubjectFromVerified(VerifiedSubject{
			UserID: subject.UserID, IDKind: subject.IDKind, UserName: subject.UserName, Directory: facts,
		}, identityLookupBlocking.Load())
	}
	decision, _ := set.explainLiveDecision(&cached, connectorName, "", nil)
	return decision
}

// auditIdentityRefresh writes the identity-refresh-completed row: counts,
// duration and the OS cache flush, never an account.
func (a *APIServer) auditIdentityRefresh(answer identityRefreshAnswer, req identityRefreshRequest) {
	if a == nil || a.logger == nil {
		return
	}
	flushed := req.OSCacheFlushed
	if flushed != "user" && flushed != "all" {
		flushed = "none"
	}
	details := fmt.Sprintf("scope=%s refreshed=%d changed=%d failed=%d skipped=%d token_groups_pending=%d duration_ms=%d os_cache_flushed=%s",
		answer.Scope, answer.Refreshed, answer.Changed, answer.Failed, answer.Skipped, len(answer.WindowsTokenGroupsPending), answer.DurationMS, flushed)
	if err := a.logger.LogAction(string(audit.ActionIdentityRefreshCompleted), "", details); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] identity-refresh-completed audit row: %v\n", err)
	}
}

// LookupIdentityRefreshAccount resolves the account an administrator names
// to `enterprise identity refresh --user` (a name, uid or SID) to its uid or
// SID and account name, as profile-explain resolves it. The CLI calls it as
// root or SYSTEM, after its privilege check.
func LookupIdentityRefreshAccount(name string) (id, userName string, err error) {
	return profileExplainAccount(name)
}

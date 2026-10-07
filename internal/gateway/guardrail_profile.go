// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Identity-based guardrail profiles: resolution and the decision-config swap.
//
// config.DerivedForProfile precomputes one configuration per profile at load
// and on every reload (guardrailProfileSet). For each request the gateway
// resolves the subject's profile once (resolveProfile) and the decision sites
// read a.decisionConfig(ctx) instead of a.scannerCfg: the profile's derived
// configuration, or the base configuration when no profile applies.
//
// Security rule: only verified subjects select a profile. The subject comes
// from profileSubjectSource (kernel- or credential-verified identity) or, in a
// per-user gateway, from the gateway's own process owner. Identity headers,
// hook payloads and claimed session facts never reach the matcher. Without a
// verified user only connector-only assignments can match; otherwise the
// default profile applies.
//
// None of this runs under the Secure Client integration: profiles are
// rejected by config validation there, and newGuardrailProfileSet returns nil
// for it, so every decision keeps reading the base configuration.

// profileSubject is the verified subject a profile is selected for.
type profileSubject struct {
	UserID    string
	IDKind    string
	UserName  string
	Principal string
	UPN       string
	// Directory and Domain say where the account lives (explain's short-name
	// note); an empty Domain is an account the host knows by a bare name.
	Directory useridentity.Directory
	Domain    string
	// Groups are verified directory group names and SIDs.
	Groups []string
	// LookupFailed is set when the directory lookup for this subject failed
	// and no cached facts within their TTL exist. The subject then gets the
	// default profile, with the reason default_lookup_failed.
	LookupFailed bool
	// LookupError is why the lookup failed, when `explain` knows (the live
	// path only records default_lookup_failed).
	LookupError string
	// viaProcessOwner marks a subject verified as the per-user gateway's own
	// account, so explain and telemetry report it as process_owner.
	viaProcessOwner bool
}

// The verified subject comes from S1's VerifiedSubject
// (internal/gateway/identity_subject.go), attached once at authentication:
// a hook-socket peer, a per-user credential's account or, on a per-user
// gateway, its process owner. profileSubjectFromVerified maps its directory
// facts (the gateway's own NSS, guardian spool or Windows lookup) to the
// matcher's view. When no subject was attached (routes that skip S1's
// authentication points, or identity facts off), a per-user gateway still
// falls back to its process owner (profileProcessOwnerSubject); a request
// S1 already verified as the process owner never takes that fallback.
// `guardrail profile explain --user` resolves the named account's facts the
// same way (lookupDirectoryProfileSubject), falling back to the OS account
// database on Linux and macOS (profileExplainUnresolved).
var (
	// profileSubjectSource returns the kernel- or credential-verified
	// subject of a request.
	profileSubjectSource = func(ctx context.Context) (profileSubject, bool) {
		subject, ok := verifiedSubjectFromContext(ctx)
		if !ok {
			return profileSubject{}, false
		}
		return profileSubjectFromVerified(subject, identityLookupBlocking.Load()), true
	}
	// profileAgentSource returns the request's verified agent identity
	// (defenseclaw.agent.identity.id, agt-...).
	profileAgentSource = requestAgentIdentity
	// profileExplainSubjectLookup resolves the subject an administrator
	// names to `guardrail profile explain --user`.
	profileExplainSubjectLookup = lookupDirectoryProfileSubject
)

// Match reasons (defenseclaw.guardrail.profile.match).
const (
	profileMatchAgent               = "agent"
	profileMatchUser                = "user"
	profileMatchGroup               = "group"
	profileMatchConnector           = "connector"
	profileMatchDefault             = "default"
	profileMatchDefaultUnverified   = "default_unverified"
	profileMatchDefaultLookupFailed = "default_lookup_failed"
)

// Subject sources reported by explain.
const (
	profileSubjectVerified     = "verified"
	profileSubjectProcessOwner = "process_owner"
	profileSubjectLookup       = "lookup"
)

// profileDecision is the profile one request resolved to. Name "" means no
// profile applies and the base guardrail configuration decides.
type profileDecision struct {
	Name          string
	Digest        string
	Match         string
	MatchedGroup  string
	SubjectSource string
	// Assignment is the 1-based index of the assignment that matched, 0 for
	// the default.
	Assignment int
}

// guardrailProfileSet is every profile derived from one configuration.
type guardrailProfileSet struct {
	base           *config.Config
	profiles       map[string]config.DerivedGuardrailProfile
	assignments    []config.ProfileAssignment
	defaultProfile string
	// groupCheck is the last look at whether the assignments' groups exist.
	groupCheck profileGroupCheck
	// rules holds the compiled rule pack of every rule_pack_dir a derived
	// profile can resolve to, keyed by the cleaned directory.
	rules map[string]*compiledRulePackCategories
	// matches memoises match for repeated subjects.
	matches *profileMatchCache
}

// newGuardrailProfileSet derives every profile of cfg and preloads their rule
// packs through loadValidatedRulePack. It returns nil when cfg configures no
// profiles or runs the Secure Client integration. strictRules makes a rule
// pack that fails to load an error (reload); otherwise the profile scans with
// the base rule set for that directory and the failure is logged (boot,
// where the base configuration already loaded).
func newGuardrailProfileSet(cfg *config.Config, cache *guardrail.RulePackCache, strictRules bool) (*guardrailProfileSet, error) {
	if cfg == nil || cfg.SecureClientIntegration() || !cfg.Guardrail.HasProfiles() {
		return nil, nil
	}
	derived, err := cfg.DeriveGuardrailProfiles()
	if err != nil {
		return nil, err
	}
	set := &guardrailProfileSet{
		base:           cfg,
		profiles:       derived,
		assignments:    append([]config.ProfileAssignment(nil), cfg.Guardrail.ProfileAssignments...),
		defaultProfile: strings.TrimSpace(cfg.Guardrail.DefaultProfile),
		rules:          make(map[string]*compiledRulePackCategories),
		matches:        newProfileMatchCache(),
	}
	if cache == nil {
		cache = guardrail.NewRulePackCache()
	}
	names := make([]string, 0, len(derived))
	for name := range derived {
		names = append(names, name)
	}
	sort.Strings(names)
	tuned := profileConnectorNames(cfg)
	for _, name := range names {
		for _, dir := range profileRulePackDirs(derived[name].Config, tuned) {
			key := profileRulePackKey(dir)
			if _, done := set.rules[key]; done {
				continue
			}
			rp, loadErr := loadValidatedRulePack(cache, dir, "guardrail profile "+name)
			var compiled *compiledRulePackCategories
			if loadErr == nil {
				compiled, loadErr = compileRulePackCategories(rp)
			}
			if loadErr != nil {
				if strictRules {
					return nil, loadErr
				}
				fmt.Fprintf(os.Stderr, "[guardrail] profile %s: %v; it scans with the base rule set\n", name, loadErr)
				set.rules[key] = nil
				continue
			}
			set.rules[key] = compiled
		}
	}
	return set, nil
}

// profileRulePackDirs lists every rule-pack directory a derived configuration
// can resolve for some connector, including the connectors some profile
// tunes (tuned, from profileConnectorNames: computed once for all profiles,
// as walking every profile for each derived configuration was quadratic).
func profileRulePackDirs(cfg *config.Config, tuned []string) []string {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var dirs []string
	add := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return
		}
		if _, ok := seen[profileRulePackKey(dir)]; ok {
			return
		}
		seen[profileRulePackKey(dir)] = struct{}{}
		dirs = append(dirs, dir)
	}
	add(cfg.Guardrail.RulePackDir)
	for name := range cfg.Guardrail.Connectors {
		add(cfg.EffectiveRulePackDirForConnector(name))
	}
	for _, name := range tuned {
		add(cfg.EffectiveRulePackDirForConnector(name))
	}
	add(cfg.ApplicationProtection.Guardrail.RulePackDir)
	for _, pc := range cfg.ApplicationProtection.Connectors {
		add(pc.Guardrail.RulePackDir)
	}
	sort.Strings(dirs)
	return dirs
}

// profileConnectorNames returns every connector some profile tunes, so the
// rule packs their connectors[c] entries select are preloaded too.
func profileConnectorNames(cfg *config.Config) []string {
	var names []string
	for _, profile := range cfg.Guardrail.Profiles {
		for name := range profile.Connectors {
			names = append(names, config.NormalizeConnectorName(name))
		}
	}
	sort.Strings(names)
	return slices.Compact(names)
}

func profileRulePackKey(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}

// guardrailProfileHolder publishes the active profile set to readers.
type guardrailProfileHolder struct {
	set atomic.Pointer[guardrailProfileSet]
}

// liveGuardrailProfiles is the set the running gateway's API server last
// published. The guardrail proxy, which has no API server, resolves through
// it.
var liveGuardrailProfiles atomic.Pointer[guardrailProfileSet]

// setGuardrailProfiles publishes set (nil clears it) for this API server and
// the proxy.
func (a *APIServer) setGuardrailProfiles(set *guardrailProfileSet) {
	if a == nil {
		return
	}
	a.guardrailProfiles.set.Store(set)
	liveGuardrailProfiles.Store(set)
}

func (a *APIServer) guardrailProfileSet() *guardrailProfileSet {
	if a == nil {
		return nil
	}
	return a.guardrailProfiles.set.Load()
}

// initGuardrailProfiles derives the profiles of the start-time config.
func (a *APIServer) initGuardrailProfiles(cfg *config.Config, cache *guardrail.RulePackCache) {
	set, err := newGuardrailProfileSet(cfg, cache, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] guardrail profiles unavailable: %v\n", err)
		return
	}
	if set != nil {
		a.setGuardrailProfiles(set)
	}
}

// resolvedGuardrailProfile is the per-request resolution stored on the
// context so every decision site of one request reads the same profile.
type resolvedGuardrailProfile struct {
	decision profileDecision
	set      *guardrailProfileSet
	derived  *config.Config
}

type resolvedGuardrailProfileKey struct{}
type profileRouteConnectorKey struct{}

// withGuardrailProfileDecision resolves the request's profile once, right
// after authentication, and stores it on ctx. routeConnector is the
// connector the server-side route serves (never a payload value). It is a
// no-op when no profiles are configured.
func (a *APIServer) withGuardrailProfileDecision(ctx context.Context, routeConnector string) context.Context {
	return withGuardrailProfile(ctx, a.guardrailProfileSet(), routeConnector)
}

// withGuardrailProfile is withGuardrailProfileDecision for set. The LLM
// proxy, which has no APIServer, calls it with the live set and the
// connector it serves (GuardrailProxy.withProxyAgent).
func withGuardrailProfile(ctx context.Context, set *guardrailProfileSet, routeConnector string) context.Context {
	if set == nil {
		return ctx
	}
	if routeConnector = config.NormalizeConnectorName(routeConnector); routeConnector != "" {
		ctx = context.WithValue(ctx, profileRouteConnectorKey{}, routeConnector)
	}
	return context.WithValue(ctx, resolvedGuardrailProfileKey{}, resolveGuardrailProfileFor(ctx, set))
}

// requestAgentIdentity is the agent identity an agents assignment matches
// for ctx: the one the hook path, ACP or the LLM proxy put on ctx, else the
// one the hook path derives for the connector the request authenticated for
// or reached (profileRequestConnector) and its verified user. The derivation
// covers the inspect endpoints, which carry no agent identity, and the
// resolution at authentication, before the hook path has derived one.
func requestAgentIdentity(ctx context.Context) (id string, verified bool) {
	if id, verified = agentIdentityFromContext(ctx); id != "" {
		return id, verified
	}
	connectorName := profileRequestConnector(ctx)
	if connectorName == "" {
		return "", false
	}
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connectorName})
	return facts.ID, facts.Verified
}

// guardrailProfileInspectMiddleware resolves the profile for the inspect
// endpoints, whose connector comes from the authenticated hook credential.
func (a *APIServer) guardrailProfileInspectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.guardrailProfileSet() != nil {
			r = r.WithContext(a.withGuardrailProfileDecision(r.Context(), ""))
		}
		next.ServeHTTP(w, r)
	})
}

func resolvedGuardrailProfileFrom(ctx context.Context) *resolvedGuardrailProfile {
	if ctx == nil {
		return nil
	}
	resolved, _ := ctx.Value(resolvedGuardrailProfileKey{}).(*resolvedGuardrailProfile)
	return resolved
}

// resolveProfile returns the profile for the request on ctx.
func (a *APIServer) resolveProfile(ctx context.Context) profileDecision {
	if resolved := a.resolvedProfile(ctx); resolved != nil {
		return resolved.decision
	}
	return profileDecision{}
}

func (a *APIServer) resolvedProfile(ctx context.Context) *resolvedGuardrailProfile {
	set := a.guardrailProfileSet()
	if set == nil {
		return nil
	}
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil && resolved.set == set {
		return resolved
	}
	return resolveGuardrailProfileFor(ctx, set)
}

// resolveGuardrailProfileFor resolves ctx's verified subject against set.
func resolveGuardrailProfileFor(ctx context.Context, set *guardrailProfileSet) *resolvedGuardrailProfile {
	if set == nil {
		return nil
	}
	subject, source := profileRequestSubject(ctx)
	agent := ""
	if source != "" && !subject.LookupFailed {
		if id, ok := profileAgentSource(ctx); ok {
			agent = strings.TrimSpace(id)
		}
	}
	decision := set.match(subject, source, profileRequestConnector(ctx), agent)
	resolved := &resolvedGuardrailProfile{decision: decision, set: set}
	if decision.Name != "" {
		if derived, ok := set.profiles[decision.Name]; ok {
			resolved.derived = derived.Config
		}
	}
	return resolved
}

// profileRequestSubject returns the verified subject of ctx and where it
// came from, or ("", "") when the request has none.
func profileRequestSubject(ctx context.Context) (*profileSubject, string) {
	if subject, ok := profileSubjectSource(ctx); ok {
		if subject.viaProcessOwner {
			return &subject, profileSubjectProcessOwner
		}
		return &subject, profileSubjectVerified
	}
	if subject, ok := profileProcessOwnerSubject(); ok {
		return &subject, profileSubjectProcessOwner
	}
	return nil, ""
}

// profileRequestConnector returns the connector the request authenticated
// for (hook-scoped credential or inspect scope) or the route it reached.
// Payload and header connector names are never consulted.
func profileRequestConnector(ctx context.Context) string {
	if name := authenticatedHookConnector(ctx); name != "" {
		return config.NormalizeConnectorName(name)
	}
	if name := authenticatedInspectConnector(ctx); name != "" {
		return config.NormalizeConnectorName(name)
	}
	if ctx != nil {
		if name, _ := ctx.Value(profileRouteConnectorKey{}).(string); name != "" {
			return name
		}
	}
	return ""
}

// profileProcessOwnerSubject is the per-user gateway's own OS account. A
// per-user gateway runs as the person using it and accepts only that
// person's credential, so its process owner is a verified subject. A
// managed gateway runs as a service account, whose identity says nothing
// about the user, and gets none.
func profileProcessOwnerSubject() (profileSubject, bool) {
	if gatewayRunsAsServiceAccount() {
		return profileSubject{}, false
	}
	return processOwnerProfileSubject()
}

// processOwnerProfileSubject is the process owner's subject; tests replace
// it. It carries the directory facts the verified paths use (NSS and SSSD on
// Linux and macOS, the identity store on Windows, cached and refreshed). The
// OS account database read by processOwnerAccountSubject lists only the groups
// /etc/group names when the binary has no cgo, so an AD account's group
// assignments never selected a profile through this fallback (GAP-0174).
var processOwnerProfileSubject = func() (profileSubject, bool) {
	if identityFactsEnabled.Load() {
		if id, name := localProcessUser(); id != "" {
			facts, _ := verifiedIdentityDirectory(id, identityLookupBlocking.Load())
			return profileSubjectFromVerified(VerifiedSubject{
				UserID: id, IDKind: useridentity.KindForID(id), UserName: name,
				Directory: facts, Source: subjectSourceProcessOwner,
			}, true), true
		}
	}
	return processOwnerAccountSubject()
}

// processOwnerAccountSubject is the process owner as the OS account database
// lists it, for a gateway that does not collect identity facts.
var processOwnerAccountSubject = sync.OnceValues(func() (profileSubject, bool) {
	current, err := osuser.Current()
	if err != nil || current == nil {
		return profileSubject{}, false
	}
	return localProfileSubject(current), true
})

// profileSubjectFromVerified maps S1's verified subject to the matcher's
// view. lookupAttempted says the directory lookup was waited on (a group or
// user assignment is configured); a subject whose facts then never resolved
// (Directory.ResolvedAt is zero: the lookup failed or ran over its budget)
// has unknown groups, not empty ones, and gets the default profile.
//
// The account name is the bare one (alice for alice@corp.example.com and
// CORP\alice) here, for every caller: a request and `explain --user` both
// build their subject through this function, so a users entry cannot match
// one and not the other (GAP-0182).
func profileSubjectFromVerified(s VerifiedSubject, lookupAttempted bool) profileSubject {
	return profileSubject{
		UserID:          s.UserID,
		IDKind:          s.IDKind,
		UserName:        useridentity.BareAccountName(s.UserName),
		Principal:       s.Directory.Principal,
		UPN:             s.Directory.UPN,
		Directory:       s.Directory.Directory,
		Domain:          s.Directory.Domain,
		Groups:          s.Directory.Groups,
		LookupFailed:    lookupAttempted && s.Directory.ResolvedAt.IsZero(),
		viaProcessOwner: s.Source == subjectSourceProcessOwner,
	}
}

// lookupDirectoryProfileSubject resolves the account an administrator names
// to `guardrail profile explain --user` with the directory facts a request
// from that account would carry. An account the directory lookup cannot
// name falls back to the OS account database on Linux and macOS; on Windows
// both are the LSA, and the LSA's reason is reported.
func lookupDirectoryProfileSubject(name string) (profileSubject, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return profileSubject{}, fmt.Errorf("no user named")
	}
	id, userName, err := profileExplainAccount(name)
	if err != nil {
		return profileExplainUnresolved(name, err)
	}
	facts, err := profileExplainDirectoryFacts(id)
	if err != nil {
		// The lookup the hook path would run failed, so a request from this
		// account gets default_lookup_failed. Answering from the OS account
		// database instead would explain a profile no request receives, and
		// hide why (GAP-0124).
		return profileSubject{
			UserID: id, IDKind: useridentity.KindForID(id), UserName: userName,
			LookupFailed: true, LookupError: err.Error(),
		}, nil
	}
	if facts.ResolvedAt.IsZero() {
		if local, localErr := lookupLocalProfileSubject(name); localErr == nil {
			return local, nil
		}
		// The account is named, so explain shows it with the reason, not a
		// bare default_lookup_failed.
		return profileSubject{UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, LookupFailed: true},
			fmt.Errorf("the operating system returned no directory facts for %s", id)
	}
	return profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
	}, true), nil
}

// lookupLocalProfileSubject resolves an account name or uid/SID through the
// OS account database (NSS on Unix, the SAM/LSA on Windows).
func lookupLocalProfileSubject(name string) (profileSubject, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return profileSubject{}, fmt.Errorf("no user named")
	}
	account, err := osuser.Lookup(name)
	if err != nil {
		var idErr error
		account, idErr = osuser.LookupId(name)
		if idErr != nil {
			return profileSubject{}, fmt.Errorf("look up user %q: %w", name, err)
		}
	}
	return localProfileSubject(account), nil
}

func localProfileSubject(account *osuser.User) profileSubject {
	subject := profileSubject{
		UserID:   account.Uid,
		IDKind:   useridentity.KindForID(account.Uid),
		UserName: useridentity.BareAccountName(account.Username),
	}
	if strings.ContainsAny(account.Username, `\@`) {
		subject.Principal = account.Username
	}
	groups, err := accountGroups(account)
	subject.Groups = groups
	if err != nil {
		// Groups that could not be listed are unknown, not empty: the subject
		// selects as a failed lookup does for a request (default_lookup_failed)
		// and explain names the reason.
		subject.LookupFailed, subject.LookupError = true, err.Error()
	}
	return subject
}

// accountGroups lists an OS account's groups from the OS account database.
// On Linux and macOS each group is its name, or its gid when no group answers
// for it, one entry per group as the NSS directory facts list them
// (unixidentity), so counts and matching agree with a hook's verified
// subject. On Windows each group is its SID followed by its name, as the
// Windows directory facts list them; identityGroupCount counts the SIDs. The
// error says the database could not list the account's groups: facts a lookup
// resolves for the hook path must not be cached as resolved without them.
func accountGroups(account *osuser.User) ([]string, error) {
	gids, err := accountGroupIDs(account)
	if err != nil {
		return nil, err
	}
	var groups []string
	for _, gid := range gids {
		group, lookupErr := osuser.LookupGroupId(gid)
		named := lookupErr == nil && group.Name != ""
		if runtime.GOOS == "windows" || !named {
			groups = append(groups, gid)
		}
		if named {
			groups = append(groups, group.Name)
		}
	}
	return groups, nil
}

// match runs the ordered assignments: the first match wins; within one
// assignment the set keys AND together and the values of a key OR together.
// Identity keys (users, groups, agents) match only a verified subject; a
// connector-only assignment matches any other request authenticated for that
// connector. A subject whose directory lookup failed gets the default profile
// (default_lookup_failed): its groups are unknown, so an identity assignment
// listed before a connector-only one might have selected it, and the reason
// must show the outage (GAP-0312).
func (set *guardrailProfileSet) match(subject *profileSubject, source, connectorName, agent string) profileDecision {
	if set.matches == nil {
		return set.matchUncached(subject, source, connectorName, agent)
	}
	key := profileMatchKey(subject, source, connectorName, agent)
	if decision, ok := set.matches.get(key); ok {
		return decision
	}
	decision := set.matchUncached(subject, source, connectorName, agent)
	set.matches.put(key, decision)
	return decision
}

func (set *guardrailProfileSet) matchUncached(subject *profileSubject, source, connectorName, agent string) profileDecision {
	if subject != nil && subject.LookupFailed {
		return set.decision(set.defaultProfile, profileMatchDefaultLookupFailed, "", source)
	}
	verified := subject != nil && source != ""
	groups := &subjectGroups{}
	if verified {
		groups.list = subject.Groups
	}
	for i, assignment := range set.assignments {
		reason, group, ok := assignmentMatches(assignment.Match, subject, groups, verified, connectorName, agent)
		if !ok {
			continue
		}
		decision := set.decision(assignment.Profile, reason, group, source)
		decision.Assignment = i + 1
		return decision
	}
	reason := profileMatchDefault
	if !verified {
		reason = profileMatchDefaultUnverified
	}
	return set.decision(set.defaultProfile, reason, "", source)
}

func (set *guardrailProfileSet) decision(name, reason, group, source string) profileDecision {
	decision := profileDecision{Name: name, Match: reason, MatchedGroup: group, SubjectSource: source}
	if derived, ok := set.profiles[name]; ok {
		decision.Digest = derived.Digest
	} else {
		decision.Name = ""
	}
	return decision
}

func assignmentMatches(m config.ProfileMatch, subject *profileSubject, groups *subjectGroups, verified bool, connectorName, agent string) (reason, group string, ok bool) {
	if m.Empty() {
		return "", "", false
	}
	if (len(m.Users) > 0 || len(m.Groups) > 0 || len(m.Agents) > 0) && !verified {
		return "", "", false
	}
	if len(m.Connectors) > 0 {
		if connectorName == "" || !anyMatches(m.Connectors, func(v string) bool {
			return config.NormalizeConnectorName(v) == connectorName
		}) {
			return "", "", false
		}
		reason = profileMatchConnector
	}
	if len(m.Groups) > 0 {
		matched := ""
		for _, want := range m.Groups {
			if groups.has(want) {
				matched = strings.TrimSpace(want)
				break
			}
		}
		if matched == "" {
			return "", "", false
		}
		reason, group = profileMatchGroup, matched
	}
	if len(m.Users) > 0 {
		if !anyMatches(m.Users, func(v string) bool { return userEntryMatches(subject, v) }) {
			return "", "", false
		}
		reason, group = profileMatchUser, ""
	}
	if len(m.Agents) > 0 {
		if agent == "" || !anyMatches(m.Agents, func(v string) bool { return strings.EqualFold(strings.TrimSpace(v), agent) }) {
			return "", "", false
		}
		reason, group = profileMatchAgent, ""
	}
	return reason, group, true
}

// userEntryMatches reports whether a users entry names the subject: its uid
// or SID, its account name without the domain, or its principal or UPN.
func userEntryMatches(subject *profileSubject, entry string) bool {
	return anyEqualFold([]string{subject.UserID, subject.UserName}, entry) ||
		useridentity.PrincipalsEqual(subject.Principal, entry) || useridentity.PrincipalsEqual(subject.UPN, entry)
}

// subjectGroups answers whether one of a subject's groups is the group an
// assignment names, compared without regard to case. Windows subjects carry
// each group as its SID and DOMAIN\name, so a bare group name in an
// assignment also matches the name part of a DOMAIN\name group.
//
// It indexes the groups on first use. A request is matched against every
// assignment in order, and scanning the whole group list for each one made
// a request cost assignments x groups comparisons (11 ms at 2,000
// assignments and 400 groups, 50 ms at 10,000, on each hook call, twice).
type subjectGroups struct {
	list  []string
	built bool
	// exact holds every group, tails the name part after the last
	// backslash of those that have one, both folded.
	exact, tails map[string]struct{}
}

func (g *subjectGroups) has(want string) bool {
	want = strings.TrimSpace(want)
	if want == "" || len(g.list) == 0 {
		return false
	}
	if !g.built {
		g.build()
	}
	key := foldKey(want)
	if _, ok := g.exact[key]; ok {
		return true
	}
	if strings.Contains(want, `\`) {
		return false
	}
	_, ok := g.tails[key]
	return ok
}

func (g *subjectGroups) build() {
	g.built = true
	g.exact = make(map[string]struct{}, len(g.list))
	for _, group := range g.list {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		g.exact[foldKey(group)] = struct{}{}
		if i := strings.LastIndexByte(group, '\\'); i >= 0 {
			if g.tails == nil {
				g.tails = map[string]struct{}{}
			}
			g.tails[foldKey(strings.TrimSpace(group[i+1:]))] = struct{}{}
		}
	}
}

// foldKey maps every rune to the smallest rune of its case-folding orbit,
// so two strings have the same key exactly when strings.EqualFold says
// they are equal, after both are put in Unicode normalization form C: an
// assignment typed or pasted with a combining accent (e plus U+0301) names
// the group the directory holds precomposed (U+00E9), and must match it
// (GAP-0154).
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			smallest = min(smallest, f)
		}
		return smallest
	}, norm.NFC.String(s))
}

func anyMatches(values []string, pred func(string) bool) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" && pred(value) {
			return true
		}
	}
	return false
}

func anyEqualFold(have []string, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, value := range have {
		if value = strings.TrimSpace(value); value != "" && useridentity.EqualFold(value, want) {
			return true
		}
	}
	return false
}

// decisionConfig returns the configuration a decision for ctx reads: the
// derived configuration of the request's profile, or a.scannerCfg.
func (a *APIServer) decisionConfig(ctx context.Context) *config.Config {
	if a == nil {
		return nil
	}
	return a.decisionConfigFrom(ctx, a.scannerCfg)
}

// decisionConfigFrom is decisionConfig for a caller that already holds a
// base snapshot (for example the live runtime configuration).
func (a *APIServer) decisionConfigFrom(ctx context.Context, base *config.Config) *config.Config {
	if base == nil || base.SecureClientIntegration() {
		return base
	}
	if resolved := a.resolvedProfile(ctx); resolved != nil && resolved.derived != nil {
		return resolved.derived
	}
	return base
}

// snapshotRulePackGenerationFor is snapshotRulePackGeneration for a request:
// when the request's profile resolves connector to another rule pack than
// the base configuration does, it returns that pack's compiled rules. A
// request with no stored resolution resolves it as decisionConfig does, so
// its thresholds and its rule pack come from the same profile (GAP-0311).
func snapshotRulePackGenerationFor(ctx context.Context, connectorName string) *compiledRulePackCategories {
	resolved := resolvedGuardrailProfileFrom(ctx)
	if set := liveGuardrailProfiles.Load(); set != nil && (resolved == nil || resolved.set != set) {
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	if resolved != nil && resolved.derived != nil {
		if generation := resolved.ruleGeneration(connectorName); generation != nil {
			return generation
		}
	}
	return snapshotRulePackGeneration(connectorName)
}

// scanAllRulesFor is ScanAllRules with the request's profile rule pack.
func scanAllRulesFor(ctx context.Context, text, toolName string) []RuleFinding {
	return scanAllRulesForConnectorFor(ctx, "", text, toolName)
}

// scanAllRulesForConnectorFor is ScanAllRulesForConnector with the request's
// profile rule pack.
func scanAllRulesForConnectorFor(ctx context.Context, connectorName, text, toolName string) []RuleFinding {
	if ManagedEnterpriseActive() {
		return nil
	}
	return scanRuleGeneration(snapshotRulePackGenerationFor(ctx, connectorName), text, toolName, ruleScanOptions{})
}

// scanContentRulesForConnectorFor is scanContentRulesForConnector with the
// request's profile rule pack.
func scanContentRulesForConnectorFor(ctx context.Context, connectorName, text, toolName string, scope ruleContentScope) []RuleFinding {
	if ManagedEnterpriseActive() {
		return nil
	}
	return scanContentRuleCategoryWithGeneration(snapshotRulePackGenerationFor(ctx, connectorName), text, toolName, scope, "")
}

func (r *resolvedGuardrailProfile) ruleGeneration(connectorName string) *compiledRulePackCategories {
	if r == nil || r.set == nil || r.derived == nil || r.set.base == nil {
		return nil
	}
	dir := profileRulePackKey(r.derived.EffectiveRulePackDirForConnector(connectorName))
	if dir == "" || dir == profileRulePackKey(r.set.base.EffectiveRulePackDirForConnector(connectorName)) {
		return nil
	}
	return r.set.rules[dir]
}

// profileProxyOverride returns the mode and block message the guardrail
// proxy applies for ctx, whose profile withProxyAgent resolved for the
// proxy's connector and agent. It applies only to a request with a verified
// user-scoped identity; without one the proxy keeps its own settings.
func profileProxyOverride(ctx context.Context, connectorName string) (mode, blockMessage string, ok bool) {
	set := liveGuardrailProfiles.Load()
	if set == nil {
		return "", "", false
	}
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || resolved.set != set {
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	if resolved == nil || resolved.derived == nil || resolved.decision.SubjectSource == "" {
		return "", "", false
	}
	connectorName = config.NormalizeConnectorName(connectorName)
	return resolved.derived.Guardrail.EffectiveMode(connectorName),
		resolved.derived.Guardrail.EffectiveBlockMessage(connectorName), true
}

// guardrailProfileTelemetry carries the correlation.guardrail.profile
// attributes for one decision record.
type guardrailProfileTelemetry struct {
	Name, Digest, Match, MatchedGroup observability.Optional[string]
}

// guardrailProfileTelemetryFor returns the profile attributes for a record
// emitted under ctx. All are absent when no profiles are configured, so
// records stay unchanged for every deployment without them.
func guardrailProfileTelemetryFor(ctx context.Context) guardrailProfileTelemetry {
	set := liveGuardrailProfiles.Load()
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil {
		if set == nil {
			return guardrailProfileTelemetry{}
		}
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	if resolved == nil {
		return guardrailProfileTelemetry{}
	}
	d := resolved.decision
	out := guardrailProfileTelemetry{Match: observability.Present(d.Match)}
	if d.Name != "" {
		out.Name = observability.Present(d.Name)
		out.Digest = observability.Present(d.Digest)
	}
	if d.Match == profileMatchGroup && d.MatchedGroup != "" {
		out.MatchedGroup = observability.Present(d.MatchedGroup)
	}
	return out
}

// guardrailProfileDigests maps each profile of set to its digest.
func guardrailProfileDigests(set *guardrailProfileSet) map[string]string {
	if set == nil {
		return nil
	}
	out := make(map[string]string, len(set.profiles))
	for name, derived := range set.profiles {
		out[name] = derived.Digest
	}
	return out
}

// guardrailProfileDigestChange is one profile whose derived configuration
// changed across a reload.
type guardrailProfileDigestChange struct {
	Name, From, To string
}

// diffGuardrailProfileDigests lists the profiles added, removed or changed
// between two sets, sorted by name.
func diffGuardrailProfileDigests(oldSet, newSet *guardrailProfileSet) []guardrailProfileDigestChange {
	before, after := guardrailProfileDigests(oldSet), guardrailProfileDigests(newSet)
	names := map[string]struct{}{}
	for name := range before {
		names[name] = struct{}{}
	}
	for name := range after {
		names[name] = struct{}{}
	}
	var changes []guardrailProfileDigestChange
	for name := range names {
		if before[name] != after[name] {
			changes = append(changes, guardrailProfileDigestChange{Name: name, From: before[name], To: after[name]})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Name < changes[j].Name })
	return changes
}

// auditGuardrailProfileChanges records one config.change.applied per profile
// whose digest changed, targeted at guardrail.profiles.<name>.
func auditGuardrailProfileChanges(logger *audit.Logger, changes []guardrailProfileDigestChange) {
	if logger == nil {
		return
	}
	for _, change := range changes {
		op := "replace"
		switch {
		case change.From == "":
			op = "add"
		case change.To == "":
			op = "remove"
		}
		entry := audit.ActivityDiffEntry{Path: "guardrail.profiles." + change.Name + ".digest", Op: op}
		before := map[string]any{}
		after := map[string]any{}
		if change.From != "" {
			entry.Before = change.From
			before["digest"] = change.From
		}
		if change.To != "" {
			entry.After = change.To
			after["digest"] = change.To
		}
		_ = logger.LogActivity(audit.ActivityInput{
			Actor:       "system",
			Action:      audit.ActionConfigUpdate,
			TargetType:  "config",
			TargetID:    "guardrail.profiles." + change.Name,
			Reason:      "guardrail_profile_reload",
			Before:      before,
			After:       after,
			Diff:        []audit.ActivityDiffEntry{entry},
			VersionFrom: change.From,
			VersionTo:   change.To,
		})
	}
}

// handleGuardrailProfileResolve serves GET
// /api/v1/guardrail/profiles/resolve?user=&connector=&agent=: which profile
// the named subject would get, for `defenseclaw guardrail profile explain`.
// It is an administrator view: loopback only, behind the gateway token.
func (a *APIServer) handleGuardrailProfileResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !connector.IsLoopback(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "profile resolution is restricted to loopback clients"})
		return
	}
	if authenticatedHookConnector(r.Context()) != "" || authenticatedInspectConnector(r.Context()) != "" {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "profile resolution needs the gateway token"})
		return
	}
	base := a.runtimeConfigSnapshot()
	if base != nil && base.SecureClientIntegration() {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "guardrail profiles are not supported with the Secure Client integration"})
		return
	}
	query := r.URL.Query()
	user := strings.TrimSpace(query.Get("user"))
	connectorName := config.NormalizeConnectorName(query.Get("connector"))
	agent := strings.TrimSpace(query.Get("agent"))

	set := a.guardrailProfileSet()
	out := map[string]any{
		"profiles_configured": set != nil,
		"user":                user,
		"connector":           connectorName,
		"agent":               agent,
	}
	if set == nil {
		out["profile"] = ""
		out["match"] = ""
		out["effective"] = profileEffectiveView(a.scannerCfg, connectorName)
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	var subject *profileSubject
	source := ""
	if user != "" {
		found, err := profileExplainSubjectLookup(user)
		if err != nil {
			if found.UserID == "" {
				found = profileSubject{UserName: user}
			}
			found.LookupFailed = true
			out["lookup_error"] = err.Error()
		} else if found.LookupError != "" {
			out["lookup_error"] = found.LookupError
		}
		subject, source = &found, profileSubjectLookup
		out["subject"] = map[string]any{
			"user_id": found.UserID, "user_name": found.UserName,
			"principal": found.Principal, "upn": found.UPN, "groups": found.Groups,
			"group_count": identityGroupCount(found.Groups),
		}
	}
	if source == "" {
		agent = ""
	}
	decision := set.match(subject, source, connectorName, agent)
	out["profile"] = decision.Name
	out["digest"] = decision.Digest
	out["match"] = decision.Match
	out["matched_group"] = decision.MatchedGroup
	out["subject_source"] = decision.SubjectSource
	out["assignment"] = decision.Assignment
	warnings := profileExplainWarnings(set, decision, subject)
	if source == profileSubjectLookup {
		if view, warning := explainCacheView(set, subject, decision, connectorName, agent, time.Now()); view != nil {
			out["cache"] = view
			if warning != "" {
				warnings = append(warnings, warning)
			}
		}
	}
	if view, _ := directoryHealthView(directoryCacheHealth(), time.Now()); view != nil {
		out["directory"] = view
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	effective := set.base
	if derived, ok := set.profiles[decision.Name]; ok {
		effective = derived.Config
	}
	out["effective"] = profileEffectiveView(effective, connectorName)
	digests := guardrailProfileDigests(set)
	out["profiles"] = digests
	a.writeJSON(w, http.StatusOK, out)
}

// profileEffectiveView is the explain summary of the policy cfg applies to
// connectorName.
func profileEffectiveView(cfg *config.Config, connectorName string) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	hilt := cfg.EffectiveHILTForConnector(connectorName)
	return map[string]any{
		"mode":          hookModeForConfig(cfg, connectorName),
		"block_at":      cfg.Guardrail.EffectiveBlockAt(connectorName),
		"alert_at":      cfg.Guardrail.EffectiveAlertAt(connectorName),
		"rule_pack_dir": cfg.EffectiveRulePackDirForConnector(connectorName),
		"hilt":          map[string]any{"enabled": hilt.Enabled, "min_severity": hilt.MinSeverity},
	}
}

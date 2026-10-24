// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

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
	Directory     useridentity.Directory
	Domain        string
	AccountDomain string
	// Groups are verified directory group names and SIDs.
	Groups []string
	// GroupsUnknown means the Windows enumerator has no current desktop
	// token for group matching; other verified identity fields remain usable.
	GroupsUnknown bool
	// unconfirmedGroups are the gids among Groups, as numbers, whose names
	// no NSS group service could give or prove absent
	// (useridentity.DirectoryFacts.UnconfirmedGroups): the account is in
	// them, but a group assignment that names a group may or may not apply
	// (identityResolution).
	unconfirmedGroups []string
	// accountToken names the account incarnation that holds UserID: the
	// SID SSSD holds for it, or a macOS account's local node record
	// (DirectoryFacts.AccountRecord); "" when the facts give none, and then
	// nothing proven is kept for the account (identityIncarnation).
	accountToken string
	// upnUnproven marks guardian-backed facts whose UPN the guardian has
	// not given yet (awaitingSpoolUPN): a users entry written as a UPN or
	// DOMAIN\name may name the account.
	upnUnproven bool
	// tokenGroupsCause says why the enumerator has no current sign-in token
	// groups for a Windows account, "" when it has them; a refusal names it.
	tokenGroupsCause string
	// LookupFailed is set when the directory lookup for this subject failed
	// and no cached facts within their TTL exist: the account and its groups
	// are unproven (resolveIdentity), and only a uid or SID entry, an agent
	// and a connector match for sure.
	LookupFailed bool
	// LookupError is why the lookup failed, when `explain` knows (the live
	// path only records default_lookup_failed).
	LookupError string
	// accountUnresolved marks a numeric explain subject whose uid has no
	// account database holder now. Its uid still describes a hook caller.
	accountUnresolved bool
	// viaProcessOwner marks a subject verified as the per-user gateway's own
	// account, so explain and telemetry report it as process_owner.
	viaProcessOwner bool
	// holderUnproven marks facts that do not show which account holds the
	// uid (useridentity.DirectoryFacts.HolderUnproven): the account and its
	// UPN are unproven, its groups are not (resolveIdentity).
	holderUnproven bool
	// nameUnconfirmed marks a UserName that kept a domain the directory facts
	// do not confirm (profileUserName): no users entry matches it by name.
	nameUnconfirmed bool
	// localAccount marks an account the verified directory facts place in the
	// machine's own account database (/etc/passwd, the computer's SAM, the
	// local Open Directory node). A bare users entry names the directory
	// account of that name, never a local namesake: a root-created local
	// ent-alice got the domain ent-alice's profile (GAP-0305, GAP-0313,
	// GAP-0418). Such an account is selected by its uid or SID, or as
	// .\name (COMPUTER\name on Windows).
	localAccount bool
	// An SSSD qualified-name host may have this short name in several
	// trusted domains. A bare users entry cannot bind either account.
	qualifiedNamesMayCollide bool
	// cachedFactsAge is set when explain serves an account the directory
	// cannot name now from the facts its hooks still apply (GAP-0899).
	cachedFactsAge time.Duration
	// refreshed is set when explain's own lookup fetched the facts the hooks
	// of the account use from their next call (GAP-0336), and not when it
	// failed and both use the facts cached before it; explain only.
	refreshed bool
	// accountName is the account's name as the account database gives it
	// (alice@corp.example.com with SSSD fully qualified names), which
	// enterprise.enrollment.exempt_users entries name; explain only.
	accountName string
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
	// profileAgentLegacySource returns the 1.0.3 identity of the request's
	// agent agent and its proof (requestLegacyAgentIdentity).
	profileAgentLegacySource = requestLegacyAgentIdentity
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
	// Refused names an unproven identity fact.
	// Enforcement surfaces block it; Name remains diagnostic context.
	Refused string
	// Assignment is the 1-based index of the assignment that matched, 0 for
	// the default.
	Assignment int
	// Unproven names the identity facts this pass did not prove, and
	// Candidates the profiles the decision chose among (selectProfile):
	// Name is the one that covers the others, or their meet. Both are empty
	// for a decision of one proven profile. Explain (an administrator view)
	// alone shows Candidates.
	Unproven   []string
	Candidates []string
}

// guardrailProfileSet is every profile derived from one configuration.
type guardrailProfileSet struct {
	base           *config.Config
	profiles       map[string]config.DerivedGuardrailProfile
	assignments    []config.ProfileAssignment
	defaultProfile string
	// groupCheck is the last look at whether the assignments' groups exist.
	groupCheck profileGroupCheck
	// rules holds the compiled rule pack of every scope a derived profile
	// can resolve to, keyed by effectiveRulePackKey (directory plus rules).
	rules map[string]*compiledRulePackCategories
	// packs are the composed packs behind rules, by the same key.
	packs map[string]*guardrail.RulePack
	// missing holds the rule packs that did not load when the set was built
	// at start, keyed like rules; requests retry them (GAP-0333).
	missing map[string]*profileRulePackRetry
	// lazy holds the scopes a request resolved that the start-time preload
	// did not list (*profileLazyScope by key); they load on first use.
	lazy sync.Map
	// matches memoises match for repeated subjects.
	matches *profileMatchCache
	// groupSIDs holds the SIDs of the assignment group names on standalone
	// Windows, where groups match on SIDs only (GAP-0860); nil elsewhere.
	groupSIDs *profileGroupSIDs
	// agentBridge links agents entries written for 1.0.3 identities to the
	// identities their accounts have now (profileAgent).
	agentBridge profileAgentBridge
	// provenProfiles holds the last fully proven profile of each account
	// incarnation (selectProfile).
	provenProfiles *provenProfileStore
	// meets holds the meets of profiles requests resolved to
	// (*profileMeet by name, guardrail_profile_meet_gw.go).
	meets sync.Map
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
		packs:          make(map[string]*guardrail.RulePack),
		matches:        newProfileMatchCache(),
		provenProfiles: &provenProfileStore{},
	}
	if runtime.GOOS == "windows" && cfg.StandaloneEnterprise() && profileGroupSIDLookup != nil {
		set.groupSIDs = buildProfileGroupSIDs(set.assignments, profileGroupSIDLookup, profileGroupLocalSIDLookup, profileGroupSIDWait)
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
	// Scopes that resolve to the same loaded pack share its compiled rules:
	// compiling it once per scope key cost a share of every start (GAP-0276).
	compiledPacks := make(map[*guardrail.RulePack]*compiledRulePackCategories)
	for _, name := range names {
		for _, scope := range profileRulePackScopes(derived[name].Config, tuned) {
			key := scope.key()
			if _, done := set.rules[key]; done {
				continue
			}
			rp, loadErr := loadScopedRulePack(cache, derived[name].Config, scope, "guardrail profile "+name)
			var compiled *compiledRulePackCategories
			if loadErr == nil {
				if compiled = compiledPacks[rp]; compiled == nil {
					compiled, loadErr = compileRulePackCategories(rp)
					if loadErr == nil {
						compiledPacks[rp] = compiled
					}
				}
			}
			if loadErr != nil {
				if strictRules {
					return nil, loadErr
				}
				fmt.Fprintf(os.Stderr, "[guardrail] profile %s: %v; it scans with the base rule set until the pack loads (retried every %s)\n",
					name, loadErr, profileRulePackRetryInterval)
				set.rules[key] = nil
				if set.missing == nil {
					set.missing = make(map[string]*profileRulePackRetry)
				}
				set.missing[key] = &profileRulePackRetry{profile: name, cfg: derived[name].Config, scope: scope,
					lastErr: loadErr.Error(), nextTry: time.Now().Add(profileRulePackRetryInterval)}
				continue
			}
			set.rules[key] = compiled
			set.packs[key] = rp
		}
	}
	return set, nil
}

// A profile rule pack that did not load at start.
//
// The gateway starts before an administrator, or the MDM that delivers the
// files, has created a profile's rule-pack directory: on a fresh managed
// install the package starts the services, and the pack is copied a moment
// later. Such a profile scanned with the base rule set until the next
// restart, while ensure and status reported a complete deployment (GAP-0333).
// The request path now retries the pack at most every
// profileRulePackRetryInterval and uses it from the first retry that loads
// it; explain says when a profile still waits for its pack. A reload keeps
// refusing a pack that does not load (strictRules).

const profileRulePackRetryInterval = 30 * time.Second

type profileRulePackRetry struct {
	profile string
	cfg     *config.Config
	scope   rulePackScope
	loaded  atomic.Pointer[compiledRulePackCategories]
	pack    atomic.Pointer[guardrail.RulePack]

	mu      sync.Mutex
	lastErr string
	nextTry time.Time
}

// rules returns the pack once it has loaded, retrying the load when the
// interval has passed. A request never waits for another request's retry.
func (r *profileRulePackRetry) rules(now time.Time) *compiledRulePackCategories {
	if loaded := r.loaded.Load(); loaded != nil {
		return loaded
	}
	if !r.mu.TryLock() {
		return nil
	}
	defer r.mu.Unlock()
	if loaded := r.loaded.Load(); loaded != nil || now.Before(r.nextTry) {
		return loaded
	}
	r.nextTry = now.Add(profileRulePackRetryInterval)
	rp, err := loadScopedRulePack(guardrail.NewRulePackCache(), r.cfg, r.scope, "guardrail profile "+r.profile)
	var compiled *compiledRulePackCategories
	if err == nil {
		compiled, err = compileRulePackCategories(rp)
	}
	if err != nil {
		r.lastErr = err.Error()
		return nil
	}
	r.pack.Store(rp)
	r.loaded.Store(compiled)
	fmt.Fprintf(os.Stderr, "[guardrail] profile %s: rule pack %s loaded; it did not load when the gateway started\n", r.profile, r.scope.key())
	return compiled
}

// rulePack returns the composed pack behind the rules the retry published.
func (r *profileRulePackRetry) rulePack(now time.Time) *guardrail.RulePack {
	if r.rules(now) == nil {
		return nil
	}
	return r.pack.Load()
}

// pendingRulePackNote is the explain warning for a profile whose rule pack
// for connectorName has not loaded yet, or "".
func (set *guardrailProfileSet) pendingRulePackNote(profile string, cfg *config.Config, connectorName string) string {
	if set == nil || cfg == nil || len(set.missing) == 0 {
		return ""
	}
	retry := set.missing[effectiveRulePackKey(cfg, connectorName)]
	if retry == nil || retry.rules(time.Now()) != nil {
		return ""
	}
	retry.mu.Lock()
	reason := retry.lastErr
	retry.mu.Unlock()
	return fmt.Sprintf("profile %s: its rule pack did not load (%s), so its requests scan with the base rule set; "+
		"the gateway retries the pack every %s and uses it once it loads", firstNonEmpty(profile, "default"), reason, profileRulePackRetryInterval)
}

// profileRulePackScopes lists every rule-pack scope a derived configuration
// can resolve for some connector, one per composed-pack key, including the
// connectors some profile tunes (tuned, from profileConnectorNames: computed
// once for all profiles, as walking every profile for each derived
// configuration was quadratic).
func profileRulePackScopes(cfg *config.Config, tuned []string) []rulePackScope {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var scopes []rulePackScope
	add := func(scope rulePackScope) {
		if scope.dir == "" && scope.ref.Name == "" && len(scope.layers) == 0 {
			return
		}
		if _, ok := seen[scope.key()]; ok {
			return
		}
		seen[scope.key()] = struct{}{}
		scopes = append(scopes, scope)
	}
	add(globalRulePackScope(cfg))
	for name := range cfg.Guardrail.Connectors {
		add(connectorRulePackScope(cfg, name))
	}
	for _, name := range tuned {
		add(connectorRulePackScope(cfg, name))
	}
	if cfg.ApplicationProtection.Enabled {
		// Disabled application protection selects no rule pack (GAP-0975).
		// A connector it protects automatically scans with its connector
		// scope: the overlay pack with application_protection.guardrail.rules
		// layered in. The overlay scope listed here before carried no
		// connector, so it lacked those rules and matched no request, and an
		// auto-protected Claude Code or Codex request scanned with the base
		// rule set (GAP-1508). List the scope of every connector it can
		// protect, keyed as the request is (effectiveRulePackKey).
		for _, name := range profileAutoProtectableConnectors() {
			add(connectorRulePackScope(cfg, name))
		}
		for _, name := range cfg.ApplicationProtection.IncludeConnectors {
			add(connectorRulePackScope(cfg, name))
		}
		for name := range cfg.ApplicationProtection.Connectors {
			add(connectorRulePackScope(cfg, name))
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].key() < scopes[j].key() })
	return scopes
}

// profileAutoProtectableConnectors are the built-in connectors, each of which
// application protection can pick up without a manual connector entry.
var profileAutoProtectableConnectors = sync.OnceValue(func() []string {
	return connector.NewDefaultRegistry().Names()
})

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
func (a *APIServer) initGuardrailProfiles(cfg *config.Config) {
	set, err := newGuardrailProfileSet(cfg, nil, false)
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
type profileRuleScanConnectorKey struct{}

// withGuardrailProfileDecision resolves the request's profile once, right
// after authentication, and stores it on ctx. routeConnector is the
// connector the server-side route serves (never a payload value). It is a
// no-op when no profiles are configured.
// It also pins the API server's published generation on ctx, so the rules,
// judge, profiles and policy stamp of the request come from one generation
// (GAP-0455).
func (a *APIServer) withGuardrailProfileDecision(ctx context.Context, routeConnector string) context.Context {
	if g := a.generation(); g.published() {
		ctx = withPinnedGeneration(ctx, g)
	}
	set := a.requestProfileSet(ctx)
	if set != nil && requestProfilePath(ctx) == profilePathHook && routeConnector != "" {
		// Profile selection may resolve the agent before the hook body is
		// parsed. Keep that verified identity for this hook's later
		// correlation, evaluation and audit work as well.
		facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: routeConnector})
		ctx = withHookIdentitySnapshot(ctx, facts)
	}
	return withGuardrailProfile(ctx, set, routeConnector)
}

// requestProfileSet is the profile set decisions for ctx read: the set of
// the generation pinned on ctx, else this API server's live set. A reload
// publishes the next generation before the live set changes, so reading the
// live set could pair one generation's rules with another's mode and
// thresholds (GAP-1295).
func (a *APIServer) requestProfileSet(ctx context.Context) *guardrailProfileSet {
	if g := pinnedGeneration(ctx); g.published() {
		return g.Profiles
	}
	return a.guardrailProfileSet()
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
// or reached (profileAssignmentConnector) and its verified user. The derivation
// covers the inspect endpoints, which carry no agent identity, and the
// resolution at authentication, before the hook path has derived one.
func requestAgentIdentity(ctx context.Context) (id string, verified bool) {
	if id, verified = agentIdentityFromContext(ctx); id != "" {
		return id, verified
	}
	connectorName := profileAssignmentConnector(ctx)
	if connectorName == "" {
		return "", false
	}
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connectorName})
	return facts.ID, facts.Verified
}

// requestLegacyAgentIdentity is the legacy identity (1.0.0 to 1.0.3,
// agentidentity.LegacyAgentID) of agent, the agent identity of ctx, with
// what proves it agent's (profileAgentClaim), and true; an empty claim and
// true for a SID, whose identity did not change. It derives the identity
// again for ctx's verified user and connector, as the hook path does, and
// returns false when that derivation is not agent. Every request derives
// its own: no state is kept, so none can be dropped.
func requestLegacyAgentIdentity(ctx context.Context, agent string) (profileAgentClaim, bool) {
	connectorName := profileAssignmentConnector(ctx)
	if connectorName == "" || agent == "" {
		return profileAgentClaim{}, false
	}
	facts := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connectorName})
	if facts.ID == "" || !strings.EqualFold(facts.ID, agent) {
		return profileAgentClaim{}, false
	}
	return legacyAgentClaim(facts.LegacyID, facts.UserID, facts.MachineHash, facts.account, facts.self), true
}

// guardrailProfileInspectMiddleware resolves the profile for the inspect
// endpoints, whose connector comes from the authenticated hook credential.
func (a *APIServer) guardrailProfileInspectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		scanConnector := profileAssignmentConnector(ctx)
		if scanConnector == "" && r.URL.Path == "/api/v1/inspect/tool" {
			// An unscoped tool inspect scans the gateway's configured
			// connector. That is the scope of its scans, not a connector
			// the request authenticated for: connector and agent
			// assignments do not match it (profileAssignmentConnector).
			scanConnector = a.connectorName()
		}
		// The other inspect routes scan the authenticated connector or the
		// global generation. An empty value is an explicit global scope.
		ctx = context.WithValue(ctx, profileRuleScanConnectorKey{}, canonicalConnectorRulePackKey(scanConnector))
		next.ServeHTTP(w, r.WithContext(a.withGuardrailProfileDecision(ctx, "")))
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
	set := a.requestProfileSet(ctx)
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
	var legacy profileAgentLegacy
	if source != "" && subject != nil {
		if id, ok := profileAgentSource(ctx); ok {
			agent = strings.TrimSpace(id)
			legacy = func() (profileAgentClaim, bool) { return profileAgentLegacySource(ctx, agent) }
		}
	}
	connectorName := profileAssignmentConnector(ctx)
	scans := set.requestScanScopes(ctx, connectorName)
	decision := set.matchAgent(subject, source, connectorName, scans, agent, legacy)
	resolved := &resolvedGuardrailProfile{decision: decision, set: set}
	if decision.Name != "" {
		if meet := set.meet(decision.Name); meet != nil {
			// A meet decides each path with its members that block there.
			resolved.derived = meet.pathConfig(requestProfilePath(ctx))
		} else if derived, ok := set.derivedProfile(decision.Name); ok {
			resolved.derived = derived.Config
		}
	}
	return resolved
}

// profileRequestSubject returns the verified subject of ctx and where it
// came from, or ("", "") when the request has none.
func profileRequestSubject(ctx context.Context) (*profileSubject, string) {
	// A sandbox bearer names a host user for attribution, but it does not
	// authenticate the process calling the loopback ingress. Never inherit
	// the gateway owner's verified subject for these requests. The one
	// exception is a call the managed gateway took over its hook socket from
	// the sandbox's own daemon and whose registration it matched to the
	// kernel peer (sandboxRelayAdmit): it carries that peer's subject.
	if isSandboxHookRequest(ctx) {
		if isRelayVerifiedSandboxRequest(ctx) {
			if subject, ok := profileSubjectSource(ctx); ok && !subject.viaProcessOwner {
				return &subject, profileSubjectVerified
			}
		}
		return nil, ""
	}
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

// profileRequestConnector returns the connector the request's scans and
// settings read: the one it authenticated for or reached
// (profileAssignmentConnector), else the scan scope the inspect middleware
// recorded (the gateway's connector for an unscoped tool inspect).
// Payload and header connector names are never consulted.
func profileRequestConnector(ctx context.Context) string {
	if name := profileAssignmentConnector(ctx); name != "" {
		return name
	}
	if ctx != nil {
		if name, _ := ctx.Value(profileRuleScanConnectorKey{}).(string); name != "" {
			return name
		}
	}
	return ""
}

// profileAssignmentConnector returns the connector the request authenticated
// for (hook-scoped credential or inspect scope) or the hook route it
// reached: the recorded connector connector and agent assignments match.
func profileAssignmentConnector(ctx context.Context) string {
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
			}, identityLookupBlocking.Load()), true
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
// has unknown groups, not empty ones. A verified ID remains usable.
//
// The account name is the bare one (alice for Unix alice@corp.example.com
// and CORP\alice) here; a Windows SID keeps a literal @ in its LSA account
// name. For every caller, a request and `explain --user` both
// build their subject through this function, so a users entry cannot match
// one and not the other (GAP-0182). A name whose domain the directory facts
// do not confirm keeps its domain (profileUserName). The account domain a
// DOMAIN\user entry matches is the one the directory confirmed (winbind,
// SSSD by the SID, the LSA, Open Directory); only on Windows, where the LSA
// names every account DOMAIN\name, does the name itself give it (GAP-0814).
func profileSubjectFromVerified(s VerifiedSubject, lookupAttempted bool) profileSubject {
	userName, nameUnconfirmed := profileUserName(s.UserName, s.Directory)
	if s.IDKind == useridentity.KindWindowsSID {
		userName, nameUnconfirmed = verifiedAccountName(s.UserID, s.UserName), false
	}
	windowsToken := s.Directory.Source == useridentity.SourceWindowsLSA || s.Directory.Source == useridentity.SourceWindowsIdentityStore
	tokenGroupsCause := ""
	switch {
	case !lookupAttempted || !windowsToken:
	case s.Directory.GroupsPartial:
		tokenGroupsCause = "the account has no desktop session, so its sign-in token groups are unknown until it signs in at the desktop again"
	case awaitingSpool(s.Directory):
		tokenGroupsCause = "the guardian has no identity record for this account yet; a desktop sign-in (console or Remote Desktop) writes it"
	}
	accountDomain := s.Directory.AccountDomain
	if accountDomain == "" && runtime.GOOS == "windows" {
		if domain, _, qualified := strings.Cut(s.UserName, `\`); qualified {
			accountDomain = domain
		}
	}
	return profileSubject{
		UserID:        s.UserID,
		IDKind:        s.IDKind,
		UserName:      userName,
		Principal:     s.Directory.Principal,
		UPN:           s.Directory.UPN,
		Directory:     s.Directory.Directory,
		Domain:        s.Directory.Domain,
		AccountDomain: accountDomain,
		Groups:        s.Directory.Groups,
		// The names of these gids are unknown, not absent.
		unconfirmedGroups: s.Directory.UnconfirmedGroups,
		accountToken:      firstNonEmpty(s.Directory.AccountSID, s.Directory.AccountRecord),
		upnUnproven:       lookupAttempted && !s.Directory.ResolvedAt.IsZero() && awaitingSpoolUPN(s.Directory),
		GroupsUnknown:     lookupAttempted && s.Directory.GroupsPartial,
		LookupFailed: lookupAttempted && (s.Directory.ResolvedAt.IsZero() ||
			windowsToken && awaitingSpool(s.Directory) && !s.Directory.GroupsPartial),
		tokenGroupsCause: tokenGroupsCause,
		viaProcessOwner:  s.Source == subjectSourceProcessOwner,
		nameUnconfirmed:  nameUnconfirmed,
		localAccount:     s.Directory.Directory == useridentity.DirectoryLocal,
		qualifiedNamesMayCollide: (s.Directory.Source == useridentity.SourceSSSD ||
			s.Directory.Source == useridentity.SourceSSSDInfoPipe) &&
			s.Directory.Directory == useridentity.DirectoryActiveDirectory &&
			strings.ContainsAny(s.UserName, `@\`) &&
			(s.Directory.QualifiedNamesMayCollide || len(useridentity.TrustedADChildDomains()) > 0),
		holderUnproven: lookupAttempted && s.Directory.HolderUnproven,
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
	var ambiguous *useridentity.AmbiguousAccountError
	var namesakesUnknown *useridentity.NamesakesUnknownError
	if errors.As(err, &ambiguous) || errors.As(err, &namesakesUnknown) {
		return profileSubject{UserName: name}, err
	}
	if err != nil {
		return profileExplainUnresolved(name, err)
	}
	facts, err := profileExplainDirectoryFacts(id)
	if err != nil {
		// A required lookup failure leaves directory-dependent assignments unresolved. With
		// agent- or connector-only assignments, live requests can still match
		// without directory facts. Keep the error for explain (GAP-0124).
		return profileSubject{
			UserID: id, IDKind: useridentity.KindForID(id), UserName: userName,
			LookupFailed: identityLookupBlocking.Load(), LookupError: err.Error(),
		}, nil
	}
	if facts.ResolvedAt.IsZero() {
		if local, localErr := lookupLocalProfileSubject(name); localErr == nil {
			if !identityLookupBlocking.Load() {
				local.LookupFailed = false
			}
			return local, nil
		}
		// The account is named, so explain shows it with the reason, not a
		// bare default_lookup_failed.
		return profileSubject{UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, LookupFailed: identityLookupBlocking.Load()},
			fmt.Errorf("the operating system returned no directory facts for %s", id)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
	}, identityLookupBlocking.Load())
	_, _, failing := cachedDirectoryRefreshFailure(id)
	subject.refreshed, subject.accountName = !failing, userName
	return subject, nil
}

// explainEnrollmentExempt reports whether enterprise.enrollment.exempt_users
// lists the explained account, matched as the gateway matches a caller:
// on Linux and macOS by its uid or its account name as the account database
// gives it, never root (managedHookAuthorizer.hostRunExempt); on Windows by SID, account name or
// DOMAIN\account (requireSandboxAccountListed). Explain names the exemption
// and what it does not change (GAP-0328).
func explainEnrollmentExempt(cfg *config.Config, subject *profileSubject) bool {
	if cfg == nil || subject == nil || subject.UserID == "" || !cfg.StandaloneEnterprise() ||
		len(cfg.Enterprise.Enrollment.ExemptUsers) == 0 {
		return false
	}
	if subject.IDKind == useridentity.KindWindowsSID {
		return requireSandboxAccountListed(cfg.Enterprise.Enrollment.ExemptUsers, VerifiedSubject{
			UserID: subject.UserID, IDKind: subject.IDKind, UserName: subject.UserName,
			Directory: useridentity.DirectoryFacts{
				AccountDomain: subject.AccountDomain, Directory: subject.Directory, Domain: subject.Domain,
				UPN: subject.UPN, Principal: subject.Principal,
			},
		})
	}
	uid, err := strconv.Atoi(subject.UserID)
	if err != nil || uid == 0 {
		// Root is never exempt: enterprise.enrollment.root governs it, and
		// the hook socket never marks its calls exempt (hostRunExempt).
		return false
	}
	name := firstNonEmpty(subject.accountName, subject.UserName)
	if (&managedHookAuthorizer{enrollment: cfg.Enterprise.Enrollment}).hostRunExempt(managedHookPeer{UID: uid, Name: name}) {
		return true
	}
	// The explained subject's own facts, which the hook cache takes from
	// explain (GAP-0336), match as the hook socket matches them (GAP-0494).
	return !subject.LookupFailed && subject.Directory != "" && anyMatches(cfg.Enterprise.Enrollment.ExemptUsers, func(entry string) bool {
		return userEntryMatches(subject, entry)
	})
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
	local, known := profileAccountLocality(account)
	subject := profileSubject{
		UserID:          account.Uid,
		IDKind:          useridentity.KindForID(account.Uid),
		UserName:        useridentity.BareAccountName(account.Username),
		localAccount:    local,
		nameUnconfirmed: !known,
	}
	groups, err := accountGroups(account)
	subject.Groups = groups
	if err != nil {
		// Groups that could not be listed are unknown, not empty. A request
		// whose assignment needs them is refused (default_lookup_failed),
		// and explain names the missing group fact and the lookup error.
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

// match is selectProfile for a request without an unresolved agents entry
// (matchAgent has the bridge's answer).
func (set *guardrailProfileSet) match(subject *profileSubject, source, connectorName, agent string) profileDecision {
	return set.matchResolved(subject, resolveIdentity(subject, nil), source, connectorName, nil, agent)
}

// matchResolved is selectProfile, memoised for repeated subjects whose
// facts are all proven. An uncertain decision is never cached, including a
// pending Windows assignment group SID lookup.
func (set *guardrailProfileSet) matchResolved(subject *profileSubject, res identityResolution, source, connectorName string, scans []string, agent string) profileDecision {
	scans = set.scanScopes(connectorName, scans)
	if set.matches == nil || !res.proven() {
		return set.selectProfile(subject, res, source, connectorName, scans, agent)
	}
	key := profileMatchKey(subject, source, connectorName, scans, agent)
	if set.groupSIDs != nil {
		waitForGroup := subject != nil && source != "" && !subject.LookupFailed && len(subject.Groups) > 0
		set.groupSIDs.refresh(time.Now(), waitForGroup)
		key = set.groupSIDs.matchKey(key)
	}
	if decision, ok := set.matches.get(key); ok {
		return decision
	}
	decision := set.selectProfile(subject, res, source, connectorName, scans, agent)
	if decision.Refused == "" {
		set.matches.put(key, decision)
	}
	return decision
}

// matchUncached is selectProfile without the memo, for a request without an
// unresolved agents entry.
func (set *guardrailProfileSet) matchUncached(subject *profileSubject, source, connectorName, agent string) profileDecision {
	return set.selectProfile(subject, resolveIdentity(subject, nil), source, connectorName, nil, agent)
}

func (set *guardrailProfileSet) decision(name, reason, group, source string) profileDecision {
	decision := profileDecision{Name: name, Match: reason, MatchedGroup: group, SubjectSource: source}
	if derived, ok := set.derivedProfile(name); ok {
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
		if !anyMatches(m.Agents, func(v string) bool { return agentEntryMatches(v, agent) }) {
			return "", "", false
		}
		reason, group = profileMatchAgent, ""
	}
	return reason, group, true
}

// agentEntryMatches reports whether an agents entry names agent.
func agentEntryMatches(entry, agent string) bool {
	return agent != "" && strings.EqualFold(strings.TrimSpace(entry), agent)
}

// profileUserName is the name users entries match: the bare account, or,
// unconfirmed, the whole name when it carries a DNS domain (user@domain) that
// the directory facts do not give the account. With short SSSD names a plain
// LDAP domain may name an account by an e-mail address in the joined domain
// (dcad-bob@dclab.test, GAP-0596): its bare part is the name of another
// account, the AD dcad-bob, so no users entry selects it by name. A
// DOMAIN\name outside Windows is unconfirmed the same way unless the facts
// confirm its domain: nslcd and a plain LDAP domain of SSSD may name an
// account DCLAB\dcad-bob, which is then selected by its uid only (GAP-0814).
func profileUserName(name string, facts useridentity.DirectoryFacts) (string, bool) {
	bare, domain := useridentity.SplitQualifiedName(name)
	if !identityFactsEnabled.Load() {
		return bare, false
	}
	if strings.Contains(name, `\`) {
		if runtime.GOOS != "windows" && domain != "" && !useridentity.EqualFold(domain, facts.AccountDomain) &&
			!useridentity.EqualFold(domain, facts.Domain) {
			return strings.TrimSpace(name), true
		}
		return bare, false
	}
	if strings.Contains(domain, ".") && !strings.EqualFold(domain, facts.Domain) {
		return strings.TrimSpace(name), true
	}
	return bare, false
}

// userEntryMatches reports whether a users entry names the subject: its uid
// or SID, its account name without the domain, its principal or UPN, or its
// account in DOMAIN\user form, the name winbind and Windows report. The
// subject's name is bare and its principal is a UPN or user@REALM, so that
// form matched none of them (GAP-0316). It is the one matcher: requests,
// `explain` and the unmatched-entry warnings all call it (GAP-0310).
//
// A bare name selects directory accounts only. A local account of the same
// name is another person (a local ent-alice next to the domain ent-alice),
// so it is selected by its uid or SID, or as .\name or COMPUTER\name
// (GAP-0305, GAP-0313, GAP-0418).
func userEntryMatches(subject *profileSubject, entry string) bool {
	// A name that kept its unconfirmed domain (profileUserName) is matched
	// by no entry: an entry with an @ is a principal or a UPN.
	userName := subject.UserName
	if subject.nameUnconfirmed {
		userName = ""
	}
	bareName := userName
	if subject.localAccount {
		bareName = ""
	}
	if anyEqualFold([]string{subject.UserID, bareName}, entry) ||
		useridentity.PrincipalsEqual(subject.Principal, entry) || useridentity.PrincipalsEqual(subject.UPN, entry) {
		return true
	}
	domain, account, qualified := strings.Cut(strings.TrimSpace(entry), `\`)
	return qualified && account != "" && useridentity.EqualFold(account, userName) && subjectInDomain(subject, domain)
}

func ambiguousBareUserEntry(subject *profileSubject, entry string) bool {
	entry = strings.TrimSpace(entry)
	return subject != nil && subject.qualifiedNamesMayCollide && entry != "" &&
		!strings.ContainsAny(entry, `@\`) && useridentity.KindForID(entry) == "" &&
		useridentity.EqualFold(entry, subject.UserName)
}

// subjectInDomain compares only verified account namespaces. Guessing a
// NetBIOS name from a DNS first label can select a different trusted domain.
// ".\user", the form Windows tools use for an account of this computer,
// names an account the verified facts place in the local account database,
// on every platform (GAP-0636, GAP-0305).
func subjectInDomain(subject *profileSubject, domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "." {
		return subject.localAccount
	}
	return domain != "" && (useridentity.EqualFold(domain, subject.AccountDomain) ||
		useridentity.EqualFold(domain, subject.Domain))
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
	// sids, on standalone Windows, gives each group name an assignment
	// writes its SID: the name matches the SID of the group and nothing
	// else (GAP-0860).
	sids *profileGroupSIDs
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
	if g.sids != nil {
		if profileGroupNeedsSID(want) {
			sid, ok := g.sids.sid(want)
			if !ok {
				return false
			}
			_, ok = g.exact[foldKey(sid)]
			return ok
		}
		// A SID names only that group, never another group's SID-shaped name.
		_, ok := g.exact[foldKey(want)]
		return ok
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
// derived configuration of the requests profile, or the live generations
// configuration (a.scannerCfg for an API server without a generation).
func (a *APIServer) decisionConfig(ctx context.Context) *config.Config {
	if a == nil {
		return nil
	}
	// Secure Client keeps the pre-profile startup policy path (issue #1092).
	if a.scannerCfg != nil && a.scannerCfg.SecureClientIntegration() {
		return a.scannerCfg
	}
	return a.decisionConfigFrom(ctx, a.liveBaseConfig(ctx))
}

// liveBaseConfig is the configuration decisions start from before a profile
// applies: the request's pinned generation, else the live one, else the
// start-time configuration.
func (a *APIServer) liveBaseConfig(ctx context.Context) *config.Config {
	if g := a.decisionGeneration(ctx); g != nil && g.Config != nil {
		return g.Config
	}
	return a.scannerCfg
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
	if set := pinnedProfileSet(ctx); set != nil && (resolved == nil || resolved.set != set) {
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	if resolved != nil && resolved.derived != nil {
		if generation := resolved.ruleGenerationFor(ctx, connectorName); generation != nil {
			return generation
		}
	}
	return pinnedRuleGeneration(ctx, connectorName)
}

// scanAllRulesFor is ScanAllRules with the request's profile rule pack.
func scanAllRulesFor(ctx context.Context, text, toolName string) []RuleFinding {
	return scanAllRulesForConnectorFor(ctx, profileRequestConnector(ctx), text, toolName)
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

// ruleGenerationFor is ruleGeneration for a request on ctx: a meet scans
// with every rule of its members' packs, the base generation's included.
func (r *resolvedGuardrailProfile) ruleGenerationFor(ctx context.Context, connectorName string) *compiledRulePackCategories {
	if r != nil && r.set != nil {
		if meet := r.set.meet(r.decision.Name); meet != nil {
			return meet.ruleGeneration(ctx, r.set, connectorName)
		}
	}
	return r.ruleGeneration(connectorName)
}

// ruleGeneration is the compiled rule pack of the resolved profile for
// connectorName, nil when it is the base configuration's.
func (r *resolvedGuardrailProfile) ruleGeneration(connectorName string) *compiledRulePackCategories {
	if r == nil || r.set == nil || r.derived == nil || r.set.base == nil {
		return nil
	}
	key := effectiveRulePackKey(r.derived, connectorName)
	if key == "" || key == effectiveRulePackKey(r.set.base, connectorName) {
		return nil
	}
	if rules, listed := r.set.rules[key]; listed {
		if rules != nil {
			return rules
		}
		if retry := r.set.missing[key]; retry != nil {
			return retry.rules(time.Now())
		}
		return nil
	}
	return r.set.lazyRules(r.decision.Name, r.derived, connectorName, key)
}

// profileLazyScope is a profile rule-pack scope loaded on its first request.
type profileLazyScope struct {
	once  sync.Once
	rules *compiledRulePackCategories
	retry *profileRulePackRetry
}

// lazyRules loads a scope the start-time preload did not list (a plugin
// connector under application protection, say) on its first request instead
// of scanning that request with the base rule set (GAP-1508). Concurrent
// first requests wait for the one load. A pack that does not load is retried
// like one that did not load at start (GAP-0333).
func (set *guardrailProfileSet) lazyRules(profile string, cfg *config.Config, connectorName, key string) *compiledRulePackCategories {
	value, _ := set.lazy.LoadOrStore(key, &profileLazyScope{})
	entry := value.(*profileLazyScope)
	entry.once.Do(func() {
		scope := connectorRulePackScope(cfg, connectorName)
		rp, err := loadScopedRulePack(guardrail.NewRulePackCache(), cfg, scope, "guardrail profile "+profile)
		var compiled *compiledRulePackCategories
		if err == nil {
			compiled, err = compileRulePackCategories(rp)
		}
		if err == nil {
			entry.rules = compiled
			return
		}
		fmt.Fprintf(os.Stderr, "[guardrail] profile %s: %v; it scans with the base rule set until the pack loads (retried every %s)\n",
			profile, err, profileRulePackRetryInterval)
		entry.retry = &profileRulePackRetry{profile: profile, cfg: cfg, scope: scope,
			lastErr: err.Error(), nextTry: time.Now().Add(profileRulePackRetryInterval)}
	})
	if entry.rules != nil {
		return entry.rules
	}
	return entry.retry.rules(time.Now())
}

// proxyProfileFor returns the profile resolution the guardrail proxy applies
// to ctx, whose profile withProxyAgent resolved for the proxy's connector and
// agent. It applies only to a request with a verified user-scoped identity;
// without one (nil) the proxy keeps its own settings.
func proxyProfileFor(ctx context.Context) *resolvedGuardrailProfile {
	if ctx != nil && ctx.Value(unverifiedProxyCallerKey{}) == true {
		return nil
	}
	set := pinnedProfileSet(ctx)
	if set == nil {
		return nil
	}
	resolved := resolvedGuardrailProfileFrom(ctx)
	if resolved == nil || resolved.set != set {
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	if resolved == nil || resolved.derived == nil || resolved.decision.SubjectSource == "" {
		return nil
	}
	return resolved
}

// profileProxyOverride returns the mode and block message the guardrail
// proxy applies for ctx (proxyProfileFor).
func profileProxyOverride(ctx context.Context, connectorName string) (mode, blockMessage string, ok bool) {
	resolved := proxyProfileFor(ctx)
	if resolved == nil {
		return "", "", false
	}
	connectorName = config.NormalizeConnectorName(connectorName)
	return resolved.derived.Guardrail.EffectiveMode(connectorName),
		resolved.derived.Guardrail.EffectiveBlockMessage(connectorName), true
}

// proxyRuleGeneration is the rule pack the guardrail proxy scans ctx's
// content with: the one its profile selects (proxyProfileFor) when that is
// another pack than the base configuration's, else the process-global one.
// The proxy scanned every request with the global pack, so a profile's
// rule_pack_dir never reached OpenClaw or ZeptoClaw traffic (GAP-0313).
func proxyRuleGeneration(ctx context.Context) *compiledRulePackCategories {
	connectorName := profileRequestConnector(ctx)
	if resolved := proxyProfileFor(ctx); resolved != nil {
		if generation := resolved.ruleGenerationFor(ctx, connectorName); generation != nil {
			return generation
		}
	}
	return pinnedRuleGeneration(ctx, connectorName)
}

// proxyGuardrailProfileTelemetryFor describes only a profile actually used
// by proxyProfileFor. An unverified shared-gateway request uses the proxy's
// base settings, even when a connector assignment resolves on the context.
func proxyGuardrailProfileTelemetryFor(ctx context.Context) guardrailProfileTelemetry {
	resolved := proxyProfileFor(ctx)
	if resolved == nil {
		return guardrailProfileTelemetry{}
	}
	return guardrailProfileTelemetryFromDecision(resolved.decision)
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
	set := pinnedProfileSet(ctx)
	resolved := resolvedGuardrailProfileFrom(ctx)
	if set == nil {
		if resolved == nil || resolved.set != nil {
			return guardrailProfileTelemetry{}
		}
		// A supplied decision without a profile set is used by callers that
		// construct a standalone decision record.
		return guardrailProfileTelemetryFromDecision(resolved.decision)
	}
	if resolved == nil || resolved.set != set {
		resolved = resolveGuardrailProfileFor(ctx, set)
	}
	return guardrailProfileTelemetryFromDecision(resolved.decision)
}

func guardrailProfileTelemetryFromDecision(d profileDecision) guardrailProfileTelemetry {
	out := guardrailProfileTelemetry{Match: observability.Present(d.Match)}
	if d.Refused != "" {
		// A candidate profile is not the caller's proven policy. Keep the
		// refusal match without recording an inferred profile or group.
		return out
	}
	if d.Name != "" {
		out.Name = observability.Present(d.Name)
		out.Digest = observability.Present(d.Digest)
	}
	if d.Match == profileMatchGroup && profileTelemetryGroupFits(d.MatchedGroup) {
		out.MatchedGroup = observability.Present(d.MatchedGroup)
	}
	return out
}

// maxProfileMatchedGroupBytes is the registry bound of
// defenseclaw.guardrail.profile.matched_group.
const maxProfileMatchedGroupBytes = 256

// profileTelemetryGroupFits reports whether a matched group fits the
// attribute. An assignment may name a longer group (the config allows 512
// characters), and a value out of range fails the whole record, which every
// producer then dropped (GAP-0319). Such a group is left out; the profile and
// the match still say what selected it, and explain names the group.
func profileTelemetryGroupFits(group string) bool {
	return group != "" && len(group) <= maxProfileMatchedGroupBytes && utf8.ValidString(group) &&
		!strings.ContainsFunc(group, func(r rune) bool { return r < 0x20 || r == 0x7f })
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

// refreshDirectoryFactsOnProfileChange has the next request of every
// account refresh its cached directory facts when a reload changes the
// guardrail profiles or their assignments, so a pushed group assignment
// applies at the next decision (GAP-1036).
func refreshDirectoryFactsOnProfileChange(oldCfg, newCfg *config.Config) {
	if oldCfg == nil || newCfg == nil {
		return
	}
	before, after := oldCfg.Guardrail, newCfg.Guardrail
	if reflect.DeepEqual(before.Profiles, after.Profiles) && reflect.DeepEqual(before.ProfileAssignments, after.ProfileAssignments) &&
		before.DefaultProfile == after.DefaultProfile {
		return
	}
	peerDirectoryCache().invalidate()
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

// profileEnrollmentExemption describes the hook's exemption decision in a
// profile explanation. The no-profile answer must not refer to a profile.
func profileEnrollmentExemption(cfg *config.Config, subject *profileSubject, withProfile bool) (map[string]any, string) {
	if !explainEnrollmentExempt(cfg, subject) {
		return nil, ""
	}
	warning := "this account is in enterprise.enrollment.exempt_users: it is not enrolled and required_for never refuses " +
		"its host runs, but its calls are still inspected under "
	if withProfile {
		warning += "the profile above, which blocks findings at its block_at, and logged "
	} else {
		warning += "the guardrail settings and logged "
	}
	return map[string]any{"exempt": true}, warning + "(defenseclaw.user.enrollment: exempt)"
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
	// Explain the base that decisions use: the published generation.
	if g := a.generation(); g != nil && g.Config != nil && (base == nil || !base.SecureClientIntegration()) {
		base = g.Config
	}
	if base != nil && base.SecureClientIntegration() {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "guardrail profiles are not supported with the Secure Client integration"})
		return
	}
	query := r.URL.Query()
	user := strings.TrimSpace(query.Get("user"))
	connectorName := config.NormalizeConnectorName(query.Get("connector"))
	agent := strings.TrimSpace(query.Get("agent"))

	set := a.guardrailProfileSet()
	if connectorName != "" && !connector.IsKnownBuiltinConnector(connectorName) &&
		(set == nil || !set.knownConnector(connectorName)) {
		known := connector.NewDefaultRegistry().Names()
		if base != nil {
			for name := range base.Guardrail.Connectors {
				known = append(known, config.NormalizeConnectorName(name))
			}
		}
		sort.Strings(known)
		known = slices.Compact(known)
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("unknown connector %q; valid connectors: %s", connectorName, strings.Join(known, ", "))})
		return
	}
	out := map[string]any{
		"profiles_configured": set != nil,
		"user":                user,
		"connector":           connectorName,
		"agent":               agent,
	}
	// The subject is resolved with or without profiles, so the identity check
	// (`profile explain --user U --json | jq .subject`) answers on every
	// install (GAP-0280).
	var subject *profileSubject
	source := ""
	refreshedFacts := false
	if user != "" {
		found, err := profileExplainSubjectLookup(user)
		if caller, ok := profileExplainCallerSubject(query.Get("caller_facts"), user); ok {
			// The administrator's own NSS lookup as root resolved the account
			// (GAP-0500); the gateway's lookup above still refreshed what the
			// hooks read, and the cache block says what they use.
			found, err = caller, nil
			out["facts_source"] = "caller"
		}
		var ambiguous *useridentity.AmbiguousAccountError
		if errors.As(err, &ambiguous) {
			// A bare name two accounts share is explained as neither: the
			// answer names both, and the administrator names one (GAP-1087).
			out["lookup_error"] = err.Error()
			out["accounts"] = ambiguous.Accounts
			out["profile"], out["match"] = "", ""
			out["effective"] = profileEffectiveView(base, connectorName)
			a.writeJSON(w, http.StatusOK, out)
			return
		}
		if err != nil {
			if found.UserID == "" {
				found = profileSubject{UserName: user}
			}
			found.LookupFailed = identityLookupBlocking.Load()
			out["lookup_error"] = err.Error()
		} else if found.LookupError != "" {
			out["lookup_error"] = found.LookupError
		} else if found.refreshed && found.UserID != "" {
			// Explain's lookup refreshed the cache the hooks read, so they use
			// the facts it resolved from their next call and the cache block
			// below states what they use now (GAP-0336). It used to store the
			// facts again, which also restarted the hour of facts kept
			// through a failed lookup and cleared the failure: polled
			// explains kept an outage's stale facts in use indefinitely
			// (GAP-0496, GAP-0517).
			refreshedFacts = true
		}
		if found.accountUnresolved {
			out["account_unresolved"] = true
		}
		subject, source = &found, profileSubjectLookup
		// directory says where the account lives (local, active_directory,
		// ...): a bare users entry selects a directory account only (GAP-0305).
		out["subject"] = map[string]any{
			"user_id": found.UserID, "user_name": found.UserName,
			"principal": found.Principal, "upn": found.UPN, "groups": found.Groups,
			"group_count": identityGroupCount(found.Groups), "directory": string(found.Directory),
		}
	}
	if set == nil {
		out["profile"] = ""
		out["match"] = ""
		out["effective"] = profileEffectiveView(base, connectorName)
		var warnings []string
		if enrollment, warning := profileEnrollmentExemption(base, subject, false); enrollment != nil {
			out["enrollment"] = enrollment
			warnings = append(warnings, warning)
		}
		if note := inertHILTWarning(base, connectorName); note != "" {
			warnings = append(warnings, note)
		}
		if len(warnings) > 0 {
			out["warnings"] = warnings
		}
		a.writeJSON(w, http.StatusOK, out)
		return
	}
	if source == "" {
		agent = ""
	}
	scans := set.requestScanScopes(r.Context(), connectorName)
	decision := set.matchAgent(subject, source, connectorName, scans, agent, nil)
	out["profile"] = decision.Name
	out["digest"] = decision.Digest
	out["match"] = decision.Match
	out["matched_group"] = decision.MatchedGroup
	if decision.Match == profileMatchGroup && decision.MatchedGroup != "" {
		// A bare group name matches a local group and a directory group of
		// that name alike; explain names which one the account is in (GAP-0356).
		if source := matchedGroupSource(set, subject, decision.MatchedGroup); source != "" {
			out["matched_group_source"] = source
		}
	}
	out["subject_source"] = decision.SubjectSource
	out["assignment"] = decision.Assignment
	warnings := profileExplainWarnings(set, decision, subject)
	if len(decision.Unproven) > 0 {
		out["unproven_facts"] = decision.Unproven
	}
	if decision.Refused != "" {
		out["refused"] = true
		out["refused_reason"] = decision.Refused
	}
	if len(decision.Candidates) > 0 {
		// An administrator view: the profiles that may apply, and the
		// candidate floor. A refused decision cannot authorize a request.
		out["candidate_profiles"] = decision.Candidates
		if config.IsProfileMeet(decision.Name) {
			if decision.Refused != "" {
				warnings = append(warnings, fmt.Sprintf("more than one profile may apply (%s): their strictest combination is diagnostic; "+
					"requests are refused until identity facts are confirmed", strings.Join(decision.Candidates, ", ")))
			} else {
				warnings = append(warnings, fmt.Sprintf("more than one profile may apply (%s): their strictest combination applies, "+
					"with every block, rule pack and sandbox limit of each and only the allows they share", strings.Join(decision.Candidates, ", ")))
			}
		}
	}
	if agent != "" {
		warnings = append(warnings, fmt.Sprintf("agent %q is not verified against a host identity record by profile-explain; confirm it with agent identities before relying on this answer", agent))
	}
	if source == profileSubjectLookup {
		if view, warning := explainCacheView(set, subject, decision, connectorName, agent, time.Now()); view != nil {
			out["cache"] = view
			if warning != "" {
				warnings = append(warnings, warning)
			}
		}
		if subject != nil && !subject.LookupFailed && slices.ContainsFunc(set.assignments, func(a config.ProfileAssignment) bool { return len(a.Match.Groups) > 0 }) {
			warnings = append(warnings, profileCacheWindowNote(refreshedFacts, runtime.GOOS))
		}
	}
	if view, _ := directoryHealthView(directoryCacheHealth(), time.Now()); view != nil {
		out["directory"] = view
	}
	if enrollment, warning := profileEnrollmentExemption(base, subject, true); enrollment != nil {
		// exempt_users skips enrollment and the sandbox requirement only;
		// the profile still inspects and blocks (GAP-0328).
		out["enrollment"] = enrollment
		warnings = append(warnings, warning)
	}
	effective := set.base
	if derived, ok := set.derivedProfile(decision.Name); ok {
		effective = derived.Config
	}
	if note := set.pendingRulePackNote(decision.Name, effective, connectorName); note != "" {
		warnings = append(warnings, note)
	}
	if note := inertHILTWarning(effective, connectorName); note != "" {
		warnings = append(warnings, note)
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	out["effective"] = profileEffectiveView(effective, connectorName)
	digests := guardrailProfileDigests(set)
	out["profiles"] = digests
	a.writeJSON(w, http.StatusOK, out)
}

// profileCacheWindowNote says how long a group membership change takes to
// reach the hooks. Explain hands the facts it resolved to the hook cache, so
// the explained account's hooks follow at once; other accounts' within the
// cache lifetime. On macOS, Open Directory's own cache held a removed member
// in the group for ten minutes and more (GAP-0336).
func profileCacheWindowNote(refreshed bool, goos string) string {
	note := "after a group membership change, hooks can use the previous profile for up to 15 minutes while the gateway refreshes cached identity facts; restart the gateway to refresh sooner"
	if refreshed {
		note = "explain refreshed this account's cached identity facts, so its hooks use the profile above from their next call; after a group " +
			"membership change, other accounts' hooks can use the previous profile for up to 15 minutes (explain the account, or restart the gateway, to refresh sooner)"
	}
	if goos == "darwin" {
		note += "; macOS Open Directory caches group membership itself: after a change in the directory run sudo dscacheutil -flushcache; sudo dsmemberutil flushcache"
	}
	return note
}

// profileEffectiveView is the explain summary of the policy cfg applies to
// connectorName.
func profileEffectiveView(cfg *config.Config, connectorName string) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	hilt := cfg.EffectiveHILTForConnector(connectorName)
	view := map[string]any{
		"mode":          cfg.HookModeForConnector(connectorName),
		"block_at":      cfg.Guardrail.EffectiveBlockAt(connectorName),
		"alert_at":      cfg.Guardrail.EffectiveAlertAt(connectorName),
		"rule_pack_dir": cfg.EffectiveRulePackDirForConnector(connectorName),
		"hilt":          map[string]any{"enabled": hilt.Enabled, "min_severity": hilt.MinSeverity},
	}
	if !cfg.SecureClientIntegration() {
		view["resolved_block_at"] = resolveThresholds(cfg, connectorName).Block
	}
	return view
}

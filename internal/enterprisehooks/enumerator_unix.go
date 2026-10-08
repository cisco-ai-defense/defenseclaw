//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The standalone Unix enumerator: the Linux and macOS counterpart of the
// Windows ProfileList enumerator. It discovers eligible interactive users
// and publishes the guardian manifest, preserving the protected enabled /
// deferred / version state of rows it already knows.

// UnixRevokeAfterMisses is how many consecutive definitive "no such user"
// answers remove a known row. Transient directory errors never count.
const UnixRevokeAfterMisses = 3

// unixNologinShells are login shells that mark a non-interactive account.
var unixNologinShells = map[string]struct{}{
	"/usr/sbin/nologin": {}, "/sbin/nologin": {}, "/usr/bin/nologin": {},
	"/bin/false": {}, "/usr/bin/false": {}, "/sbin/false": {},
}

// UnixEnumeratorState is persisted between cycles (root-only) so revocation
// needs several definitive misses.
type UnixEnumeratorState struct {
	Version int            `json:"version"`
	Misses  map[string]int `json:"misses,omitempty"`
	// Sources records, per enrolled user, whether the account was last
	// seen in the local account database ("files") or only through a
	// directory ("directory"). A later "no such user" is definitive for a
	// local account; for a directory account it counts only when the
	// directory is shown to be answering.
	Sources map[string]string `json:"sources,omitempty"`
	// ACPMisses and ACPSources are the same for the uid principals of
	// managed ACP enrollments, keyed by principal (uid:N).
	ACPMisses  map[string]int    `json:"acp_misses,omitempty"`
	ACPSources map[string]string `json:"acp_sources,omitempty"`
}

const (
	unixSourceFiles     = "files"
	unixSourceDirectory = "directory"
)

// UnixDiscoverFunc returns connector → version for one account, discovered
// with that account's credentials (the apply-target worker). reasons
// explains connectors without a version.
type UnixDiscoverFunc func(ctx context.Context, account unixidentity.Account, connectors []string) (versions map[string]string, reasons map[string]string, err error)

// UnixDiscovery is one account's discovery: connector → CLI version,
// reasons for connectors without one, and the connector's app and
// extension installs.
type UnixDiscovery struct {
	Versions map[string]string
	Reasons  map[string]string
	Surfaces map[string][]connector.AgentSurface
}

// UnixDiscoverSurfacesFunc is UnixDiscoverFunc plus the app and extension
// surfaces.
type UnixDiscoverSurfacesFunc func(ctx context.Context, account unixidentity.Account, connectors []string) (UnixDiscovery, error)

// UnixRefusedSurface is a (user, connector) whose only installs are
// surfaces refused under enterprise.enrollment.unverified_versions:
// refuse. The gateway refuses that user's hook calls for the connector
// (reason surface_unverified).
type UnixRefusedSurface struct {
	User      string `json:"user"`
	UID       *int   `json:"uid,omitempty"`
	Connector string `json:"connector"`
}

// UnixEnumerateOptions configures one enumeration cycle. Zero values pick
// the platform defaults.
type UnixEnumerateOptions struct {
	ExistingManifestPath string
	Resolver             unixidentity.Resolver
	// HomeRoots are the parents homes must live under (default /home,
	// /var/home on Linux; /Users on macOS) plus enrollment.home_roots.
	HomeRoots []string
	// UIDMin/UIDMax bound interactive accounts (default login.defs).
	UIDMin, UIDMax int
	// LocalAccounts returns the local account database (name → uid);
	// nil or an error leaves every account's source unknown, which keeps
	// login.defs UID_MAX for all of them and never corroborates a miss.
	LocalAccounts func() (map[string]int, error)
	// DirectoryConfigured reports whether lookups may reach a remote
	// directory; nil means they may.
	DirectoryConfigured func() bool
	// MachinePolicyConnectors come from the runtime descriptor; they get
	// per-user rows only when enrollment.unenrolled_users is "deny".
	MachinePolicyConnectors []string
	// OwnershipOffConnectors are machine-policy connectors whose machine
	// policy the administrator leaves alone (ownership: "off"). They get
	// no DefenseClaw route, so no per-user rows either, not even with
	// unenrolled_users: deny.
	OwnershipOffConnectors []string
	// SessionUIDs lists uids with a live login session.
	SessionUIDs func() []int
	Discover    UnixDiscoverFunc
	// DiscoverStatic finds agents without executing anything (package
	// metadata and the presence of the agent CLIs), with the account's
	// credentials. It runs for an eligible user whose home is untrusted
	// and who has no rows, so the agents they can run there are reported
	// even though they are not enrolled.
	DiscoverStatic UnixDiscoverFunc
	// DiscoverSurfaces, when set, replaces Discover and also returns the
	// account's app and extension installs; DiscoverStaticSurfaces
	// likewise replaces DiscoverStatic.
	DiscoverSurfaces       UnixDiscoverSurfacesFunc
	DiscoverStaticSurfaces UnixDiscoverSurfacesFunc
	// MachineVersion reads root-owned machine-scoped metadata.
	MachineVersion func(connector string) string
	// OutsideDiscovery finds a connector's CLI in an administrator prefix
	// that discovery does not search (UnixAgentOutsideDiscovery), so a
	// user without a row for it is reported instead of skipped silently.
	OutsideDiscovery func(connector string) (binary, prefix string)
	State            *UnixEnumeratorState
	Logger           EnumerationLogger
	// CheckHome classifies a candidate's home; nil uses CheckUnixTargetHome.
	CheckHome func(home string, uid int) HomeCheck
	// PreviousRefusedSurfaces are the refusals the last cycle published. A
	// user whose surface discovery fails or cannot run keeps them, so a
	// failed worker never lifts a refusal.
	PreviousRefusedSurfaces []UnixRefusedSurface
}

// UnixEnumerationReport summarizes a cycle for logs and JSON output.
type UnixEnumerationReport struct {
	Candidates int      `json:"candidates"`
	Eligible   int      `json:"eligible"`
	Rows       int      `json:"rows"`
	New        int      `json:"new"`
	Deferred   int      `json:"deferred"`
	Revoked    int      `json:"revoked"`
	Skipped    []string `json:"skipped,omitempty"`
	Connectors []string `json:"connectors"`
	// Unprotected lists agents found installed for an eligible user that
	// could not be enrolled (their version could not be read). The
	// lifecycle's status and verify report them.
	Unprotected []UnprotectedAgent `json:"unprotected,omitempty"`
	// RefusedSurfaces are the (user, connector) pairs the gateway refuses
	// under unverified_versions: refuse.
	RefusedSurfaces []UnixRefusedSurface `json:"refused_surfaces,omitempty"`
	// EligibleAccounts are the accounts that passed every enrollment filter
	// and whose home is available this cycle, including users with only
	// machine-policy connectors (no manifest rows). The guardian runs the
	// per-user foreign-hook cleanup for them.
	EligibleAccounts []UnixEligibleAccount `json:"-"`
	// IdentityAccounts are the accounts that pass every enrollment filter
	// but whose home is untrusted, so they are not enrolled. The guardian
	// still keeps their identity record (GAP-0714).
	IdentityAccounts []UnixEligibleAccount `json:"-"`
	// DirectoryAnswered is set when a directory account resolved in this
	// cycle, which makes another directory account's "no such user"
	// definitive.
	DirectoryAnswered bool `json:"-"`
}

// UnixEligibleAccount is one enrolled-or-eligible account in the
// root-only eligible-accounts record next to the manifest.
type UnixEligibleAccount struct {
	User      string `json:"user"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	Home      string `json:"home"`
	HomeInode uint64 `json:"home_inode,omitempty"`
	// CreatedDirs, only in the guardian's VS Code Local accounts record,
	// are the folders below Home the guardian created for DefenseClaw's
	// Local files there; their removal takes the empty ones out again.
	CreatedDirs []string `json:"created_dirs,omitempty"`
}

type unixCandidate struct {
	account  unixidentity.Account
	included bool
}

// DefaultUnixHomeRoots are the home parents the guardian units allow.
func DefaultUnixHomeRoots(goos string) []string {
	if goos == "darwin" {
		return []string{"/Users"}
	}
	return []string{"/home", "/var/home"}
}

// EffectiveUnixHookConnectors returns the enabled hook-owning connectors
// for per-user enrollment on this host, in sorted order.
func EffectiveUnixHookConnectors(cfg *config.Config, registry *connector.Registry) []string {
	if cfg == nil || registry == nil {
		return nil
	}
	disabled := map[string]struct{}{}
	seen := map[string]struct{}{}
	var out []string
	consider := func(name string, explicitlyDisabled bool) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if explicitlyDisabled {
			disabled[name] = struct{}{}
			return
		}
		if _, off := disabled[name]; off {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		conn, ok := registry.Get(name)
		if !ok || connector.IsProxyConnector(name) || !connector.OwnsManagedHookRuntime(conn) ||
			!connector.ConnectorSupportedOnHostOS(name) {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for name, perConn := range cfg.Guardrail.Connectors {
		consider(name, perConn.Enabled != nil && !*perConn.Enabled)
	}
	consider(cfg.Guardrail.Connector, false)
	sort.Strings(out)
	return out
}

// EnumerateUnix discovers eligible users and returns the manifest to
// publish. It never writes; WriteUnixTargetsManifestAtomic publishes.
func EnumerateUnix(ctx context.Context, cfg *config.Config, registry *connector.Registry, opts UnixEnumerateOptions) (Manifest, UnixEnumerationReport, error) {
	report := UnixEnumerationReport{}
	if cfg == nil {
		return Manifest{}, report, errors.New("enterprise hooks: enumerate: nil config")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Resolver == nil {
		return Manifest{}, report, errors.New("enterprise hooks: enumerate: no account resolver")
	}
	if opts.State == nil {
		opts.State = &UnixEnumeratorState{Version: 1}
	}
	if opts.State.Misses == nil {
		opts.State.Misses = map[string]int{}
	}
	if opts.State.Sources == nil {
		opts.State.Sources = map[string]string{}
	}
	enrollment := cfg.Enterprise.Enrollment
	connectors := EffectiveUnixHookConnectors(cfg, registry)
	machinePolicy := map[string]struct{}{}
	for _, name := range opts.MachinePolicyConnectors {
		machinePolicy[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	ownershipOff := map[string]struct{}{}
	for _, name := range opts.OwnershipOffConnectors {
		ownershipOff[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	var perUser []string
	for _, name := range connectors {
		if _, off := ownershipOff[name]; off {
			continue
		}
		if _, isMachine := machinePolicy[name]; isMachine &&
			!strings.EqualFold(strings.TrimSpace(enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) {
			continue
		}
		perUser = append(perUser, name)
	}
	report.Connectors = perUser
	outsideFound := map[string][2]string{}
	outsideDiscovery := func(conn string) (string, string) {
		if opts.OutsideDiscovery == nil {
			return "", ""
		}
		found, known := outsideFound[conn]
		if !known {
			found[0], found[1] = opts.OutsideDiscovery(conn)
			outsideFound[conn] = found
		}
		return found[0], found[1]
	}
	// Machine-policy connectors whose unenrolled users are inspected get no
	// rows; with unverified_versions: refuse their surfaces are still
	// discovered, so the gateway can refuse a user whose only installs are
	// refused surfaces.
	var surfaceOnly []string
	for _, name := range connectors {
		if _, off := ownershipOff[name]; off || connectorListed(perUser, name) {
			continue
		}
		if _, isMachine := machinePolicy[name]; isMachine && enrollment.UnverifiedVersionsFor(name) == config.EnterpriseUnverifiedRefuse {
			surfaceOnly = append(surfaceOnly, name)
		}
	}

	previous, err := loadPreviousUnixRows(opts.ExistingManifestPath)
	if err != nil {
		// Publishing from scratch would re-enable administrator-disabled
		// rows and drop known users without the miss count. Keep the file
		// as it is until an administrator repairs it.
		return Manifest{}, report, err
	}
	uidMin, uidMax := opts.UIDMin, opts.UIDMax
	if enrollment.UIDMin > 0 {
		uidMin = enrollment.UIDMin
	}
	sources := newUnixAccountSources(opts.LocalAccounts, opts.DirectoryConfigured, opts.State.Sources, opts.Logger)
	// upperBound is the highest uid enrolled for account. login.defs
	// UID_MAX describes the local useradd range: directory accounts (SSSD
	// id-mapping from 200000, FreeIPA ranges, systemd-homed 60001-60513)
	// routinely sit above it, so it bounds only local accounts unless the
	// administrator sets enterprise.enrollment.uid_max.
	upperBound := func(account unixidentity.Account) int {
		if enrollment.UIDMax > 0 {
			return enrollment.UIDMax
		}
		if sources.sourceOf(account) == unixSourceDirectory {
			return 0
		}
		return uidMax
	}
	homeRoots := normalizeHomeRoots(opts.HomeRoots)
	checkHome := opts.CheckHome
	if checkHome == nil {
		// A hung network home must not stall the whole cycle: no new user
		// would be enrolled and no deleted one revoked while the process
		// stays alive, so the service manager never restarts it.
		checkHome = func(home string, uid int) HomeCheck {
			return BoundedCheckUnixTargetHome(home, uid, unixHomeProbeTimeout)
		}
	}

	candidates, _ := collectUnixCandidates(ctx, opts, enrollment, homeRoots)
	// Re-evaluate every previously enrolled user even when enumeration did
	// not surface it (SSSD enumerate=false, a logged-out user), so a known
	// row is only dropped by a filter decision or repeated definitive
	// "no such user" answers — never by an incomplete listing.
	keep := map[string]struct{}{}
	missing := map[string]struct{}{}
	listed := map[string]struct{}{}
	previousUsers := map[string]struct{}{}
	previousUIDs := map[string]map[int]bool{}
	for _, prev := range previous {
		previousUsers[strings.TrimSpace(prev.User)] = struct{}{}
		addEnrolledUID(previousUIDs, prev)
	}
	// cachedLocal reports an enrolled local account that the local database
	// no longer lists but a lookup still resolves with the enrolled uid (a
	// lookup cache). A resolved account with another uid is a different
	// account under the same name, for example one moved to a directory:
	// it is a candidate like any other and gets a row for its new uid.
	cachedLocal := func(userName string, account unixidentity.Account) bool {
		return sources.goneLocally(userName) && sameEnrolledUID(previousUIDs, userName, account.UID)
	}
	logGoneLocally := func(userName string) {
		logfSafely(opts.Logger, userName, "no longer in the local account database; a cached lookup still resolves it, so it counts as not found")
	}
	resolvedCandidates := candidates[:0]
	for _, candidate := range candidates {
		name := candidate.account.Name
		listed[name] = struct{}{}
		if _, enrolled := previousUsers[name]; enrolled && cachedLocal(name, candidate.account) {
			missing[name] = struct{}{}
			logGoneLocally(name)
			continue
		}
		resolvedCandidates = append(resolvedCandidates, candidate)
	}
	candidates = resolvedCandidates
	for _, prev := range previous {
		userName := strings.TrimSpace(prev.User)
		if _, ok := listed[userName]; ok || userName == "" {
			continue
		}
		listed[userName] = struct{}{}
		account, err := opts.Resolver.LookupUser(userName)
		switch {
		case err == nil && cachedLocal(userName, account):
			missing[userName] = struct{}{}
			logGoneLocally(userName)
		case err == nil:
			candidates = append(candidates, unixCandidate{account: account})
		case unixidentity.IsNotFound(err):
			missing[userName] = struct{}{}
		default:
			keep[userName] = struct{}{}
			logfSafely(opts.Logger, userName, fmt.Sprintf("directory lookup failed; keeping known rows unchanged: %v", err))
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].account.Name < candidates[j].account.Name })
	report.Candidates = len(candidates)
	// A directory account that resolved this cycle shows the directory is
	// answering, which is what makes another directory account's "no such
	// user" (getent exit 2, also its answer while a backend is down)
	// definitive.
	resolvedSource := map[string]string{}
	directoryAnswered := false
	for _, candidate := range candidates {
		source := sources.sourceOf(candidate.account)
		resolvedSource[candidate.account.Name] = source
		if source == unixSourceDirectory && !systemdLocalUID(candidate.account.UID) {
			directoryAnswered = true
		}
	}
	report.DirectoryAnswered = directoryAnswered
	definitiveMiss := func(user string) bool {
		return sources.definitiveMiss(user, directoryAnswered)
	}
	filtered := map[string]struct{}{}
	include := stringSet(enrollment.IncludeUsers)
	exclude := stringSet(enrollment.ExcludeUsers)
	exempt := stringSet(enrollment.ExemptUsers)

	var targets []ManifestTarget
	emitted := map[string]struct{}{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return Manifest{}, report, err
		}
		account := candidate.account
		name := account.Name
		skip := func(reason string) {
			report.Skipped = append(report.Skipped, name+": "+reason)
			logfSafely(opts.Logger, name, reason)
		}
		// exclude_users and exempt_users match an account name or its
		// decimal uid. The gateway authorizes exempt callers by
		// kernel-verified uid, and directory names it cannot resolve are
		// easiest to list by uid, so both spellings must mean the same.
		uidText := strconv.Itoa(account.UID)
		if _, byName := exclude[name]; byName || hasKey(exclude, uidText) {
			skip("excluded by enterprise.enrollment.exclude_users")
			continue
		}
		if _, byName := exempt[name]; byName || hasKey(exempt, uidText) {
			skip("exempt by enterprise.enrollment.exempt_users")
			continue
		}
		_, explicitlyIncluded := include[name]
		if account.UID == 0 {
			skip("root is never a guardian target")
			continue
		}
		if account.UID == 65534 || name == "nobody" {
			skip("nobody is never a guardian target")
			continue
		}
		if !explicitlyIncluded {
			if reason := unixReservedUID(account.UID); reason != "" {
				skip(reason)
				continue
			}
			if account.UID < uidMin {
				skip(fmt.Sprintf("uid %d outside the interactive range (below %d)", account.UID, uidMin))
				continue
			}
			if bound := upperBound(account); bound > 0 && account.UID > bound {
				skip(fmt.Sprintf("uid %d outside the interactive range %d-%d", account.UID, uidMin, bound))
				continue
			}
		}
		if _, nologin := unixNologinShells[filepath.Clean(account.Shell)]; nologin && !explicitlyIncluded {
			skip("non-interactive login shell " + account.Shell)
			continue
		}
		if ok, transientErr, counted, reason := groupFilterAllows(opts.Resolver, account, enrollment); !ok {
			if transientErr {
				keep[name] = struct{}{}
			} else if _, enrolled := previousUsers[name]; enrolled && counted {
				// A missing include-group membership can be a partial
				// answer from a degraded directory: revoke only after
				// repeated answers, like a missing account.
				filtered[name] = struct{}{}
			}
			skip(reason)
			continue
		}
		home := filepath.Clean(account.Home)
		if !homeUnderRoots(home, homeRoots) {
			skip(fmt.Sprintf("home %s is outside the guardian-writable home roots %v", home, homeRoots))
			continue
		}
		check := checkHome(home, account.UID)
		if check.State == HomeUntrusted {
			// The mode of a home is the user's to change: it must not
			// change the identity, and so the profile, the gateway gives
			// him (GAP-0714).
			report.IdentityAccounts = append(report.IdentityAccounts, UnixEligibleAccount{
				User: name, UID: account.UID, GID: account.GID, Home: home,
			})
			if _, enrolled := previousUsers[name]; enrolled {
				// A user must not unenroll themselves by loosening their
				// own home's mode: keep the rows so the guardian reports
				// the trust failure instead of silently dropping them.
				keep[name] = struct{}{}
				skip(check.Reason + "; keeping the existing enrollment")
				continue
			}
			skip(check.Reason)
			// Nor may a user hide the agents they run by loosening their
			// home before they are first enrolled: report them, or the
			// account itself when no agent is found, so status and verify
			// name it (GAP-0646).
			agents := unixUntrustedHomeAgents(ctx, opts, account, perUser, machinePolicy, check)
			if len(agents) == 0 {
				agents = append(agents, UnprotectedAgent{
					User: name, UID: intPointer(account.UID), Code: UnprotectedCodeHomeUntrusted,
					Reason: check.Reason + "; DefenseClaw does not enroll this account, so it gets no hooks, IDE " +
						"inventory or discovery until group and other write are removed from the home",
				})
			}
			report.Unprotected = append(report.Unprotected, agents...)
			continue
		}
		report.Eligible++
		if check.State == HomeAvailable {
			report.EligibleAccounts = append(report.EligibleAccounts, UnixEligibleAccount{
				User: name, UID: account.UID, GID: account.GID, Home: home, HomeInode: check.Inode,
			})
		}
		var versions, reasons map[string]string
		var surfaces map[string][]connector.AgentSurface
		surfacesKnown := false
		if check.State == HomeAvailable && opts.DiscoverSurfaces != nil {
			found, err := opts.DiscoverSurfaces(ctx, account, append(append([]string{}, perUser...), surfaceOnly...))
			if err != nil {
				logfSafely(opts.Logger, name, fmt.Sprintf("version discovery failed; keeping known rows: %v", err))
			}
			versions, reasons, surfaces = found.Versions, found.Reasons, found.Surfaces
			surfacesKnown = err == nil
		} else if check.State == HomeAvailable && opts.Discover != nil {
			var err error
			versions, reasons, err = opts.Discover(ctx, account, perUser)
			if err != nil {
				logfSafely(opts.Logger, name, fmt.Sprintf("version discovery failed; keeping known rows: %v", err))
			}
		}
		report.Unprotected = append(report.Unprotected, applyKiroIDESurface(name, account.UID, versions, reasons)...)
		for _, conn := range surfaceOnly {
			if !surfacesKnown && opts.DiscoverSurfaces != nil {
				// Discovery failed or the home is unavailable: keep the last
				// cycle's refusal instead of publishing none.
				if previouslyRefusedSurface(opts.PreviousRefusedSurfaces, name, account.UID, conn) {
					report.RefusedSurfaces = append(report.RefusedSurfaces, UnixRefusedSurface{User: name, UID: intPointer(account.UID), Connector: conn})
				}
				continue
			}
			unprotected, refused := unixSurfaceOnlyRefusals(account, conn, versions[conn], surfaces[conn], enrollment.UnverifiedVersionsFor(conn))
			report.Unprotected = append(report.Unprotected, unprotected...)
			if refused {
				report.RefusedSurfaces = append(report.RefusedSurfaces, UnixRefusedSurface{User: name, UID: intPointer(account.UID), Connector: conn})
			}
		}
		// Only an available home's inode identifies it. A pending home's
		// inode belongs to whatever is visible while it is unavailable (a
		// locked ecryptfs home shows its lower mountpoint directory, whose
		// inode differs from the mounted root's), so it is neither compared
		// nor bound: comparing it re-enrolled or revoked the user on every
		// logout.
		currentInode := uint64(0)
		if check.State == HomeAvailable {
			currentInode = check.Inode
		}
		for _, conn := range perUser {
			key := unixRowKey(name, conn)
			_, isMachine := machinePolicy[conn]
			admission := admitSurfaces(conn, enrollment.UnverifiedVersionsFor(conn), surfaces[conn])
			cliVersion := versions[conn]
			if rowVersion := admission.rowVersion(cliVersion); rowVersion != cliVersion {
				if versions == nil {
					versions = map[string]string{}
				}
				versions[conn] = rowVersion
				logfSafely(opts.Logger, name, fmt.Sprintf("(%s, %s) follows its %s surface at engine version %s", name, conn, admission.surface, rowVersion))
			}
			// A per-user connector's user whose only installs are refused
			// surfaces gets a refusal row: its hooks are installed so the
			// gateway can refuse the user's calls, instead of the agent
			// running without DefenseClaw.
			refusalVersion := ""
			if check.State == HomeAvailable && !isMachine && versions[conn] == "" {
				refusalVersion = unixRefusalRowVersion(conn, admission)
			}
			if refusalVersion != "" {
				report.RefusedSurfaces = append(report.RefusedSurfaces, UnixRefusedSurface{User: name, UID: intPointer(account.UID), Connector: conn})
				for _, rejected := range admission.rejected {
					report.Unprotected = append(report.Unprotected, rejected.unprotected(account.Name, "", intPointer(account.UID), conn,
						"it is the user's only "+conn+" install, so DefenseClaw enrolls a refusal row and the gateway refuses this user's "+conn+" hook calls (surface_unverified)", RefusalEnforced))
				}
			} else if check.State == HomeAvailable {
				_, known := previous[key]
				report.Unprotected = append(report.Unprotected, unixRejectedSurfaces(account, conn, isMachine, known || versions[conn] != "", admission)...)
			}
			if refusalVersion == "" && !isMachine && !surfacesKnown && opts.DiscoverSurfaces != nil &&
				previouslyRefusedSurface(opts.PreviousRefusedSurfaces, name, account.UID, conn) {
				// Discovery failed or the home is unavailable: the kept
				// refusal row keeps its refusal.
				report.RefusedSurfaces = append(report.RefusedSurfaces, UnixRefusedSurface{User: name, UID: intPointer(account.UID), Connector: conn})
			}
			row := ManifestTarget{
				User:      name,
				UserHome:  home,
				UID:       intPointer(account.UID),
				GID:       intPointer(account.GID),
				Connector: conn,
				DataDir:   filepath.Join(home, ".defenseclaw"),
				HomeInode: currentInode,
			}
			if prev, known := previous[key]; known && sameUnixIdentity(prev, row) {
				row.AgentVersion = prev.AgentVersion
				row.Enabled = prev.Enabled
				if check.State == HomeAvailable {
					if version := versions[conn]; version != "" && version != prev.AgentVersion && prev.IsEnabled() {
						if refused := unixKnownRowVersionRefused(conn, prev.AgentVersion, version); refused == "" {
							row.AgentVersion = version
						} else {
							logfSafely(opts.Logger, name, fmt.Sprintf("(%s, %s) agent version changed from %s to %s, which is not followed (%s); keeping the row at its last verified version", name, conn, prev.AgentVersion, version, refused))
							report.Unprotected = append(report.Unprotected, UnprotectedAgent{
								User:      name,
								UID:       intPointer(account.UID),
								Connector: conn,
								Version:   version,
								Code:      UnprotectedCodeForReason(refused),
								Reason: fmt.Sprintf("%s; the row stays enrolled at %s, so the guardian keeps repairing this user's hooks as rendered for %s, not for the installed version",
									refused, prev.AgentVersion, prev.AgentVersion),
							})
						}
					}
					row.Deferred = false
				} else {
					row.Deferred = prev.IsEnabled()
					row.HomeInode = prev.HomeInode
				}
				targets = append(targets, row)
				emitted[key] = struct{}{}
				continue
			} else if known {
				logfSafely(opts.Logger, name, fmt.Sprintf("uid or home changed for (%s, %s); re-enrolling as a new target", name, conn))
			}
			version := versions[conn]
			if check.State != HomeAvailable && opts.MachineVersion != nil {
				version = opts.MachineVersion(conn)
			}
			if version == "" && refusalVersion != "" {
				version = refusalVersion
				logfSafely(opts.Logger, name, fmt.Sprintf("(%s, %s) enrolled as a refusal row at %s: the user's only installs are refused surfaces", name, conn, version))
			}
			if version == "" {
				reason := reasons[conn]
				if reason == "" {
					reason = "no supported installation found"
				}
				consequence := "it runs without DefenseClaw hooks"
				if _, isMachine := machinePolicy[conn]; isMachine {
					consequence = "it is not enrolled, so the gateway refuses its tool calls (enrollment.unenrolled_users: deny)"
				}
				if check.State != HomeAvailable {
					reason = check.Reason
				} else if UnixAgentInstalledWithoutVersion(reason) {
					report.Unprotected = append(report.Unprotected, UnprotectedAgent{
						User:      name,
						UID:       intPointer(account.UID),
						Connector: conn,
						Code:      UnprotectedCodeAgentUnprotected,
						Reason:    reason + "; DefenseClaw cannot select a hook contract without a version, so " + consequence,
					})
				} else if binary, prefix := outsideDiscovery(conn); binary != "" {
					report.Unprotected = append(report.Unprotected, UnprotectedAgent{
						User:      name,
						UID:       intPointer(account.UID),
						Connector: conn,
						Code:      UnprotectedCodeAgentUnprotected,
						Reason: fmt.Sprintf("installed at %s, a prefix DefenseClaw does not search for agents; add %s to enterprise.enrollment.agent_prefixes. Until then %s",
							binary, prefix, consequence),
					})
				}
				logfSafely(opts.Logger, name, fmt.Sprintf("new (%s, %s) row skipped: %s", name, conn, reason))
				continue
			}
			enabled := true
			row.AgentVersion = version
			row.Enabled = &enabled
			row.Deferred = check.State != HomeAvailable
			if row.Deferred {
				report.Deferred++
			}
			report.New++
			targets = append(targets, row)
			emitted[key] = struct{}{}
		}
	}

	// Known rows that were not re-emitted: keep them through transient
	// failures, count definitive misses, and revoke only after
	// UnixRevokeAfterMisses consecutive "no such user" answers or an
	// explicit filter decision.
	for key, prev := range previous {
		if _, ok := emitted[key]; ok {
			delete(opts.State.Misses, key)
			continue
		}
		if !connectorListed(perUser, prev.Connector) {
			// The connector is no longer enabled for per-user enrollment.
			delete(opts.State.Misses, key)
			report.Revoked++
			continue
		}
		userName := strings.TrimSpace(prev.User)
		if _, transientErr := keep[userName]; transientErr {
			targets = append(targets, prev)
			continue
		}
		_, gone := missing[userName]
		_, filteredOut := filtered[userName]
		if gone && !definitiveMiss(userName) {
			// getent reports "no such user" both for a deleted account and
			// for any account while sssd, nslcd or ypbind cannot reach the
			// directory; nothing shows the directory answering this cycle.
			logfSafely(opts.Logger, userName, fmt.Sprintf("account not found, but the directory could not be confirmed reachable; keeping (%s, %s) unchanged", userName, prev.Connector))
			targets = append(targets, prev)
			continue
		}
		if gone || filteredOut {
			what := "account not found"
			if filteredOut {
				what = "no longer passes the enrollment group filter"
			}
			opts.State.Misses[key]++
			if opts.State.Misses[key] < UnixRevokeAfterMisses {
				logfSafely(opts.Logger, userName, fmt.Sprintf("%s (%d/%d); keeping (%s, %s) for now", what, opts.State.Misses[key], UnixRevokeAfterMisses, userName, prev.Connector))
				targets = append(targets, prev)
				continue
			}
			logfSafely(opts.Logger, userName, fmt.Sprintf("%s %d times; revoking (%s, %s)", what, UnixRevokeAfterMisses, userName, prev.Connector))
		}
		delete(opts.State.Misses, key)
		report.Revoked++
	}
	for key := range opts.State.Misses {
		if _, known := previous[key]; !known {
			delete(opts.State.Misses, key)
		}
	}
	withRows := map[string]struct{}{}
	for _, target := range targets {
		withRows[strings.TrimSpace(target.User)] = struct{}{}
	}
	for user := range opts.State.Sources {
		if _, ok := withRows[user]; !ok {
			delete(opts.State.Sources, user)
		}
	}
	for user := range withRows {
		if source := resolvedSource[user]; source != "" {
			opts.State.Sources[user] = source
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].User != targets[j].User {
			return targets[i].User < targets[j].User
		}
		return targets[i].Connector < targets[j].Connector
	})
	report.Rows = len(targets)
	if targets == nil {
		targets = []ManifestTarget{}
	}
	return Manifest{Version: 1, Targets: targets}, report, nil
}

// unixAccountSources tells a local account from a directory account and
// decides whether a "no such user" answer is definitive. The enumerator and
// RevokeGoneUnixTargets share it.
type unixAccountSources struct {
	local               map[string]int
	localKnown          bool
	directoryConfigured bool
	// recorded is UnixEnumeratorState.Sources: where each enrolled user
	// was last seen.
	recorded map[string]string
}

func newUnixAccountSources(localAccounts func() (map[string]int, error), directoryConfigured func() bool, recorded map[string]string, logger EnumerationLogger) unixAccountSources {
	sources := unixAccountSources{recorded: recorded}
	if localAccounts != nil {
		if accounts, err := localAccounts(); err == nil {
			sources.local, sources.localKnown = accounts, true
		} else {
			logfSafely(logger, "directory", fmt.Sprintf("local account database unreadable; account sources are unknown this cycle: %v", err))
		}
	}
	sources.directoryConfigured = directoryConfigured == nil || directoryConfigured()
	return sources
}

// sourceOf classifies a resolved account; "" when it cannot tell.
func (s unixAccountSources) sourceOf(account unixidentity.Account) string {
	if !s.localKnown {
		return ""
	}
	if uid, ok := s.local[account.Name]; ok && uid == account.UID {
		return unixSourceFiles
	}
	return unixSourceDirectory
}

// goneLocally reports an enrolled local account that the local account
// database no longer lists. A lookup can still resolve it for a while: a
// long-running process on macOS keeps answering from its directory cache
// for minutes after the record is deleted, as nscd can on Linux. That
// answer must neither keep the account enrolled nor reclassify it as a
// directory account, which made every later "no such user" count as a
// possible directory outage, so the row was never revoked.
func (s unixAccountSources) goneLocally(user string) bool {
	if !s.localKnown || s.recorded[user] != unixSourceFiles {
		return false
	}
	_, listed := s.local[user]
	return !listed
}

// addEnrolledUID records the uid a manifest row was enrolled with.
func addEnrolledUID(uids map[string]map[int]bool, target ManifestTarget) {
	if target.UID == nil {
		return
	}
	user := strings.TrimSpace(target.User)
	if uids[user] == nil {
		uids[user] = map[int]bool{}
	}
	uids[user][*target.UID] = true
}

// sameEnrolledUID reports whether uid is the uid user's rows were enrolled
// with. Rows without a recorded uid cannot tell, and count as the same.
func sameEnrolledUID(uids map[string]map[int]bool, user string, uid int) bool {
	enrolled := uids[user]
	return len(enrolled) == 0 || enrolled[uid]
}

// definitiveMiss reports whether a "no such user" answer for user proves
// the account is gone. directoryAnswered is set when a directory account
// resolved in the same pass.
func (s unixAccountSources) definitiveMiss(user string, directoryAnswered bool) bool {
	if s.localKnown {
		if _, stillLocal := s.local[user]; stillLocal {
			return false // the local database still has it: lookups are failing
		}
	}
	return !s.directoryConfigured || s.recorded[user] == unixSourceFiles || directoryAnswered
}

// UnixRevokeGoneOptions configures RevokeGoneUnixTargets; the fields mean
// what they mean in UnixEnumerateOptions.
type UnixRevokeGoneOptions struct {
	ExistingManifestPath string
	Resolver             unixidentity.Resolver
	LocalAccounts        func() (map[string]int, error)
	DirectoryConfigured  func() bool
	State                *UnixEnumeratorState
	Logger               EnumerationLogger
}

// UnixRevokeGoneReport is what RevokeGoneUnixTargets decided.
type UnixRevokeGoneReport struct {
	Rows int `json:"rows"`
	// Revoked lists the removed rows as user/connector.
	Revoked []string `json:"revoked,omitempty"`
	// Kept explains, per account, why the rows of an account that did not
	// resolve stay.
	Kept []string `json:"kept,omitempty"`
	// DirectoryAnswered is UnixEnumerationReport.DirectoryAnswered for
	// this pass.
	DirectoryAnswered bool `json:"-"`
}

// RevokeGoneUnixTargets returns the published manifest without the rows of
// accounts that no longer exist. The enumerator removes such a row after
// UnixRevokeAfterMisses cycles; an administrator's repair runs this so a
// deleted account's target is removed at once instead of failing the host
// for another 10 to 15 minutes. "No longer exist" is the enumerator's
// definitive miss: a failed lookup, or a "no such user" answer that an
// unreachable directory could also give, keeps the rows. It never writes.
func RevokeGoneUnixTargets(ctx context.Context, opts UnixRevokeGoneOptions) (Manifest, UnixRevokeGoneReport, error) {
	report := UnixRevokeGoneReport{}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Resolver == nil {
		return Manifest{}, report, errors.New("enterprise hooks: revoke deleted accounts: no account resolver")
	}
	if opts.State == nil {
		opts.State = &UnixEnumeratorState{Version: 1}
	}
	if opts.State.Misses == nil {
		opts.State.Misses = map[string]int{}
	}
	if opts.State.Sources == nil {
		opts.State.Sources = map[string]string{}
	}
	path := strings.TrimSpace(opts.ExistingManifestPath)
	manifest, err := LoadManifest(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{Version: 1, Targets: []ManifestTarget{}}, report, nil
		}
		return Manifest{}, report, fmt.Errorf("enterprise hooks: revoke deleted accounts: the manifest %s does not load, so it is kept unchanged: %w", path, err)
	}
	sources := newUnixAccountSources(opts.LocalAccounts, opts.DirectoryConfigured, opts.State.Sources, opts.Logger)
	var users []string
	seen := map[string]struct{}{}
	enrolledUIDs := map[string]map[int]bool{}
	for _, target := range manifest.Targets {
		addEnrolledUID(enrolledUIDs, target)
		user := strings.TrimSpace(target.User)
		if _, dup := seen[user]; dup || user == "" {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	sort.Strings(users)
	missing := map[string]struct{}{}
	directoryAnswered := false
	for _, user := range users {
		if err := ctx.Err(); err != nil {
			return Manifest{}, report, err
		}
		account, err := opts.Resolver.LookupUser(user)
		switch {
		case err == nil && sources.goneLocally(user) && sameEnrolledUID(enrolledUIDs, user, account.UID):
			missing[user] = struct{}{}
		case err == nil:
			if sources.sourceOf(account) == unixSourceDirectory && !systemdLocalUID(account.UID) {
				directoryAnswered = true
			}
		case unixidentity.IsNotFound(err):
			missing[user] = struct{}{}
		default:
			reason := err.Error()
			if len(reason) > 200 {
				reason = reason[:200]
			}
			report.Kept = append(report.Kept, fmt.Sprintf("%s: the account lookup failed, so its targets stay: %s", user, reason))
		}
	}
	report.DirectoryAnswered = directoryAnswered
	gone := map[string]struct{}{}
	for _, user := range users {
		if _, ok := missing[user]; !ok {
			continue
		}
		// Repair removes rows in one pass, with none of the enumerator's
		// three-cycle margin, so it acts only on a local account database it
		// could read: a short dscl or opendirectoryd failure would otherwise
		// look like every local account being deleted at once.
		if !sources.localKnown {
			report.Kept = append(report.Kept, fmt.Sprintf("%s: account not found, but the local account database could not be read, so its targets stay", user))
			continue
		}
		if sources.definitiveMiss(user, directoryAnswered) {
			gone[user] = struct{}{}
			continue
		}
		report.Kept = append(report.Kept, fmt.Sprintf("%s: account not found, but the directory could not be confirmed reachable, so its targets stay", user))
	}
	targets := make([]ManifestTarget, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		user := strings.TrimSpace(target.User)
		if _, ok := gone[user]; ok {
			report.Revoked = append(report.Revoked, user+"/"+strings.ToLower(strings.TrimSpace(target.Connector)))
			delete(opts.State.Misses, unixRowKey(user, target.Connector))
			logfSafely(opts.Logger, user, fmt.Sprintf("account no longer exists; revoking (%s, %s)", user, target.Connector))
			continue
		}
		targets = append(targets, target)
	}
	for user := range gone {
		delete(opts.State.Sources, user)
	}
	if manifest.Version == 0 {
		manifest.Version = 1
	}
	manifest.Targets = targets
	report.Rows = len(targets)
	return manifest, report, nil
}

func collectUnixCandidates(ctx context.Context, opts UnixEnumerateOptions, enrollment config.EnterpriseEnrollmentConfig, homeRoots []string) ([]unixCandidate, bool) {
	byName := map[string]*unixCandidate{}
	transient := false
	add := func(account unixidentity.Account, included bool) {
		if existing, ok := byName[account.Name]; ok {
			existing.included = existing.included || included
			return
		}
		byName[account.Name] = &unixCandidate{account: account, included: included}
	}
	if accounts, _, err := opts.Resolver.ListUsers(); err == nil {
		for _, account := range accounts {
			add(account, false)
		}
	} else {
		transient = true
		logfSafely(opts.Logger, "directory", fmt.Sprintf("account enumeration failed: %v", err))
	}
	resolveUID := func(uid int, source string) {
		account, err := opts.Resolver.LookupUID(uid)
		if err != nil {
			if !unixidentity.IsNotFound(err) {
				transient = true
			}
			logfSafely(opts.Logger, strconv.Itoa(uid), fmt.Sprintf("%s uid did not resolve: %v", source, err))
			return
		}
		add(account, false)
	}
	if opts.SessionUIDs != nil {
		for _, uid := range opts.SessionUIDs() {
			resolveUID(uid, "session")
		}
	}
	for _, root := range homeRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				break
			}
			path := filepath.Join(root, entry.Name())
			info, err := BoundedLstat(path, unixHomeProbeTimeout)
			if err != nil {
				if PendingTargetError(err) && !errors.Is(err, os.ErrNotExist) {
					logfSafely(opts.Logger, path, fmt.Sprintf("home owner scan skipped this entry: %v", err))
				}
				continue
			}
			if !info.IsDir() {
				continue
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid == 0 {
				continue
			}
			resolveUID(int(st.Uid), "home owner")
		}
	}
	for _, name := range enrollment.IncludeUsers {
		account, err := opts.Resolver.LookupUser(strings.TrimSpace(name))
		if err != nil {
			if !unixidentity.IsNotFound(err) {
				transient = true
			}
			logfSafely(opts.Logger, name, fmt.Sprintf("included user did not resolve: %v", err))
			continue
		}
		add(account, true)
	}
	out := make([]unixCandidate, 0, len(byName))
	for _, candidate := range byName {
		out = append(out, *candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].account.Name < out[j].account.Name })
	return out, transient
}

// unixKnownRowVersionRefused explains why a known row must not follow its
// user's agent from version from to version to: to has no verified hook
// contract while from has one. The guardian's install refuses a version
// without a verified contract, so recording it would stop every repair of
// the user's hooks, and the user could then remove them for good; the row
// keeps its last verified version and the new one is reported
// (hook_contract_unverified). Empty when the change is followed.
func unixKnownRowVersionRefused(connectorName, from, to string) string {
	if standaloneNotGatedAgentFloor(connectorName) != "" {
		// A not-gated connector (Kiro) is verified by its standalone floor
		// instead of a known contract: a row never follows a version below
		// the floor. That includes a row an earlier release enrolled below
		// the floor: the guardian keeps repairing it at its enrolled version
		// (validateHookContract), while it refuses a change to another
		// version below the floor as drift, so following one would stop
		// every repair of the user's hooks.
		admitted, reason := standaloneNotGatedVersionAdmitted(resolveHookContract(connectorName, to))
		if admitted {
			return ""
		}
		return reason
	}
	if resolveHookContract(connectorName, to).Status == connector.HookCompatibilityKnown {
		return ""
	}
	if resolveHookContract(connectorName, from).Status != connector.HookCompatibilityKnown {
		return "" // nothing verified to keep
	}
	return fmt.Sprintf("version %s is not verified against a known hook contract", strings.TrimSpace(to))
}

// unixRejectedSurfaces reports the surfaces of one (user, connector) that
// were not admitted. With a row (enrolled) a surface the report policy did
// not admit still runs the hooks rendered for the row, so it is reported
// only when it is refused: the gateway refuses the hook calls that name it
// (surfaceRefusalConsequence).
func unixRejectedSurfaces(account unixidentity.Account, conn string, isMachine, enrolled bool, admission surfaceAdmission) []UnprotectedAgent {
	var out []UnprotectedAgent
	for _, rejected := range admission.rejected {
		consequence, refusal := "it runs without DefenseClaw hooks", RefusalMissing
		switch {
		case enrolled && !rejected.refused:
			continue
		case enrolled:
			consequence, refusal = surfaceRefusalConsequence(conn, rejected)
		case isMachine:
			consequence, refusal = "it is not enrolled, so the gateway refuses its tool calls (enrollment.unenrolled_users: deny)", RefusalEnforced
		}
		out = append(out, rejected.unprotected(account.Name, "", intPointer(account.UID), conn, consequence, refusal))
	}
	return out
}

// unixRefusalRowVersion is the version a refusal row of a per-user
// connector is enrolled at (its default contract's minimum), or "" when the
// user has an admitted surface or no refused one.
func unixRefusalRowVersion(conn string, admission surfaceAdmission) string {
	if len(admission.admitted) != 0 {
		return ""
	}
	for _, rejected := range admission.rejected {
		if rejected.refused {
			version := connector.ResolveHookContract(conn, "").Contract.MinAgentVersion
			if version == "" || connector.ResolveHookContract(conn, version).Status != connector.HookCompatibilityKnown {
				return ""
			}
			return version
		}
	}
	return ""
}

// previouslyRefusedSurface reports whether the last cycle refused
// (user, connector) for this uid.
func previouslyRefusedSurface(previous []UnixRefusedSurface, user string, uid int, conn string) bool {
	for _, entry := range previous {
		if entry.User == user && entry.Connector == conn && (entry.UID == nil || *entry.UID == uid) {
			return true
		}
	}
	return false
}

// unixSurfaceOnlyRefusals reports the surfaces of a machine-policy
// connector whose unenrolled users are inspected, for a user under
// unverified_versions: refuse. refused is true when the user's only
// installs are refused surfaces: the gateway then refuses the user's hook
// calls for the connector. A user with an admitted install keeps being
// inspected; the gateway refuses only the calls that name a refused
// surface.
func unixSurfaceOnlyRefusals(account unixidentity.Account, conn, cliVersion string, surfaces []connector.AgentSurface, policy string) ([]UnprotectedAgent, bool) {
	admission := admitSurfaces(conn, policy, surfaces)
	if len(admission.rejected) == 0 {
		return nil, false
	}
	admittedInstall := cliVersion != "" || len(admission.admitted) != 0
	var out []UnprotectedAgent
	for _, rejected := range admission.rejected {
		consequence, refusal := "the gateway refuses this user's "+conn+" hook calls (surface_unverified)", RefusalEnforced
		if admittedInstall {
			consequence, refusal = surfaceRefusalConsequence(conn, rejected)
		}
		out = append(out, rejected.unprotected(account.Name, "", intPointer(account.UID), conn, consequence, refusal))
	}
	return out, !admittedInstall
}

// unixUntrustedHomeAgents reports the agents an eligible user without rows
// can run from a home the enumerator does not enroll because it is
// untrusted (group/other writable, a symlink, owned by another account, or
// covered by a user mount). Discovery there is static: it reads package
// metadata and checks for the CLIs as the user, and executes nothing in a
// home others may have written to.
func unixUntrustedHomeAgents(ctx context.Context, opts UnixEnumerateOptions, account unixidentity.Account, perUser []string, machinePolicy map[string]struct{}, check HomeCheck) []UnprotectedAgent {
	if (opts.DiscoverStatic == nil && opts.DiscoverStaticSurfaces == nil) || len(perUser) == 0 {
		return nil
	}
	var versions, reasons map[string]string
	var surfaces map[string][]connector.AgentSurface
	var err error
	if opts.DiscoverStaticSurfaces != nil {
		var found UnixDiscovery
		found, err = opts.DiscoverStaticSurfaces(ctx, account, perUser)
		versions, reasons, surfaces = found.Versions, found.Reasons, found.Surfaces
	} else {
		versions, reasons, err = opts.DiscoverStatic(ctx, account, perUser)
	}
	if err != nil {
		logfSafely(opts.Logger, account.Name, fmt.Sprintf("agents in the untrusted home could not be listed: %v", err))
		return nil
	}
	out := applyKiroIDESurface(account.Name, account.UID, versions, reasons)
	remedy := ""
	if check.LooseMode {
		remedy = "; remove group and other write from the home to enroll it"
	}
	for _, conn := range perUser {
		version := versions[conn]
		if version == "" && !UnixAgentInstalledWithoutVersion(reasons[conn]) {
			continue
		}
		consequence := "it runs without DefenseClaw hooks"
		if _, isMachine := machinePolicy[conn]; isMachine {
			// Machine-policy connectors are enrolled per user only
			// with unenrolled_users: deny.
			consequence = "it is not enrolled, so the gateway refuses its tool calls (enrollment.unenrolled_users: deny)"
		}
		out = append(out, UnprotectedAgent{
			User:      account.Name,
			UID:       intPointer(account.UID),
			Connector: conn,
			Version:   version,
			Code:      UnprotectedCodeAgentUnprotected,
			Reason:    check.Reason + "; DefenseClaw does not enroll agents in an untrusted home, so " + consequence + remedy,
		})
	}
	for _, conn := range perUser {
		for _, surface := range surfaces[conn] {
			if surface.Surface == "" || surface.Surface == connector.HostSurfaceCLI {
				continue
			}
			out = append(out, surfaceRejection{surface: surface, reason: check.Reason}.unprotected(
				account.Name, "", intPointer(account.UID), conn, "DefenseClaw does not enroll agents in an untrusted home"+remedy, ""))
		}
	}
	return out
}

// groupFilterAllows applies include/exclude groups (exclude wins). A
// transient membership failure reports transient=true so known rows stay.
// counted marks a denial that rests only on a membership being absent,
// which a degraded directory can also produce; membership of an excluded
// group is positive evidence and applies at once.
func groupFilterAllows(resolver unixidentity.Resolver, account unixidentity.Account, enrollment config.EnterpriseEnrollmentConfig) (allowed, transient, counted bool, reason string) {
	if len(enrollment.IncludeGroups) == 0 && len(enrollment.ExcludeGroups) == 0 {
		return true, false, false, ""
	}
	ids, err := resolver.GroupIDs(account)
	if err != nil {
		notFound := unixidentity.IsNotFound(err)
		return false, !notFound, notFound, fmt.Sprintf("group membership unavailable: %v", err)
	}
	names := map[string]struct{}{}
	for _, gid := range ids {
		names[strconv.Itoa(gid)] = struct{}{}
		if group, err := resolver.LookupGroupID(gid); err == nil {
			names[group.Name] = struct{}{}
		}
	}
	for _, excluded := range enrollment.ExcludeGroups {
		if _, ok := names[strings.TrimSpace(excluded)]; ok {
			return false, false, false, "member of excluded group " + excluded
		}
	}
	if len(enrollment.IncludeGroups) == 0 {
		return true, false, false, ""
	}
	for _, included := range enrollment.IncludeGroups {
		if _, ok := names[strings.TrimSpace(included)]; ok {
			return true, false, false, ""
		}
	}
	return false, false, true, "not a member of any enterprise.enrollment.include_groups group"
}

// unixReservedUID explains why uid can never be an interactive user:
// the overflow and "-1"/"-2" uids, and on Linux systemd's DynamicUser
// range.
func unixReservedUID(uid int) string {
	switch {
	case uid == 65535 || int64(uid) >= 4294967294:
		return fmt.Sprintf("uid %d is reserved", uid)
	case runtime.GOOS == "linux" && uid >= 61184 && uid <= 65519:
		return fmt.Sprintf("uid %d is a systemd dynamic service uid", uid)
	}
	return ""
}

// systemdLocalUID reports uids systemd allocates on the host itself
// (systemd-homed 60001-60513, DynamicUser 61184-65519). They come from
// nss-systemd, not a remote directory, so resolving one says nothing about
// whether the directory is reachable.
func systemdLocalUID(uid int) bool {
	return (uid >= 60001 && uid <= 60513) || (uid >= 61184 && uid <= 65519)
}

// loadPreviousUnixRows reads the published manifest's rows. A missing file
// is a first run; any other failure is returned so the cycle publishes
// nothing rather than rebuilding the manifest from scratch.
func loadPreviousUnixRows(path string) (map[string]ManifestTarget, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("enterprise hooks: enumerate: the existing manifest %s does not load, so it is kept unchanged until it is repaired: %w", path, err)
	}
	previous := make(map[string]ManifestTarget, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if key := unixRowKey(target.User, target.Connector); key != "" {
			previous[key] = target
		}
	}
	return previous, nil
}

func unixRowKey(user, conn string) string {
	user = strings.TrimSpace(user)
	conn = strings.ToLower(strings.TrimSpace(conn))
	if user == "" || conn == "" {
		return ""
	}
	return user + "\x00" + conn
}

// sameUnixIdentity reports whether a previous row still names the same
// account and home. A different uid, or a different inode for a home
// that exists, is a reused or recreated identity.
func sameUnixIdentity(prev, current ManifestTarget) bool {
	if prev.UID == nil || current.UID == nil || *prev.UID != *current.UID {
		return false
	}
	if filepath.Clean(prev.UserHome) != filepath.Clean(current.UserHome) {
		return false
	}
	if prev.HomeInode != 0 && current.HomeInode != 0 && prev.HomeInode != current.HomeInode {
		return false
	}
	return true
}

func normalizeHomeRoots(roots []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, root := range roots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "" || !filepath.IsAbs(root) || root == "/" {
			continue
		}
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	sort.Strings(out)
	return out
}

func homeUnderRoots(home string, roots []string) bool {
	for _, root := range roots {
		if rel, err := filepath.Rel(root, home); err == nil && rel != "." && rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func connectorListed(list []string, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, candidate := range list {
		if candidate == name {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func intPointer(value int) *int { return &value }

func hasKey(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

// MarshalUnixTargetsManifest renders the deterministic manifest bytes.
func MarshalUnixTargetsManifest(m Manifest) ([]byte, error) {
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Targets == nil {
		m.Targets = []ManifestTarget{}
	}
	raw, err := yaml.Marshal(&m)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: marshal manifest: %w", err)
	}
	return raw, nil
}

// WriteUnixTargetsManifestAtomic publishes m at path when its bytes change:
// root-owned 0640 file below a root-owned directory chain with no symlinks
// or group/other-writable elements, written through a same-directory temp
// file, fsync and rename. A byte-identical manifest is not rewritten, so a
// stable host never wakes the guardian's file watch.
func WriteUnixTargetsManifestAtomic(path string, m Manifest) (bool, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: path must be absolute: %s", path)
	}
	dir := filepath.Dir(path)
	if err := validateRootOwnedDirChain(dir); err != nil {
		return false, err
	}
	data, err := MarshalUnixTargetsManifest(m)
	if err != nil {
		return false, err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("enterprise hooks: existing manifest %s is not a regular file", path)
		}
		current, readErr := readBoundedFile(path, enterpriseHookManifestMaxBytes)
		if readErr == nil && bytes.Equal(current, data) {
			return false, nil
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, statErr)
	}
	tmp, err := os.CreateTemp(dir, ".defenseclaw-targets-*.new")
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: create temp manifest: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: write temp manifest: %w", err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: chmod temp manifest: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			_ = tmp.Close()
			return false, fmt.Errorf("enterprise hooks: chown temp manifest: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: sync temp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("enterprise hooks: close temp manifest: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("enterprise hooks: publish manifest: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return true, nil
}

// validateRootOwnedDirChain requires dir and every ancestor to be a real
// directory owned by root and not group/other writable.
func validateRootOwnedDirChain(dir string) error {
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect manifest directory %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is not a real directory", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is group/other writable", current)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is not root-owned", current)
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

// unixManifestTestOwnerAllowed lets unprivileged tests publish into their
// own temp directories; production runs as root, where it is never used.
var unixManifestTestOwnerAllowed = func(uid uint32) bool { return false }

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

// LoadUnixEnumeratorState reads the root-only enumerator state; a missing
// or malformed file starts fresh (the worst case is a slower revocation).
func LoadUnixEnumeratorState(path string) *UnixEnumeratorState {
	state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}}
	data, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return state
	}
	var parsed UnixEnumeratorState
	if json.Unmarshal(data, &parsed) != nil || parsed.Version != 1 {
		return state
	}
	for key, count := range parsed.Misses {
		if count > 0 && count < 1000 {
			state.Misses[key] = count
		}
	}
	for user, source := range parsed.Sources {
		if user != "" && (source == unixSourceFiles || source == unixSourceDirectory) {
			if state.Sources == nil {
				state.Sources = map[string]string{}
			}
			state.Sources[user] = source
		}
	}
	for principal, count := range parsed.ACPMisses {
		if count > 0 && count < 1000 {
			if state.ACPMisses == nil {
				state.ACPMisses = map[string]int{}
			}
			state.ACPMisses[principal] = count
		}
	}
	for principal, source := range parsed.ACPSources {
		if principal != "" && (source == unixSourceFiles || source == unixSourceDirectory) {
			if state.ACPSources == nil {
				state.ACPSources = map[string]string{}
			}
			state.ACPSources[principal] = source
		}
	}
	return state
}

// SaveUnixEnumeratorState writes the state atomically, root-only 0600.
func SaveUnixEnumeratorState(path string, state *UnixEnumeratorState) error {
	if state == nil {
		return nil
	}
	state.Version = 1
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".defenseclaw-enumerator-*.new")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

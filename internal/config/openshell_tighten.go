// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	sandboxpolicies "github.com/defenseclaw/defenseclaw/policies/sandbox"
)

// Sandbox floors: openshell.admin is the organization floor (the loosest
// anyone gets) and guardrail.profiles.<p>.sandbox tightens it for the
// subjects of profile p. TightenOpenShellAdmin combines the two into the
// profile's floor F; only request_access overrides.

// Bounds of the managed floor keys.
const (
	// OpenShellMinSilenceAfter is the shortest max_silence_after (the
	// packs' MinSilenceAfter).
	OpenShellMinSilenceAfter = time.Minute
	// OpenShellMinDeleteStoppedAfter is the shortest delete_stopped_after.
	OpenShellMinDeleteStoppedAfter = time.Hour
	// openShellMaxCredentials bounds allowed_credentials (schema maxItems).
	openShellMaxCredentials = 64
	// maxSandboxPackDigestBytes bounds the pack file a floor digest reads;
	// a larger file digests as "oversized" (the pack loader refuses packs
	// far smaller than this).
	maxSandboxPackDigestBytes = 1 << 20
	// sandboxPackFileName is the file a pack directory holds (packs.PackFileName).
	sandboxPackFileName = "pack.yaml"
)

var (
	openShellCredentialName = regexp.MustCompile(`^(none|[a-z0-9][a-z0-9_-]{0,63})$`)
	openShellDaysDuration   = regexp.MustCompile(`^([0-9]{1,6})d$`)
	// sandboxPackNamePattern is a custom pack name (the packs loader's
	// packNamePattern): <pack_dir>/<name>/pack.yaml.
	sandboxPackNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// SandboxProfilePackCheck, when set, refuses a profile floor's required_pack
// (profilePack, pinned by profileDigest when it is set) that does not load,
// does not match its pin, or is looser than the base pack
// (openshell.admin.required_pack, basePack) or, with no base pack, than the
// default pack (openshell.pack, else balanced). The packs package owns pack
// strictness and registers it; the loader calls it for every profile floor
// with a pack of its own or a pin of its own, and skips the check while it
// is unset. Resolve re-checks at each create.
var SandboxProfilePackCheck func(c *Config, basePack, profilePack, profileDigest string) error

// SandboxMachinePolicyRoute, when set, reports whether the standalone
// profile publishes connector's hooks on goos through a machine policy
// source standard users cannot write. internal/enterprisepolicy owns the
// routes and registers it; while it is unset every connector with host hooks
// on goos counts as machine-owned.
var SandboxMachinePolicyRoute func(connector, goos string) bool

// SandboxPolicyContradictionError is a profile sandbox section that, combined
// with openshell.admin, leaves a floor no sandbox could satisfy.
type SandboxPolicyContradictionError struct {
	// Field is the YAML key the contradiction is about.
	Field string
	// Message is the loader's text, without the profile prefix.
	Message string
}

func (e *SandboxPolicyContradictionError) Error() string { return e.Message }

// ParseOpenShellFloorDuration parses a floor duration: a Go duration ("90s",
// "5m", "12h") or a whole number of days ("14d").
func ParseOpenShellFloorDuration(value string) (time.Duration, error) {
	v := strings.TrimSpace(value)
	if m := openShellDaysDuration.FindStringSubmatch(v); m != nil {
		days, _ := strconv.Atoi(m[1])
		return time.Duration(days) * 24 * time.Hour, nil
	}
	if strings.HasPrefix(v, "+") || strings.HasPrefix(v, "-") {
		return 0, errors.New("a floor duration takes no sign")
	}
	return time.ParseDuration(v)
}

// EffectiveRequestAccess is the contact refusals end with: RequestAccess, or
// OpenShellRequestAccessFallback when none is configured.
func (a OpenShellAdminConfig) EffectiveRequestAccess() string {
	if s := strings.TrimSpace(a.RequestAccess); s != "" {
		return s
	}
	return OpenShellRequestAccessFallback
}

// managedFloorKeys lists the YAML names of the managed sandbox floor keys a
// section sets (the keys Secure Client refuses).
func (a OpenShellAdminConfig) managedFloorKeys() []string {
	var keys []string
	add := func(set bool, key string) {
		if set {
			keys = append(keys, key)
		}
	}
	add(a.Allowed != nil, "allowed")
	add(a.RequiredFor != nil, "required_for")
	add(a.WhenUnavailable != "", "when_unavailable")
	add(a.UserApprovals != "", "user_approvals")
	add(a.AllowedCredentials != nil, "allowed_credentials")
	add(a.OnSilence != "", "on_silence")
	add(a.MaxSilenceAfter != "", "max_silence_after")
	add(a.ProcessTree != nil, "process_tree")
	add(a.ForeignSandboxes != "", "foreign_sandboxes")
	add(a.AllowUpstreamTelemetry != nil, "allow_upstream_telemetry")
	add(a.DeleteStoppedAfter != "", "delete_stopped_after")
	add(a.RequestAccess != "", "request_access")
	add(a.DriverFallback != "", "driver_fallback")
	return keys
}

// validateManagedFloor checks the managed floor keys of one section; prefix
// is "admin" (openshell.admin) or "sandbox" (a profile's section). The
// messages are mirrored by the Python loader (cli/defenseclaw/config.py).
func (a *OpenShellAdminConfig) validateManagedFloor(prefix string) error {
	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, list := range []struct {
		key    string
		values []string
	}{
		{"required_for", a.RequiredFor}, {"allowed_credentials", a.AllowedCredentials},
		{"allowed_harnesses", a.AllowedHarnesses}, {"egress_allow_only", a.EgressAllowOnly},
	} {
		if list.values != nil && len(list.values) == 0 {
			check(fmt.Errorf("%s.%s: an empty list is refused; leave the key out for no constraint", prefix, list.key))
		}
	}
	check(validateOpenShellEnum(prefix+".when_unavailable", a.WhenUnavailable, true,
		OpenShellWhenUnavailableRefuse, OpenShellWhenUnavailableAlert))
	check(validateOpenShellEnum(prefix+".user_approvals", a.UserApprovals, true,
		OpenShellUserApprovalsNone, OpenShellUserApprovalsSession))
	check(validateOpenShellEnum(prefix+".on_silence", a.OnSilence, true,
		OpenShellOnSilenceStop, OpenShellOnSilenceAlert))
	check(validateOpenShellEnum(prefix+".foreign_sandboxes", a.ForeignSandboxes, true,
		OpenShellForeignSandboxesStop, OpenShellForeignSandboxesAlert))
	check(validateOpenShellEnum(prefix+".driver_fallback", a.DriverFallback, true,
		EnterpriseOpenShellFallbackDocker, EnterpriseOpenShellFallbackNone))
	for i, name := range a.RequiredFor {
		switch {
		case !openShellNamePattern.MatchString(strings.TrimSpace(name)):
			check(fmt.Errorf("%s.required_for[%d]: invalid name %q", prefix, i, name))
		case !gatewayconnector.IsKnownBuiltinConnector(NormalizeConnectorName(name)):
			check(fmt.Errorf("%s.required_for[%d]: %q is not a known connector", prefix, i, name))
		}
	}
	if len(a.AllowedCredentials) > openShellMaxCredentials {
		check(fmt.Errorf("%s.allowed_credentials: at most %d entries", prefix, openShellMaxCredentials))
	}
	for i, name := range a.AllowedCredentials {
		if !openShellCredentialName.MatchString(name) {
			check(fmt.Errorf("%s.allowed_credentials[%d]: %q must be none or a provider name (lowercase letters, digits, \"_\" and \"-\")",
				prefix, i, name))
		}
	}
	if len(a.AllowedCredentials) > 1 && slices.Contains(a.AllowedCredentials, OpenShellCredentialsNone) {
		check(fmt.Errorf("%s.allowed_credentials: none cannot be combined with other credentials", prefix))
	}
	check(validateFloorDuration(prefix+".max_silence_after", a.MaxSilenceAfter, OpenShellMinSilenceAfter, "1m", "5m"))
	check(validateFloorDuration(prefix+".delete_stopped_after", a.DeleteStoppedAfter, OpenShellMinDeleteStoppedAfter, "1h", "12h or 14d"))
	if r := a.RequestAccess; r != "" {
		switch {
		case len(r) > OpenShellRequestAccessMaxBytes:
			check(fmt.Errorf("%s.request_access must be at most %d bytes", prefix, OpenShellRequestAccessMaxBytes))
		case !printableLine(r):
			check(fmt.Errorf("%s.request_access must be printable text on one line", prefix))
		}
	}
	if a.Allowed != nil && !*a.Allowed && len(a.RequiredFor) > 0 {
		check(fmt.Errorf("%s: allowed: false contradicts required_for [%s]: a required agent could not run anywhere",
			prefix, strings.Join(a.RequiredFor, ", ")))
	}
	if outside := connectorsOutside(a.RequiredFor, a.AllowedHarnesses); len(outside) > 0 {
		check(fmt.Errorf("%s: required_for [%s] is outside allowed_harnesses [%s]: a required agent could not run anywhere",
			prefix, strings.Join(outside, ", "), strings.Join(a.AllowedHarnesses, ", ")))
	}
	return errors.Join(errs...)
}

// connectorsOutside lists the names of required (as written, once each) that
// allowed does not admit by NormalizeConnectorName; an unset allowed admits
// every name.
func connectorsOutside(required, allowed []string) []string {
	if allowed == nil {
		return nil
	}
	admitted := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		admitted[NormalizeConnectorName(name)] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range required {
		if key := NormalizeConnectorName(name); !admitted[key] && !seen[key] {
			seen[key] = true
			out = append(out, name)
		}
	}
	return out
}

// canonicalConnectorNames returns names as NormalizeConnectorName spells
// them, each once, in their first order; nil stays nil.
func canonicalConnectorNames(names []string) []string {
	if names == nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if key := NormalizeConnectorName(name); !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	return out
}

func validateFloorDuration(field, value string, minimum time.Duration, minText, example string) error {
	if value == "" {
		return nil
	}
	d, err := ParseOpenShellFloorDuration(value)
	if err != nil {
		return fmt.Errorf("%s %q must be a duration such as %s", field, value, example)
	}
	if d < minimum {
		return fmt.Errorf("%s %q must be at least %s", field, value, minText)
	}
	return nil
}

func printableLine(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// TightenOpenShellAdmin returns base tightened by overlay (plan §5.2): a nil
// overlay returns base. Unset keys add no constraint. allowed, allow_* and
// allow_upstream_telemetry: false wins (an unset base telemetry switch, false
// on a managed host, is never loosened); process_tree and
// block_large_uploads: true wins; min_profile: stricter; required_pack: the
// profile's pack replaces the base's (packs judge strictness); required_for,
// egress_block, require_copy_for, locked: union; allowed_harnesses,
// allowed_credentials, egress_allow_only: intersection; when_unavailable
// refuse, on_silence and foreign_sandboxes stop win; user_approvals none <
// session < unset; max_resources, max_silence_after (at least a minute) and
// delete_stopped_after: minimum; request_access: the profile's non-empty
// value replaces the base's; driver_fallback: none wins (a profile can
// refuse the docker fallback, never allow it back). A profile naming the base's own pack keeps the
// base's required_pack_digest; its own pin applies over an unpinned base,
// and a different pin is a contradiction.
//
// F's required_for and allowed_harnesses are canonical connector names
// (NormalizeConnectorName, each once: "claudecode", never "claude-code"),
// with or without an overlay, so the gates can compare them exactly.
//
// A floor no sandbox could satisfy (allowed: false with required_for, a
// required agent outside allowed_harnesses, an intersection that leaves
// nothing, two pins for one pack) is a *SandboxPolicyContradictionError.
func TightenOpenShellAdmin(base OpenShellAdminConfig, overlay *OpenShellAdminConfig) (OpenShellAdminConfig, error) {
	out := cloneOpenShellAdmin(base)
	if overlay == nil {
		out.RequiredFor = canonicalConnectorNames(out.RequiredFor)
		out.AllowedHarnesses = canonicalConnectorNames(out.AllowedHarnesses)
		return out, nil
	}
	o := cloneOpenShellAdmin(*overlay)

	if pack := strings.TrimSpace(o.RequiredPack); pack != "" {
		switch pin := o.RequiredPackDigest; {
		case !sameSandboxPack(pack, out.RequiredPack):
			out.RequiredPack, out.RequiredPackDigest = o.RequiredPack, o.RequiredPackDigest
		case pin == "":
			// The base's own pack: its pin stays.
		case out.RequiredPackDigest != "" && out.RequiredPackDigest != pin:
			return OpenShellAdminConfig{}, &SandboxPolicyContradictionError{
				Field: "required_pack_digest",
				Message: fmt.Sprintf("sandbox: combined with openshell.admin, required_pack_digest %s contradicts %s for the same pack %q: "+
					"no pack content matches both", pin, out.RequiredPackDigest, pack),
			}
		default:
			out.RequiredPackDigest = pin
		}
	}
	if OpenShellProfileRank(o.MinProfile) > OpenShellProfileRank(out.MinProfile) {
		out.MinProfile = o.MinProfile
	}
	out.Allowed = falseWins(out.Allowed, o.Allowed)
	out.AllowYolo = falseWins(out.AllowYolo, o.AllowYolo)
	out.AllowMount = falseWins(out.AllowMount, o.AllowMount)
	out.AllowHostPorts = falseWins(out.AllowHostPorts, o.AllowHostPorts)
	out.AllowUnblock = falseWins(out.AllowUnblock, o.AllowUnblock)
	out.AllowLearnMode = falseWins(out.AllowLearnMode, o.AllowLearnMode)
	out.AllowUpstreamTelemetry = falseByDefault(out.AllowUpstreamTelemetry, o.AllowUpstreamTelemetry)
	out.ProcessTree = trueWins(out.ProcessTree, o.ProcessTree)
	out.BlockLargeUploads = out.BlockLargeUploads || o.BlockLargeUploads

	out.RequiredFor = unionStrings(out.RequiredFor, o.RequiredFor, NormalizeConnectorName)
	out.EgressBlock = unionStrings(out.EgressBlock, o.EgressBlock, NormalizeOpenShellEgressPattern)
	out.RequireCopyFor = unionStrings(out.RequireCopyFor, o.RequireCopyFor, strings.TrimSpace)
	out.Locked = unionStrings(out.Locked, o.Locked, strings.TrimSpace)

	var err error
	if out.AllowedHarnesses, err = intersectHarnesses(out.AllowedHarnesses, o.AllowedHarnesses); err != nil {
		return OpenShellAdminConfig{}, err
	}
	if out.AllowedCredentials, err = intersectCredentials(out.AllowedCredentials, o.AllowedCredentials); err != nil {
		return OpenShellAdminConfig{}, err
	}
	if out.EgressAllowOnly, err = intersectEgressAllowOnly(out.EgressAllowOnly, o.EgressAllowOnly); err != nil {
		return OpenShellAdminConfig{}, err
	}

	out.WhenUnavailable = permissiveOnlyIfBoth(out.WhenUnavailable, o.WhenUnavailable,
		OpenShellWhenUnavailableAlert, OpenShellWhenUnavailableRefuse)
	out.ForeignSandboxes = permissiveOnlyIfBoth(out.ForeignSandboxes, o.ForeignSandboxes,
		OpenShellForeignSandboxesAlert, OpenShellForeignSandboxesStop)
	if o.OnSilence == OpenShellOnSilenceStop || (o.OnSilence != "" && out.OnSilence == "") {
		out.OnSilence = o.OnSilence
	}
	if userApprovalsRank(o.UserApprovals) < userApprovalsRank(out.UserApprovals) {
		out.UserApprovals = o.UserApprovals
	}
	out.MaxSilenceAfter = minFloorDuration(out.MaxSilenceAfter, o.MaxSilenceAfter)
	if d, perr := ParseOpenShellFloorDuration(out.MaxSilenceAfter); perr == nil && out.MaxSilenceAfter != "" && d < OpenShellMinSilenceAfter {
		out.MaxSilenceAfter = OpenShellMinSilenceAfter.String()
	}
	out.DeleteStoppedAfter = minFloorDuration(out.DeleteStoppedAfter, o.DeleteStoppedAfter)
	out.MaxResources = minResources(out.MaxResources, o.MaxResources)
	if strings.TrimSpace(o.RequestAccess) != "" {
		out.RequestAccess = o.RequestAccess
	}
	// driver_fallback: none wins; a docker overlay never loosens a none base.
	if o.DriverFallback == EnterpriseOpenShellFallbackNone || out.DriverFallback == "" {
		out.DriverFallback = o.DriverFallback
	}

	if out.Allowed != nil && !*out.Allowed && len(out.RequiredFor) > 0 {
		return OpenShellAdminConfig{}, &SandboxPolicyContradictionError{
			Field: "allowed",
			Message: fmt.Sprintf("sandbox: combined with openshell.admin, allowed: false contradicts required_for [%s]: "+
				"a required agent could not run anywhere", strings.Join(out.RequiredFor, ", ")),
		}
	}
	out.RequiredFor = canonicalConnectorNames(out.RequiredFor)
	out.AllowedHarnesses = canonicalConnectorNames(out.AllowedHarnesses)
	if outside := connectorsOutside(out.RequiredFor, out.AllowedHarnesses); len(outside) > 0 {
		return OpenShellAdminConfig{}, &SandboxPolicyContradictionError{
			Field: "required_for",
			Message: fmt.Sprintf("sandbox: combined with openshell.admin, required_for [%s] is outside allowed_harnesses [%s]: "+
				"a required agent could not run anywhere", strings.Join(outside, ", "), strings.Join(out.AllowedHarnesses, ", ")),
		}
	}
	return out, nil
}

// sameSandboxPack reports whether two required_pack references name one
// pack: equal names, or paths equal once cleaned, a trailing pack.yaml
// dropped (the loader reads <dir>/pack.yaml for a directory).
func sameSandboxPack(a, b string) bool {
	return sandboxPackKey(a) == sandboxPackKey(b)
}

func sandboxPackKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if !strings.ContainsAny(ref, `/\`) {
		return ref
	}
	clean := filepath.Clean(ref)
	if filepath.Base(clean) == sandboxPackFileName {
		clean = filepath.Dir(clean)
	}
	return clean
}

func cloneOpenShellAdmin(a OpenShellAdminConfig) OpenShellAdminConfig {
	out := a
	for _, p := range []**bool{&out.AllowYolo, &out.AllowMount, &out.AllowHostPorts, &out.AllowUnblock,
		&out.AllowLearnMode, &out.Allowed, &out.ProcessTree, &out.AllowUpstreamTelemetry} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	for _, s := range []*[]string{&out.AllowedHarnesses, &out.EgressBlock, &out.EgressAllowOnly, &out.RequireCopyFor,
		&out.Locked, &out.RequiredFor, &out.AllowedCredentials} {
		*s = slices.Clone(*s)
	}
	return out
}

func floorBool(v bool) *bool { return &v }

// falseWins: false from either side; otherwise the base as it is (an
// overlay true adds nothing).
func falseWins(base, overlay *bool) *bool {
	if (base != nil && !*base) || (overlay != nil && !*overlay) {
		return floorBool(false)
	}
	return base
}

// trueWins: true from either side; otherwise the base as it is (an overlay
// false adds nothing).
func trueWins(base, overlay *bool) *bool {
	if (base != nil && *base) || (overlay != nil && *overlay) {
		return floorBool(true)
	}
	return base
}

// falseByDefault combines a switch whose unset value is false on a managed
// host: the result is true only when the base says true and the overlay does
// not say false.
func falseByDefault(base, overlay *bool) *bool {
	switch {
	case overlay != nil && !*overlay, base != nil && !*base:
		return floorBool(false)
	case base != nil:
		return floorBool(true)
	default:
		return nil
	}
}

// permissiveOnlyIfBoth combines a two-valued key whose unset value means the
// strict one: an overlay can only turn a permissive base strict, so an unset
// or strict base stays as it is.
func permissiveOnlyIfBoth(base, overlay, permissive, strict string) string {
	if base == permissive && overlay == strict {
		return strict
	}
	return base
}

func userApprovalsRank(v string) int {
	switch v {
	case OpenShellUserApprovalsNone:
		return 0
	case OpenShellUserApprovalsSession:
		return 1
	default:
		return 2
	}
}

func unionStrings(base, overlay []string, key func(string) string) []string {
	if len(overlay) == 0 {
		return base
	}
	out := slices.Clone(base)
	seen := make(map[string]bool, len(base)+len(overlay))
	for _, v := range base {
		seen[key(v)] = true
	}
	for _, v := range overlay {
		if k := key(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}

func intersectHarnesses(base, overlay []string) ([]string, error) {
	if base == nil || overlay == nil {
		if base == nil {
			return overlay, nil
		}
		return base, nil
	}
	allowed := make(map[string]bool, len(overlay))
	for _, v := range overlay {
		allowed[NormalizeConnectorName(v)] = true
	}
	var out []string
	for _, v := range base {
		if allowed[NormalizeConnectorName(v)] {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, emptyIntersection("allowed_harnesses", overlay, base, "harness")
	}
	return out, nil
}

// intersectCredentials intersects two allowed_credentials lists; [none] is
// the empty set and the strictest value, so it absorbs the other side.
func intersectCredentials(base, overlay []string) ([]string, error) {
	switch {
	case base == nil:
		return overlay, nil
	case overlay == nil:
		return base, nil
	case slices.Contains(base, OpenShellCredentialsNone) || slices.Contains(overlay, OpenShellCredentialsNone):
		return []string{OpenShellCredentialsNone}, nil
	}
	var out []string
	for _, v := range base {
		if slices.Contains(overlay, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, emptyIntersection("allowed_credentials", overlay, base, "credential")
	}
	return out, nil
}

// intersectEgressAllowOnly keeps every destination both lists admit: an
// overlay pattern a base pattern covers, and a base pattern an overlay
// pattern covers, canonically spelled.
func intersectEgressAllowOnly(base, overlay []string) ([]string, error) {
	if base == nil || overlay == nil {
		if base == nil {
			return overlay, nil
		}
		return base, nil
	}
	parse := func(list []string) []OpenShellEgressPattern {
		out := make([]OpenShellEgressPattern, 0, len(list))
		for _, v := range list {
			if p, err := ParseOpenShellEgressPattern(v); err == nil {
				out = append(out, p)
			}
		}
		return out
	}
	b, o := parse(base), parse(overlay)
	var out []string
	add := func(p OpenShellEgressPattern) {
		if s := p.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	coveredBy := func(p OpenShellEgressPattern, list []OpenShellEgressPattern) bool {
		for _, q := range list {
			if q.Covers(p) {
				return true
			}
		}
		return false
	}
	for _, p := range o {
		if coveredBy(p, b) {
			add(p)
		}
	}
	for _, p := range b {
		if coveredBy(p, o) {
			add(p)
		}
	}
	if len(out) == 0 {
		return nil, emptyIntersection("egress_allow_only", overlay, base, "destination")
	}
	return out, nil
}

func emptyIntersection(field string, overlay, base []string, noun string) error {
	return &SandboxPolicyContradictionError{
		Field: field,
		Message: fmt.Sprintf("sandbox: combined with openshell.admin, %s [%s] leaves no %s (openshell.admin allows [%s])",
			field, strings.Join(overlay, ", "), noun, strings.Join(base, ", ")),
	}
}

func minFloorDuration(a, b string) string {
	switch {
	case b == "":
		return a
	case a == "":
		return b
	}
	da, errA := ParseOpenShellFloorDuration(a)
	db, errB := ParseOpenShellFloorDuration(b)
	if errA == nil && errB == nil && db < da {
		return b
	}
	return a
}

func minResources(a, b OpenShellResourcesConfig) OpenShellResourcesConfig {
	out := a
	if b.CPU != "" {
		cb, errB := ParseOpenShellCPU(b.CPU)
		ca, errA := ParseOpenShellCPU(a.CPU)
		if a.CPU == "" || (errA == nil && errB == nil && cb < ca) {
			out.CPU = b.CPU
		}
	}
	if b.Memory != "" {
		mb, errB := ParseOpenShellMemory(b.Memory)
		ma, errA := ParseOpenShellMemory(a.Memory)
		if a.Memory == "" || (errA == nil && errB == nil && mb < ma) {
			out.Memory = b.Memory
		}
	}
	return out
}

// SandboxFloor returns F for profile name ("" = openshell.admin alone) and
// its digest ("sha256:..." of F's canonical JSON and the content of the pack
// it references).
func (c *Config) SandboxFloor(profile string) (OpenShellAdminConfig, string, error) {
	return c.sandboxFloor(profile, nil)
}

// SandboxFloorWithMembers resolves a saved meet even when its telemetry name
// was shortened to a hash and the process that created it has restarted.
func (c *Config) SandboxFloorWithMembers(profile string, storedMembers []string) (OpenShellAdminConfig, string, error) {
	return c.sandboxFloor(profile, storedMembers)
}

func (c *Config) sandboxFloor(profile string, storedMembers []string) (OpenShellAdminConfig, string, error) {
	if c == nil {
		return OpenShellAdminConfig{}, "", errors.New("sandbox floor: configuration is unavailable")
	}
	if len(storedMembers) != 0 {
		if !IsProfileMeet(profile) || ProfileMeetName(storedMembers) != profile {
			return OpenShellAdminConfig{}, "", fmt.Errorf("sandbox floor: stored members do not match profile %q", profile)
		}
		return c.meetSandboxFloor(storedMembers)
	}
	if members, ok := ProfileMeetMembers(profile); ok {
		return c.meetSandboxFloor(members)
	}
	var overlay *OpenShellAdminConfig
	if name := strings.TrimSpace(profile); name != "" {
		p, ok := c.Guardrail.Profiles[name]
		if !ok {
			return OpenShellAdminConfig{}, "", fmt.Errorf("guardrail profile %q is not defined", name)
		}
		overlay = p.Sandbox
	}
	f, err := TightenOpenShellAdmin(c.OpenShell.Admin, overlay)
	if err != nil {
		return OpenShellAdminConfig{}, "", err
	}
	digest, err := sandboxFloorDigest(f, c.OpenShell.PackDir)
	if err != nil {
		return OpenShellAdminConfig{}, "", err
	}
	return f, digest, nil
}

// SandboxManagedFloor is SandboxFloor for a managed computer's per-user
// sandbox daemon, which has no config file: the configured value of a
// locked openshell key it would otherwise lose travels in the floor. A
// locked openshell.pack becomes the floor's required_pack (unless the floor
// requires one already), a locked openshell.profile its min_profile, and a
// locked openshell.yolo: false its allow_yolo: false. Each only says what
// the lock already enforces at the gateway, so the daemon's own resolve of
// the run matches the gateway's: a locked deny pack ran the default
// balanced pack in the sandbox (GAP-0675).
func (c *Config) SandboxManagedFloor(profile string) (OpenShellAdminConfig, string, error) {
	return c.sandboxManagedFloor(profile, nil)
}

// SandboxManagedFloorWithMembers is the managed floor for a saved meet whose
// member names were stored with its sandbox registration.
func (c *Config) SandboxManagedFloorWithMembers(profile string, members []string) (OpenShellAdminConfig, string, error) {
	return c.sandboxManagedFloor(profile, members)
}

func (c *Config) sandboxManagedFloor(profile string, members []string) (OpenShellAdminConfig, string, error) {
	f, digest, err := c.sandboxFloor(profile, members)
	if err != nil {
		return f, digest, err
	}
	o := c.OpenShell
	changed := false
	if pack := strings.TrimSpace(o.Pack); pack != "" && f.IsLocked("pack") && strings.TrimSpace(f.RequiredPack) == "" {
		f.RequiredPack, changed = pack, true
	}
	if p := strings.TrimSpace(o.Profile); p != "" && f.IsLocked("profile") && OpenShellProfileRank(p) > OpenShellProfileRank(f.MinProfile) {
		f.MinProfile, changed = p, true
	}
	if o.Yolo != nil && !*o.Yolo && f.IsLocked("yolo") && (f.AllowYolo == nil || *f.AllowYolo) {
		off := false
		f.AllowYolo, changed = &off, true
	}
	if !changed {
		return f, digest, nil
	}
	if digest, err = sandboxFloorDigest(f, o.PackDir); err != nil {
		return OpenShellAdminConfig{}, "", err
	}
	return f, digest, nil
}

// sandboxFloorDigestView is what a sandbox floor digest covers: F with its
// set-valued lists sorted, and the content digest of the referenced pack
// (sandboxPackContentDigest).
type sandboxFloorDigestView struct {
	Version int                  `json:"v"`
	Floor   OpenShellAdminConfig `json:"floor"`
	Pack    string               `json:"pack,omitempty"`
}

// sandboxFloorDigest returns "sha256:" + the hex SHA-256 of f's canonical
// JSON and its pack content, a custom pack name found in packDir
// (openshell.pack_dir). Equal floors always digest alike, whatever the order
// of their lists.
func sandboxFloorDigest(f OpenShellAdminConfig, packDir string) (string, error) {
	view := sandboxFloorDigestView{Version: 1, Floor: cloneOpenShellAdmin(f)}
	for _, s := range []*[]string{&view.Floor.AllowedHarnesses, &view.Floor.EgressBlock, &view.Floor.EgressAllowOnly,
		&view.Floor.RequireCopyFor, &view.Floor.Locked, &view.Floor.RequiredFor, &view.Floor.AllowedCredentials} {
		sort.Strings(*s)
	}
	view.Pack = sandboxPackContentDigest(f.RequiredPack, packDir)
	data, err := json.Marshal(view)
	if err != nil {
		return "", fmt.Errorf("sandbox floor digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// sandboxPackContentDigest names a required pack by content, the way the
// pack loader finds it: a built-in pack by its embedded file
// ("builtin:<name>:sha256:<hex>"); a path, "~/..." path or custom name in
// packDir by its pack.yaml ("file:sha256:<hex>"), or "missing",
// "unreadable" or "oversized" (larger than any pack the loader accepts)
// when that file cannot be digested. A custom name with no packDir, which
// no loader can find, stands for itself.
func sandboxPackContentDigest(pack, packDir string) string {
	pack = strings.TrimSpace(pack)
	if pack == "" {
		return ""
	}
	if isBuiltinSandboxPack(pack) {
		data, err := fs.ReadFile(sandboxpolicies.BuiltinPacks(), pack+"/"+sandboxPackFileName)
		if err != nil {
			return "builtin:" + pack
		}
		sum := sha256.Sum256(data)
		return "builtin:" + pack + ":sha256:" + hex.EncodeToString(sum[:])
	}
	file, ok := sandboxPackFile(pack, packDir)
	if !ok {
		return pack
	}
	f, err := os.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "missing"
		}
		return "unreadable"
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxSandboxPackDigestBytes+1))
	switch {
	case err != nil:
		return "unreadable"
	case n > maxSandboxPackDigestBytes:
		return "oversized"
	}
	return "file:sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func isBuiltinSandboxPack(name string) bool {
	return slices.Contains(sandboxpolicies.BuiltinPackNames(), name)
}

// sandboxPackFile is the pack.yaml a custom pack reference names, as the
// pack loader resolves it (packs.packFilePath): a name in packDir, or an
// absolute or "~/" path, a directory meaning its pack.yaml. ok is false
// when the reference names no file.
func sandboxPackFile(ref, packDir string) (file string, ok bool) {
	target := ref
	if sandboxPackNamePattern.MatchString(ref) {
		if packDir = strings.TrimSpace(packDir); packDir == "" {
			return "", false
		}
		target = filepath.Join(packDir, ref)
	}
	target, err := expandSandboxHome(target)
	if err != nil || !filepath.IsAbs(target) {
		return "", false
	}
	target = filepath.Clean(target)
	if info, err := os.Lstat(target); err == nil && info.IsDir() {
		target = filepath.Join(target, sandboxPackFileName)
	}
	return target, true
}

// expandSandboxHome expands a leading "~" or "~/" the way the pack loader does.
func expandSandboxHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot resolve the home directory")
	}
	return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")), nil
}

// validateSandboxProfiles checks every profile sandbox section: its own
// values, the floor it makes with openshell.admin, and, on a managed
// standalone host, where its pack lives. It runs after validateProfiles,
// which refuses every profile under Secure Client.
func (c *Config) validateSandboxProfiles() error {
	names := make([]string, 0, len(c.Guardrail.Profiles))
	for name, p := range c.Guardrail.Profiles {
		if p.Sandbox != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		section := c.Guardrail.Profiles[name].Sandbox
		if err := section.validateAs("sandbox"); err != nil {
			return profileSettingError(name, err)
		}
		floor, err := TightenOpenShellAdmin(c.OpenShell.Admin, section)
		if err != nil {
			return profileSettingError(name, err)
		}
		if err := c.validateManagedSandboxPack("guardrail.profiles["+strconv.Quote(name)+"].sandbox", section.RequiredPack); err != nil {
			return settingErrorAt("guardrail.profiles["+strconv.Quote(name)+"]", err)
		}
		// Tighten-only holds for the pack too: a profile's own pack (or its
		// own pin on the base's pack) is refused here, so ensure keeps the
		// previous config, when it is looser than the base pack, or than the
		// default pack with no base pack, or does not match its pin
		// (GAP-0268, GAP-0380, GAP-0401).
		base := strings.TrimSpace(c.OpenShell.Admin.RequiredPack)
		pack, pin := strings.TrimSpace(floor.RequiredPack), strings.TrimSpace(floor.RequiredPackDigest)
		if SandboxProfilePackCheck != nil && pack != "" &&
			(!sameSandboxPack(pack, base) || pin != strings.TrimSpace(c.OpenShell.Admin.RequiredPackDigest)) {
			if err := SandboxProfilePackCheck(c, base, pack, pin); err != nil {
				return profileSettingError(name, fmt.Errorf("sandbox.required_pack: %w", err))
			}
		}
	}
	return c.validateLockedSandboxPack(names)
}

// validateLockedSandboxPack judges, on a managed standalone host, a locked
// openshell.pack the way each run will. With openshell.admin.locked listing
// pack, SandboxManagedFloor makes openshell.pack the required pack of every
// floor that names none (openshell.admin's, and a profile's whose sandbox
// section names none), and each policy, explain and run then judges it like
// a profile's own pack: tighten-only, and copy-only on a managed computer.
// A pack that inherits workspace.mode: mount from balanced passed validate,
// ensure and verify, and then every user's sandbox policy could not load
// (GAP-0510). profiles are the names of the profiles with a sandbox section.
func (c *Config) validateLockedSandboxPack(profiles []string) error {
	pack := strings.TrimSpace(c.OpenShell.Pack)
	if pack == "" || !c.StandaloneEnterprise() || SandboxProfilePackCheck == nil {
		return nil
	}
	takes := func(f OpenShellAdminConfig) bool {
		return f.IsLocked("pack") && strings.TrimSpace(f.RequiredPack) == ""
	}
	// lockedBy names the lock that makes openshell.pack a required pack, so
	// the refusal points at the setting to change.
	lockedBy := ""
	if takes(c.OpenShell.Admin) {
		lockedBy = "openshell.admin.locked lists pack, so it is the required pack of every sandbox on this computer"
	}
	for _, name := range profiles {
		if lockedBy != "" {
			break
		}
		if floor, err := TightenOpenShellAdmin(c.OpenShell.Admin, c.Guardrail.Profiles[name].Sandbox); err == nil && takes(floor) {
			lockedBy = fmt.Sprintf("guardrail.profiles[%q].sandbox.locked lists pack, so it is the required pack of that profile's sandboxes", name)
		}
	}
	if lockedBy == "" {
		return nil
	}
	if err := SandboxProfilePackCheck(c, "", pack, ""); err != nil {
		return settingErrorAt("openshell.pack", fmt.Errorf("openshell.pack %q: %s: %w", pack, lockedBy, err))
	}
	return nil
}

// validateManagedSandboxPack refuses, on a managed standalone host, a
// required pack outside <policy_dir>/sandbox/, the administrator-owned packs
// folder: a path, or a custom pack name as openshell.pack_dir resolves it.
// A "~" path (each user's own home) is refused, and so is a symbolic link
// that leaves the folder. A built-in pack name is not a file.
func (c *Config) validateManagedSandboxPack(where, pack string) error {
	pack = strings.TrimSpace(pack)
	if pack == "" || !c.StandaloneEnterprise() || isBuiltinSandboxPack(pack) {
		return nil
	}
	root := filepath.Join(c.PolicyDir, "sandbox")
	target := pack
	if sandboxPackNamePattern.MatchString(pack) {
		dir := strings.TrimSpace(c.OpenShell.PackDir)
		if dir == "" || strings.HasPrefix(dir, "~") || !managedPackInside(root, filepath.Join(dir, pack)) {
			return fmt.Errorf("%s.required_pack %q names a custom pack, which must be inside %s on a managed device (openshell.pack_dir is %q)",
				where, pack, root, dir)
		}
		return nil
	}
	if strings.HasPrefix(target, "~") || !filepath.IsAbs(target) || !managedPackInside(root, target) {
		if filepath.IsAbs(target) && managedPackUnreadable(root, target) {
			// Inside the tree, but this account (the gateway's service
			// account) cannot reach it: not "outside" (GAP-0521).
			return fmt.Errorf("%s.required_pack %q is inside %s, but this account cannot read it (permission denied); let the DefenseClaw service group read the pack folder and its files (root:<service group>, folders 0750, files 0640)",
				where, pack, root)
		}
		return fmt.Errorf("%s.required_pack %q must be inside %s on a managed device", where, pack, root)
	}
	return nil
}

// managedPackUnreadable reports whether target lies below root by its path
// and a folder on the way, or target itself, cannot be read by this process.
func managedPackUnreadable(root, target string) bool {
	clean := filepath.Clean(target)
	if _, ok := strictlyBelow(filepath.Clean(root), clean); !ok {
		return false
	}
	_, err := os.Lstat(clean)
	return errors.Is(err, fs.ErrPermission)
}

// managedPackInside reports whether target lies below root (not root
// itself): where it really is when it exists, or, when it does not exist
// yet, by its path with no symbolic link between root and it.
func managedPackInside(root, target string) bool {
	roots := []string{filepath.Clean(root)}
	if r, err := filepath.EvalSymlinks(root); err == nil && r != roots[0] {
		roots = append(roots, r)
	}
	clean := filepath.Clean(target)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		for _, r := range roots {
			if _, ok := strictlyBelow(r, resolved); ok {
				return true
			}
		}
		return false
	}
	for _, r := range roots {
		if rel, ok := strictlyBelow(r, clean); ok {
			return noSymlinkBelow(r, rel)
		}
	}
	return false
}

func strictlyBelow(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// noSymlinkBelow walks rel down from root: false at the first symbolic link
// (a dangling one included) or unreadable entry, true once a component does
// not exist.
func noSymlinkBelow(root, rel string) bool {
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return errors.Is(err, fs.ErrNotExist)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

// validateSecureClientOpenShell refuses the managed sandbox floor keys under
// the Secure Client integration, whose behavior stays byte-identical.
func (c *Config) validateSecureClientOpenShell() error {
	if !c.SecureClientIntegration() {
		return nil
	}
	if keys := c.OpenShell.Admin.managedFloorKeys(); len(keys) > 0 {
		return fmt.Errorf("admin.%s: managed sandbox keys are not supported with the Secure Client integration",
			strings.Join(keys, ", admin."))
	}
	return nil
}

// sandboxPolicyConfigured reports whether any sandbox floor is configured.
func (c *Config) sandboxPolicyConfigured() bool {
	if !c.OpenShell.Admin.IsZero() {
		return true
	}
	for _, p := range c.Guardrail.Profiles {
		if p.Sandbox != nil {
			return true
		}
	}
	return false
}

// SandboxDefaultProfileWarnings lists, field by field, where the floor of
// guardrail.default_profile (openshell.admin alone when it is unset) is
// looser than the floor of an assigned profile: offline and unmatched users
// get the default, e.g. "default_profile lacks required_for [claudecode]
// from contractors".
func (c *Config) SandboxDefaultProfileWarnings() []string {
	if c == nil || !c.sandboxPolicyConfigured() {
		return nil
	}
	label := "default_profile"
	def := strings.TrimSpace(c.Guardrail.DefaultProfile)
	if def == "" {
		label = "openshell.admin (no default_profile)"
	}
	fd, _, err := c.SandboxFloor(def)
	if err != nil {
		return nil
	}
	var assigned []string
	for _, a := range c.Guardrail.ProfileAssignments {
		if a.Profile != def && !slices.Contains(assigned, a.Profile) {
			assigned = append(assigned, a.Profile)
		}
	}
	var out []string
	for _, name := range assigned {
		fp, _, err := c.SandboxFloor(name)
		if err != nil {
			continue
		}
		tightened, err := TightenOpenShellAdmin(fd, &fp)
		if err != nil {
			out = append(out, fmt.Sprintf("%s contradicts the sandbox floor of %s: %v", label, name, err))
			continue
		}
		// The combine takes the assigned profile's other pack as it is; it is
		// a gap only when the default's pack is looser (or cannot be judged).
		packJudgedNotLooser := !sameSandboxPack(fd.RequiredPack, fp.RequiredPack) && !c.sandboxPackLooser(fd.RequiredPack, fp.RequiredPack)
		for _, diff := range sandboxFloorDiff(fd, tightened) {
			if packJudgedNotLooser && (strings.HasPrefix(diff, "required_pack ") || strings.HasPrefix(diff, "required_pack_digest ")) {
				continue
			}
			out = append(out, fmt.Sprintf("%s lacks %s from %s", label, diff, name))
		}
	}
	return out
}

// sandboxPackLooser reports whether pack is looser than other by the pack
// strictness hook: true when pack is unset while other is set, or when the
// hook is not registered and cannot judge.
func (c *Config) sandboxPackLooser(pack, other string) bool {
	switch {
	case strings.TrimSpace(other) == "":
		return false
	case strings.TrimSpace(pack) == "", SandboxProfilePackCheck == nil:
		return true
	}
	return SandboxProfilePackCheck(c, other, pack, "") != nil
}

// sandboxFloorDiff names every key where tightened is stricter than loose,
// with the stricter value ("required_for [claudecode]", "allow_mount false").
// request_access is not a constraint and is left out.
func sandboxFloorDiff(loose, tightened OpenShellAdminConfig) []string {
	lv, tv := reflect.ValueOf(loose), reflect.ValueOf(tightened)
	typ := lv.Type()
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		key, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ",")
		if key == "request_access" || reflect.DeepEqual(lv.Field(i).Interface(), tv.Field(i).Interface()) {
			continue
		}
		// An unset allow_upstream_telemetry is already false on a managed host.
		if key == "allow_upstream_telemetry" && loose.AllowUpstreamTelemetry == nil {
			continue
		}
		switch v := tv.Field(i).Interface().(type) {
		case []string:
			var added []string
			for _, s := range v {
				if !slices.Contains(loose.listField(key), s) {
					added = append(added, s)
				}
			}
			if len(added) == 0 {
				added = v
			}
			out = append(out, fmt.Sprintf("%s [%s]", key, strings.Join(added, ", ")))
		case *bool:
			if v != nil {
				out = append(out, fmt.Sprintf("%s %t", key, *v))
			}
		case OpenShellResourcesConfig:
			var parts []string
			if v.CPU != loose.MaxResources.CPU {
				parts = append(parts, "cpu "+v.CPU)
			}
			if v.Memory != loose.MaxResources.Memory {
				parts = append(parts, "memory "+v.Memory)
			}
			out = append(out, fmt.Sprintf("%s {%s}", key, strings.Join(parts, ", ")))
		default:
			out = append(out, fmt.Sprintf("%s %v", key, v))
		}
	}
	return out
}

func (a OpenShellAdminConfig) listField(key string) []string {
	switch key {
	case "allowed_harnesses":
		return a.AllowedHarnesses
	case "egress_block":
		return a.EgressBlock
	case "egress_allow_only":
		return a.EgressAllowOnly
	case "require_copy_for":
		return a.RequireCopyFor
	case "locked":
		return a.Locked
	case "required_for":
		return a.RequiredFor
	case "allowed_credentials":
		return a.AllowedCredentials
	}
	return nil
}

// SandboxAdvisories lists what an administrator should know about the
// sandbox floors on goos, none of it an error: required_for on a connector
// with no machine-owned hook there (its host runs are not refused), a profile
// floor reachable only through match.agents or match.connectors (claims, not
// directory facts; key strict floors on groups), an empty request_access,
// and a custom required_pack without a required_pack_digest.
func (c *Config) SandboxAdvisories(goos string) []string {
	if c == nil || !c.sandboxPolicyConfigured() {
		return nil
	}
	var out []string
	required := map[string][]string{}
	note := func(source string, names []string) {
		for _, n := range names {
			n = NormalizeConnectorName(n)
			if !slices.Contains(required[n], source) {
				required[n] = append(required[n], source)
			}
		}
	}
	note("openshell.admin", c.OpenShell.Admin.RequiredFor)
	profiles := make([]string, 0, len(c.Guardrail.Profiles))
	for name := range c.Guardrail.Profiles {
		profiles = append(profiles, name)
	}
	sort.Strings(profiles)
	for _, name := range profiles {
		if s := c.Guardrail.Profiles[name].Sandbox; s != nil {
			note(name, s.RequiredFor)
		}
	}
	connectors := make([]string, 0, len(required))
	for n := range required {
		connectors = append(connectors, n)
	}
	sort.Strings(connectors)
	for _, n := range connectors {
		switch owned := c.machineOwnsHookOn(n, goos); {
		case owned && n == "opencode":
			// The managed plugin puts OpenCode on machine policy only while
			// OpenCode's managed config loads it.
			out = append(out, fmt.Sprintf("required_for names %s (%s), whose hook on %s is machine-owned only while OpenCode's managed config "+
				"loads the DefenseClaw plugin (`enterprise policy show` lists its route as machine_policy); otherwise its host runs are not refused there",
				n, strings.Join(required[n], ", "), goos))
		case !owned:
			out = append(out, fmt.Sprintf("required_for names %s (%s), which has no machine-owned hook on %s: its host runs are not refused there",
				n, strings.Join(required[n], ", "), goos))
		}
	}
	for i, a := range c.Guardrail.ProfileAssignments {
		p, ok := c.Guardrail.Profiles[a.Profile]
		if !ok || p.Sandbox == nil || len(a.Match.Groups) > 0 || len(a.Match.Users) > 0 {
			continue
		}
		out = append(out, fmt.Sprintf("guardrail.profile_assignments[%d] reaches the sandbox floor of %s only through match.agents or "+
			"match.connectors, which sandboxes do not verify; key strict floors on groups", i, a.Profile))
	}
	if strings.TrimSpace(c.OpenShell.Admin.RequestAccess) == "" {
		out = append(out, fmt.Sprintf("openshell.admin.request_access is empty: sandbox refusals end with %q", OpenShellRequestAccessFallback))
	}
	// A custom pack without a pin changes its users' floor whenever the file
	// changes, with no config change for ensure to check (GAP-0393).
	unpinned := func(where, pack, digest string) {
		if pack = strings.TrimSpace(pack); pack != "" && !isBuiltinSandboxPack(pack) && strings.TrimSpace(digest) == "" {
			out = append(out, fmt.Sprintf("%s.required_pack %s has no required_pack_digest: an edit of the pack file changes the sandbox floor "+
				"without a config change; pin it with the digest %s", where, pack, sandboxPackDigestHint(goos, pack)))
		}
	}
	unpinned("openshell.admin", c.OpenShell.Admin.RequiredPack, c.OpenShell.Admin.RequiredPackDigest)
	for _, name := range profiles {
		if s := c.Guardrail.Profiles[name].Sandbox; s != nil && !sameSandboxPack(s.RequiredPack, c.OpenShell.Admin.RequiredPack) {
			unpinned("guardrail.profiles["+strconv.Quote(name)+"].sandbox", s.RequiredPack, s.RequiredPackDigest)
		}
	}
	return out
}

// sandboxPackDigestHint is the administrator's command that prints pack's
// digest on goos. `defenseclaw sandbox pack show` asks the caller's own
// sandbox daemon, which root does not have on a managed computer, so the
// advisory names the offline reader with the installed gateway's absolute
// path (sudo's secure_path does not include its folder) (GAP-0484). Windows runs no
// sandboxes and has no reader; the digest is read where the pack is used.
func sandboxPackDigestHint(goos, pack string) string {
	if strings.ContainsAny(pack, " \t'\"") {
		pack = "'" + strings.ReplaceAll(pack, "'", `'\''`) + "'"
	}
	platform := map[string]string{"linux": "linux", "darwin": "macos"}[goos]
	layout, err := managed.StandaloneLayoutFor(goos)
	if platform == "" || err != nil {
		return fmt.Sprintf("`defenseclaw-gateway enterprise linux sandbox pack-digest %s` (or `enterprise macos`) prints on a computer that runs sandboxes", pack)
	}
	return fmt.Sprintf("`%s/defenseclaw-gateway enterprise %s sandbox pack-digest %s` prints", layout.BinDir, platform, pack)
}

// machineOwnsHookOn reports whether the require-sandbox gate can see every
// host run of connector name on goos: the connector has host hooks there,
// the standalone profile publishes them through machine policy, and the
// administrator did not turn its machine policy off. An agent whose hooks
// sit in the user's own config (Antigravity, Hermes, Kiro, Amp, Devin) can
// have them switched off (GAP-0535). OpenCode counts: the deployment's
// managed plugin can put it on machine policy, which the caller words as a
// condition. Proxy connectors have no hooks.
func (c *Config) machineOwnsHookOn(name, goos string) bool {
	if gatewayconnector.IsProxyConnector(name) {
		return false
	}
	switch gatewayconnector.ConnectorSupportOnOS(name, goos).Status {
	case gatewayconnector.PlatformSupported, gatewayconnector.PlatformPreview:
	default:
		return false
	}
	if name != "opencode" && SandboxMachinePolicyRoute != nil && !SandboxMachinePolicyRoute(name, goos) {
		return false
	}
	return c.Enterprise.MachinePolicy.PolicyFor(name).Ownership != MachinePolicyOwnershipOff
}

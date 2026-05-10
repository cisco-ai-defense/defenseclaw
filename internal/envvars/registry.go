// Package envvars is the Go side of the DefenseClaw environment-variable
// registry. The single source of truth lives at registry.json in this
// package; both Go and Python (cli/defenseclaw/envvars.py) load that file
// and expose a typed API around it.
//
// Why a registry?
//
// The codebase historically accumulated ~70 DEFENSECLAW_* env vars across
// Go, Python, shell, TypeScript, and Docker compose files. Operators had
// no way to know which were security-impacting, which were debug-only,
// and which were internal. The registry centralises the metadata so
// that:
//
//  1. Operators see exactly which security overrides are active via
//     `defenseclaw doctor`.
//  2. Docs (docs/ENV-VARS.md and docs-site/.../env-vars.mdx) are generated
//     from one source and never drift.
//  3. CI fails if a new env var is added without a registry entry.
//
// The cross-language sync test in registry_test.go asserts the Go and
// Python loaders see identical entry sets.
package envvars

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Category identifiers. Must match the keys of `$categories` in
// registry.json and the constants in cli/defenseclaw/envvars.py.
const (
	CategorySecurityOptOut = "security_opt_out"
	CategoryDebug          = "debug"
	CategoryTelemetry      = "telemetry"
	CategoryRuntimePath    = "runtime_path"
	CategoryHookInternal   = "hook_internal"
	CategoryCredential     = "credential"
	CategoryDiscovery      = "discovery"
	CategorySplunkBridge   = "splunk_bridge"
	CategoryTestFixture    = "test_fixture"
)

// AllowedCategories is the set of valid category strings.
var AllowedCategories = map[string]struct{}{
	CategorySecurityOptOut: {},
	CategoryDebug:          {},
	CategoryTelemetry:      {},
	CategoryRuntimePath:    {},
	CategoryHookInternal:   {},
	CategoryCredential:     {},
	CategoryDiscovery:      {},
	CategorySplunkBridge:   {},
	CategoryTestFixture:    {},
}

// SecurityImpact levels.
const (
	ImpactNone   = "none"
	ImpactLow    = "low"
	ImpactMedium = "medium"
	ImpactHigh   = "high"
)

// AllowedSecurityImpact is the set of valid security_impact strings.
var AllowedSecurityImpact = map[string]struct{}{
	ImpactNone:   {},
	ImpactLow:    {},
	ImpactMedium: {},
	ImpactHigh:   {},
}

// truthyValues matches cli/defenseclaw/envvars.py _TRUTHY.
var truthyValues = map[string]struct{}{
	"1":    {},
	"true": {},
	"yes":  {},
	"on":   {},
}

// disableByOff is the inverse-pattern set: setting any non-empty value
// other than "on" activates the bypass. Mirrors the Python side.
var disableByOff = map[string]struct{}{
	"DEFENSECLAW_SCHEMA_VALIDATION": {},
}

// Consumer is a single file:line location that references the var.
type Consumer struct {
	Location    string `json:"location"`
	Description string `json:"description"`
}

// EnvVar is one registry entry. Fields mirror the JSON schema exactly.
type EnvVar struct {
	Name            string     `json:"name"`
	Category        string     `json:"category"`
	Purpose         string     `json:"purpose"`
	Default         string     `json:"default"`
	AcceptedValues  []string   `json:"accepted_values"`
	SecurityImpact  string     `json:"security_impact"`
	SurfaceInDoctor bool       `json:"surface_in_doctor"`
	Consumers       []Consumer `json:"consumers"`
	Since           string     `json:"since"`
	SecurityNote    string     `json:"security_note,omitempty"`
	ReplacementHint string     `json:"replacement_hint,omitempty"`
	Deprecated      bool       `json:"deprecated,omitempty"`
}

// IsActive returns true when the var is set to a value that activates
// the feature it controls. Mirrors EnvVar.is_active in Python.
func (e EnvVar) IsActive() bool {
	return e.isActiveWithGetter(os.Getenv)
}

// isActiveWithGetter is the testable seam used by IsActive.
func (e EnvVar) isActiveWithGetter(get func(string) string) bool {
	v := strings.ToLower(strings.TrimSpace(get(e.Name)))
	if v == "" {
		return false
	}
	if _, ok := disableByOff[e.Name]; ok {
		return v != "on"
	}
	_, truthy := truthyValues[v]
	return truthy
}

// Registry is the full registry, indexed by name.
type Registry struct {
	SchemaVersion string            `json:"$schema_version"`
	Description   string            `json:"$description"`
	Categories    map[string]string `json:"$categories"`
	Entries       []EnvVar          `json:"entries"`

	byName map[string]EnvVar
}

// Get returns the entry for name, or nil if absent.
func (r *Registry) Get(name string) (EnvVar, bool) {
	e, ok := r.byName[name]
	return e, ok
}

// Has returns true if the registry declares an entry for name.
func (r *Registry) Has(name string) bool {
	_, ok := r.byName[name]
	return ok
}

// Names returns every declared name, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for k := range r.byName {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ByCategory returns entries in the requested category, in declaration order.
func (r *Registry) ByCategory(category string) []EnvVar {
	if _, ok := AllowedCategories[category]; !ok {
		return nil
	}
	out := make([]EnvVar, 0)
	for _, e := range r.Entries {
		if e.Category == category {
			out = append(out, e)
		}
	}
	return out
}

// ActiveSecurityOverrides returns entries flagged surface_in_doctor that
// are currently active in the process environment.
//
// If includeLowImpact is false, entries with security_impact="low" are
// omitted.
func (r *Registry) ActiveSecurityOverrides(includeLowImpact bool) []EnvVar {
	out := make([]EnvVar, 0)
	for _, e := range r.Entries {
		if !e.SurfaceInDoctor {
			continue
		}
		if e.SecurityImpact == ImpactNone {
			continue
		}
		if !includeLowImpact && e.SecurityImpact == ImpactLow {
			continue
		}
		if e.IsActive() {
			out = append(out, e)
		}
	}
	return out
}

// embeddedRegistry is the bytes of registry.json shipped with the
// binary. The JSON file is the single source of truth; both this Go
// loader and cli/defenseclaw/envvars.py parse it.
//
//go:embed registry.json
var embeddedRegistry []byte

var (
	registryOnce sync.Once
	registry     *Registry
	registryErr  error
)

// Load returns the singleton registry, validating its contents.
//
// Load is safe to call concurrently. It is idempotent: subsequent calls
// return the cached value.
func Load() (*Registry, error) {
	registryOnce.Do(func() {
		registry, registryErr = parseAndValidate(embeddedRegistry)
	})
	return registry, registryErr
}

// MustLoad is Load that panics on validation failure. Intended for boot
// paths where a malformed registry is a programmer error.
func MustLoad() *Registry {
	r, err := Load()
	if err != nil {
		panic(fmt.Errorf("envvars: registry load failed: %w", err))
	}
	return r
}

func parseAndValidate(data []byte) (*Registry, error) {
	var r Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("registry.json: %w", err)
	}

	// Declared categories must equal AllowedCategories — no missing, no
	// extra. Prevents typos from going unnoticed.
	if len(r.Categories) != len(AllowedCategories) {
		return nil, fmt.Errorf(
			"registry.json: $categories has %d entries but AllowedCategories has %d",
			len(r.Categories), len(AllowedCategories),
		)
	}
	for c := range AllowedCategories {
		if _, ok := r.Categories[c]; !ok {
			return nil, fmt.Errorf("registry.json: $categories missing %q", c)
		}
	}
	for c := range r.Categories {
		if _, ok := AllowedCategories[c]; !ok {
			return nil, fmt.Errorf("registry.json: $categories declares unknown category %q", c)
		}
	}

	seen := make(map[string]struct{}, len(r.Entries))
	for i, e := range r.Entries {
		if err := validateEntry(i, e); err != nil {
			return nil, err
		}
		if _, dup := seen[e.Name]; dup {
			return nil, fmt.Errorf("registry.json: duplicate entry for %q", e.Name)
		}
		seen[e.Name] = struct{}{}
	}

	r.byName = make(map[string]EnvVar, len(r.Entries))
	for _, e := range r.Entries {
		r.byName[e.Name] = e
	}
	return &r, nil
}

func validateEntry(idx int, e EnvVar) error {
	if e.Name == "" {
		return fmt.Errorf("registry.json: entry #%d has empty name", idx)
	}
	// Names must start with DEFENSECLAW_ (or be the legacy
	// MIGRATION_DEFENSECLAW_HOME).
	if !strings.HasPrefix(e.Name, "DEFENSECLAW_") && e.Name != "MIGRATION_DEFENSECLAW_HOME" {
		return fmt.Errorf("registry.json: entry %q: name must start with DEFENSECLAW_", e.Name)
	}
	if _, ok := AllowedCategories[e.Category]; !ok {
		return fmt.Errorf("registry.json: entry %q: unknown category %q", e.Name, e.Category)
	}
	if _, ok := AllowedSecurityImpact[e.SecurityImpact]; !ok {
		return fmt.Errorf("registry.json: entry %q: unknown security_impact %q", e.Name, e.SecurityImpact)
	}
	if e.Purpose == "" {
		return fmt.Errorf("registry.json: entry %q: purpose is required", e.Name)
	}
	if e.Since == "" {
		return fmt.Errorf("registry.json: entry %q: since is required", e.Name)
	}
	for _, c := range e.Consumers {
		if c.Location == "" || c.Description == "" {
			return fmt.Errorf("registry.json: entry %q: consumer must have location and description", e.Name)
		}
	}
	return nil
}

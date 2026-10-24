// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// ManifestSchemaVersion is the manifest.json schema this build reads.
const ManifestSchemaVersion = 1

// Platforms a bundle can target.
const (
	PlatformLinux   = "linux"
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"
)

// Platforms are the platforms a bundle can target, in canonical order.
var Platforms = []string{PlatformLinux, PlatformDarwin, PlatformWindows}

func knownPlatform(platform string) bool {
	return platform == PlatformLinux || platform == PlatformDarwin || platform == PlatformWindows
}

// SecretRefScheme prefixes a secret reference: secret://<credential name>.
const SecretRefScheme = "secret://"

// Manifest is manifest.json (spec section 3). The signature covers its exact
// bytes, so DecodeManifest refuses every spelling another JSON reader could
// read differently: unknown, repeated or upper-case keys and trailing data.
type Manifest struct {
	SchemaVersion     int             `json:"schema_version"`
	BundleID          string          `json:"bundle_id"`
	TenantID          string          `json:"tenant_id"`
	Target            Target          `json:"target"`
	Version           uint64          `json:"version"`
	Parent            string          `json:"parent,omitempty"`
	RollbackOf        string          `json:"rollback_of,omitempty"`
	CreatedAt         string          `json:"created_at"`
	CreatedBy         string          `json:"created_by"`
	ChangeSummary     string          `json:"change_summary,omitempty"`
	MinProductVersion string          `json:"min_product_version,omitempty"`
	Files             []FileEntry     `json:"files"`
	SecretRefs        []SecretRef     `json:"secret_refs,omitempty"`
	EffectivePolicy   EffectivePolicy `json:"effective_policy"`
	Warnings          []Warning       `json:"warnings,omitempty"`
}

// Target is the device group and platforms a bundle is for.
type Target struct {
	DeviceGroup string   `json:"device_group"`
	Platforms   []string `json:"platforms"`
}

// FileEntry is one files[] entry: a bundle file with its SHA-256 (lower-case
// hex) and size.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SecretRef names an enterprise credential the device must hold, and binds
// its value: ValueSHA256 is CredentialValueSHA256 of the value the signer
// gave. A device refuses a stored value with another digest
// (secret_ref_mismatch) and an entry without one (secret_ref_unbound).
type SecretRef struct {
	Ref         string `json:"ref"`
	Required    bool   `json:"required"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
}

// Name is the credential name of a secret://<name> reference.
func (r SecretRef) Name() string { return strings.TrimPrefix(r.Ref, SecretRefScheme) }

// Binds reports whether the reference signs value as the credential of a
// bundle for tenant. An entry without a digest binds no value.
func (r SecretRef) Binds(tenant string, value []byte) bool {
	if r.ValueSHA256 == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.ValueSHA256), []byte(CredentialValueSHA256(tenant, r.Name(), value))) == 1
}

// EffectivePolicy is the per-platform effective policy digest bundle sign
// computed, with the product version that computed it (the digest covers
// the built-in packs of that version).
type EffectivePolicy struct {
	ProductVersion string `json:"product_version"`
	// ComputedOn is the platform bundle sign ran on, for diagnostics. A
	// device compares its own digest whenever ProductVersion is its own,
	// on any signing platform; a difference is digest_mismatch. Another
	// product version reports digest_unverifiable and the device's digest.
	ComputedOn string            `json:"computed_on"`
	Digests    map[string]string `json:"digests"`
	// Components are signed diagnostic sub-digests, sorted by name, that
	// a digest_mismatch refusal names. They are omitted when the digester
	// reports none; they do not change the effective digest.
	Components map[string][]DigestComponent `json:"components,omitempty"`
}

type DigestComponent struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// Warning is an informational finding (group reachability). It never
// blocks a bundle.
type Warning struct {
	Code     string `json:"code"`
	Platform string `json:"platform,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Message  string `json:"message"`
}

var (
	// bundleIDPattern is "b-" and a ULID in canonical upper-case Crockford
	// base32 (the first character at most 7: 128 bits).
	bundleIDPattern        = regexp.MustCompile(`^b-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	scopeIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	componentDigestPattern = regexp.MustCompile(`^sha256:([0-9a-f]{12}|[0-9a-f]{64})$`)
	productVersionRegex    = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$`)
	warningCodePattern     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	manifestKeyPattern     = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// MaxVersion is the highest manifest version: 2^53-1, the largest integer a
// JSON reader that stores numbers as doubles (the console) reads exactly, so
// every reader agrees on the version the rollback floor compares.
const MaxVersion = 1<<53 - 1

// maxManifestDepth bounds the nesting of manifest.json (its schema is three
// levels deep).
const maxManifestDepth = 8

// ValidBundleID reports whether id is "b-" followed by a canonical ULID.
func ValidBundleID(id string) bool { return bundleIDPattern.MatchString(id) }

// DecodeManifest decodes and validates manifest.json. It refuses
// (manifest_invalid) a document over MaxManifestBytes, invalid UTF-8 or a
// byte-order mark, keys that are unknown, repeated or not lower-case
// snake_case, trailing data, and any field Validate refuses.
func DecodeManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, refuse(CodeManifestInvalid, ManifestName, "larger than %d bytes", MaxManifestBytes)
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, refuse(CodeManifestInvalid, ManifestName, "not UTF-8 JSON without a byte-order mark")
	}
	if err := checkJSONKeys(raw, CodeManifestInvalid, ManifestName); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, refuse(CodeManifestInvalid, ManifestName, "%s", jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(CodeManifestInvalid, ManifestName, "data after the manifest object")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Marshal encodes m as manifest.json (indented, files[] in the order given).
// It does not validate; bundle sign validates before it signs the bytes.
func (m *Manifest) Marshal() ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// jsonProblem describes a decode error by kind and field, never by value.
func jsonProblem(err error) string {
	var typeErr *json.UnmarshalTypeError
	var syntaxErr *json.SyntaxError
	switch {
	case errors.As(err, &typeErr):
		return fmt.Sprintf("field %s has the wrong type (want %s)", safePath(typeErr.Field), typeErr.Type)
	case errors.As(err, &syntaxErr):
		return fmt.Sprintf("invalid JSON at byte %d", syntaxErr.Offset)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "unknown field " + safePath(strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`))
	}
	return "invalid JSON"
}

type jsonFrame struct {
	object  bool
	keys    map[string]bool
	wantKey bool
}

// checkJSONKeys walks the JSON tokens and refuses (code, at name) a document whose root
// is not an object, that nests deeper than maxManifestDepth, or that has an
// object key that repeats or is not lower-case snake_case. encoding/json
// matches keys case-insensitively and keeps the last duplicate; another
// reader may not, and the signature covers the bytes, not one reading of
// them. The manifest, manifest.sig and the trust anchor file share it.
func checkJSONKeys(raw []byte, code Code, name string) *Error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonFrame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return refuse(code, name, "invalid JSON")
		}
		if len(stack) == 0 && tok != json.Delim('{') {
			return refuse(code, name, "not a JSON object")
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				valueDone()
				if len(stack) == 0 {
					return nil
				}
				continue
			}
			key, _ := tok.(string)
			if !manifestKeyPattern.MatchString(key) {
				return refuse(code, name, "key %s is not lower-case snake_case", safePath(key))
			}
			if stack[n-1].keys[key] {
				return refuse(code, name, "key %s appears twice in one object", key)
			}
			stack[n-1].keys[key] = true
			stack[n-1].wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) >= maxManifestDepth {
				return refuse(code, name, "nested deeper than %d levels", maxManifestDepth)
			}
			object := tok == json.Delim('{')
			stack = append(stack, &jsonFrame{object: object, keys: map[string]bool{}, wantKey: object})
			continue
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		valueDone()
		if len(stack) == 0 {
			return nil
		}
	}
}

// Validate checks every manifest field against spec section 3. Checks that
// need the trust anchor, the device state or the bundle files (tenant and
// device group membership, the version floor, files[] hashes) are the
// callers'.
func (m *Manifest) Validate() error {
	bad := func(field, format string, args ...any) error {
		return refuse(CodeManifestInvalid, field, format, args...)
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return bad("schema_version", "unsupported schema version %d (this build reads %d)", m.SchemaVersion, ManifestSchemaVersion)
	}
	if !ValidBundleID(m.BundleID) {
		return bad("bundle_id", "want b- followed by an upper-case ULID")
	}
	if !scopeIDPattern.MatchString(m.TenantID) {
		return bad("tenant_id", "want 1-128 characters of [A-Za-z0-9._-]")
	}
	if !scopeIDPattern.MatchString(m.Target.DeviceGroup) {
		return bad("target.device_group", "want 1-128 characters of [A-Za-z0-9._-]")
	}
	if len(m.Target.Platforms) == 0 {
		return bad("target.platforms", "names no platform")
	}
	seenPlatform := map[string]bool{}
	for _, platform := range m.Target.Platforms {
		if !knownPlatform(platform) {
			return bad("target.platforms", "unknown platform %s (want linux, darwin or windows)", safePath(platform))
		}
		if seenPlatform[platform] {
			return bad("target.platforms", "%s is listed twice", platform)
		}
		seenPlatform[platform] = true
	}
	if m.Version == 0 || m.Version > MaxVersion {
		return bad("version", "must be 1 to %d", uint64(MaxVersion))
	}
	for _, ref := range []struct{ field, id string }{{"parent", m.Parent}, {"rollback_of", m.RollbackOf}} {
		field, id := ref.field, ref.id
		if id == "" {
			continue
		}
		if !ValidBundleID(id) {
			return bad(field, "want b- followed by an upper-case ULID")
		}
		if id == m.BundleID {
			return bad(field, "names this bundle")
		}
	}
	if _, err := m.CreatedTime(); err != nil {
		return bad("created_at", "want an RFC 3339 UTC time ending in Z")
	}
	if err := checkPrincipal(m.CreatedBy, m.TenantID); err != nil {
		return bad("created_by", "%s", err)
	}
	if err := checkDisplayText(m.ChangeSummary, MaxChangeSummary); err != nil {
		return bad("change_summary", "%s", err)
	}
	if m.MinProductVersion != "" && !IsReleaseVersion(m.MinProductVersion) {
		return bad("min_product_version", "want a version such as 1.2.3")
	}
	if err := m.validateFiles(); err != nil {
		return err
	}
	if err := m.validateSecretRefs(); err != nil {
		return err
	}
	if !IsReleaseVersion(m.EffectivePolicy.ProductVersion) {
		return bad("effective_policy.product_version", "want a version such as 1.2.3")
	}
	if !knownPlatform(m.EffectivePolicy.ComputedOn) {
		return bad("effective_policy.computed_on", "want linux, darwin or windows")
	}
	if len(m.EffectivePolicy.Digests) != len(m.Target.Platforms) {
		return bad("effective_policy.digests", "want one digest for each target platform")
	}
	for _, platform := range m.Target.Platforms {
		if !digestPattern.MatchString(m.EffectivePolicy.Digests[platform]) {
			return bad("effective_policy.digests."+platform, "want sha256: and 64 lower-case hex digits")
		}
	}
	for platform, components := range m.EffectivePolicy.Components {
		if !knownPlatform(platform) || m.EffectivePolicy.Digests[platform] == "" || len(components) > 1024 {
			return bad("effective_policy.components", "invalid platform or component count")
		}
		previous := ""
		for _, component := range components {
			if component.Name == "" || len(component.Name) > 512 || component.Name <= previous ||
				!componentDigestPattern.MatchString(component.Digest) && component.Digest != "missing" {
				return bad("effective_policy.components", "component names must be sorted and sub-digests valid")
			}
			previous = component.Name
		}
	}
	if len(m.Warnings) > MaxWarnings {
		return bad("warnings", "more than %d warnings", MaxWarnings)
	}
	for i, warning := range m.Warnings {
		field := fmt.Sprintf("warnings[%d]", i)
		switch {
		case !warningCodePattern.MatchString(warning.Code):
			return bad(field+".code", "want 1-64 characters of [a-z0-9_]")
		case warning.Platform != "" && !knownPlatform(warning.Platform):
			return bad(field+".platform", "unknown platform")
		}
		if err := checkDisplayText(warning.Subject, 256); err != nil {
			return bad(field+".subject", "%s", err)
		}
		if err := checkDisplayText(warning.Message, 512); err != nil || warning.Message == "" {
			return bad(field+".message", "want 1-512 characters of display text")
		}
	}
	return nil
}

func (m *Manifest) validateFiles() error {
	if len(m.Files) == 0 {
		return refuse(CodeManifestInvalid, "files", "lists no file")
	}
	if len(m.Files) > MaxEntries {
		return refuse(CodeManifestInvalid, "files", "more than %d files", MaxEntries)
	}
	var total int64
	folded := map[string]bool{}
	hasConfig := false
	for i, file := range m.Files {
		field := fmt.Sprintf("files[%d]", i)
		if err := checkBundlePath(file.Path, false); err != nil {
			return refuse(CodeManifestInvalid, field+".path", "%s", err.Detail)
		}
		if file.Path == ManifestName || file.Path == SignatureName {
			return refuse(CodeManifestInvalid, field+".path", "the manifest envelope is not listed in files[]")
		}
		if i > 0 && file.Path <= m.Files[i-1].Path {
			return refuse(CodeManifestInvalid, field+".path", "files[] must be sorted by path with no duplicates")
		}
		if lower := strings.ToLower(file.Path); folded[lower] {
			return refuse(CodeManifestInvalid, field+".path", "differs from another path only in case")
		} else {
			folded[lower] = true
		}
		if !sha256Pattern.MatchString(file.SHA256) {
			return refuse(CodeManifestInvalid, field+".sha256", "want 64 lower-case hex digits")
		}
		if file.Size < 0 || file.Size > MaxExpandedBytes {
			return refuse(CodeManifestInvalid, field+".size", "out of range")
		}
		if total += file.Size; total > MaxExpandedBytes {
			return refuse(CodeManifestInvalid, "files", "lists more than %d bytes", MaxExpandedBytes)
		}
		hasConfig = hasConfig || file.Path == ConfigName
	}
	if !hasConfig {
		return refuse(CodeManifestInvalid, "files", "lists no %s", ConfigName)
	}
	return nil
}

func (m *Manifest) validateSecretRefs() error {
	if len(m.SecretRefs) > MaxSecretRefs {
		return refuse(CodeManifestInvalid, "secret_refs", "more than %d references", MaxSecretRefs)
	}
	seen := map[string]bool{}
	for i, ref := range m.SecretRefs {
		field := fmt.Sprintf("secret_refs[%d].ref", i)
		name, ok := strings.CutPrefix(ref.Ref, SecretRefScheme)
		if !ok || !config.ValidEnterpriseCredentialName(name) {
			return refuse(CodeManifestInvalid, field, "want secret:// followed by an enterprise credential name")
		}
		if seen[name] {
			return refuse(CodeManifestInvalid, field, "%s is listed twice", name)
		}
		seen[name] = true
		if ref.ValueSHA256 != "" && !validSHA256Hex(ref.ValueSHA256) {
			return refuse(CodeManifestInvalid, fmt.Sprintf("secret_refs[%d].value_sha256", i), "want 64 lower-case hex characters")
		}
	}
	return nil
}

// CreatedTime parses created_at, which must be RFC 3339 in UTC ("Z").
func (m *Manifest) CreatedTime() (time.Time, error) {
	if !strings.HasSuffix(m.CreatedAt, "Z") {
		return time.Time{}, errors.New("created_at is not UTC")
	}
	return time.Parse(time.RFC3339Nano, m.CreatedAt)
}

// checkPrincipal accepts control-plane:<tenant>/<admin> for tenant and
// operator:<os-admin>.
func checkPrincipal(principal, tenant string) error {
	// The device records the principal as the config writer, which takes at
	// most MaxPrincipalBytes: refuse a longer one at sign and verify, not at
	// apply.
	if len(principal) > configwrite.MaxPrincipalBytes {
		return fmt.Errorf("longer than %d bytes", configwrite.MaxPrincipalBytes)
	}
	switch {
	case strings.HasPrefix(principal, "control-plane:"):
		rest := strings.TrimPrefix(principal, "control-plane:")
		owner, admin, ok := strings.Cut(rest, "/")
		if !ok || owner != tenant {
			return errors.New("want control-plane:<tenant_id>/<admin>")
		}
		if admin == "" || strings.Contains(admin, "/") {
			return errors.New("want control-plane:<tenant_id>/<admin>")
		}
		return checkDisplayText(admin, 128)
	case strings.HasPrefix(principal, "operator:"):
		admin := strings.TrimPrefix(principal, "operator:")
		if admin == "" {
			return errors.New("want operator:<os-admin>")
		}
		return checkDisplayText(admin, 128)
	}
	return errors.New("want control-plane:<tenant_id>/<admin> or operator:<os-admin>")
}

// checkDisplayText refuses text an audit line could be spoofed with: control
// characters, bidirectional overrides and isolates, or more than max runes.
func checkDisplayText(text string, max int) error {
	if utf8.RuneCountInString(text) > max {
		return fmt.Errorf("longer than %d characters", max)
	}
	for _, r := range text {
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == utf8.RuneError {
			return errors.New("holds a control or bidirectional formatting character")
		}
	}
	return nil
}

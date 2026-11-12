// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Rejection codes. They are stable: they go into template_unverified events
// and the CLI's --json output.
const (
	CodeNoAttestation  = "no_attestation"
	CodeBadSignature   = "bad_signature"
	CodeUntrustedKey   = "untrusted_signer"
	CodeKeyRevoked     = "key_revoked"
	CodeKeyExpired     = "key_expired"
	CodeBadStatement   = "bad_statement"
	CodeSubjectMismach = "subject_mismatch"
	CodeImageMismatch  = "image_mismatch"
	CodeStalePolicy    = "stale_policy"
	CodeTooOld         = "too_old"
	CodeKitNotAccepted = "kit_not_accepted"
	CodeKitLayer       = "kit_layer_mismatch"
	CodeBaseUntrusted  = "base_untrusted"
	CodeScanBlocked    = "scan_blocked"
	CodeHooksNotRoot   = "hooks_not_root_owned"
	CodePhoneHome      = "phone_home_enabled"
	CodeUnpinned       = "unpinned_reference"
	CodeRegistry       = "registry_error"
	CodeBadReference   = "bad_reference"
)

// Rejection is why a template is not admitted. It is an error.
type Rejection struct {
	Code   string
	Detail string
	// Retryable is true when the cause may pass (the registry is down); the
	// template is still not admitted meanwhile.
	Retryable bool
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

// AsRejection returns err as a *Rejection if it is one.
func AsRejection(err error) (*Rejection, bool) {
	var r *Rejection
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

func reject(code, format string, a ...any) *Rejection {
	return &Rejection{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Verified is an admitted template.
type Verified struct {
	// Image is the reference as given; Digest the digest it resolved to.
	Image  string
	Digest string
	// Pinned is true when Image already named the digest.
	Pinned    bool
	Statement *Statement
	KeyID     string
	KeyName   string
	CheckedAt time.Time
}

// Attestor decides whether a template image is attested. A3's controller
// admits a template only when Verify returns nil error; every error is a
// non-admission, a *Rejection when the cause is known.
type Attestor interface {
	Verify(ctx context.Context, image string) (*Verified, error)
}

// Policy is what the controller requires of an attestation. The Verifier
// asks for a fresh Policy on every call, so rotating the trust anchors or
// raising the generation takes effect at the next poll.
type Policy struct {
	Anchors *TrustAnchors
	// MinPolicyGeneration rejects statements scanned under an older policy.
	MinPolicyGeneration int64
	// MaxAge rejects statements older than this; 0 disables.
	MaxAge time.Duration
	// AcceptKit judges the kit version (N and N-1); nil accepts any.
	AcceptKit func(version string) error
	// KitLayers pins a kit version to the diff id of its layer; a version
	// not in the map is not pinned.
	KitLayers map[string]string
	// AllowUnverifiedBase admits a template whose base is neither
	// allowlisted nor attested.
	AllowUnverifiedBase bool
	// RequireDigest refuses a tag reference, which could move after the
	// check.
	RequireDigest bool
	Now           func() time.Time
}

func (p Policy) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// Verifier implements Attestor over a registry.
type Verifier struct {
	Registry *Registry
	// Policy returns the current policy.
	Policy func() Policy

	mu    sync.Mutex
	cache map[string]cached
	// SuccessTTL and FailureTTL bound the verdict cache (a digest's
	// attestation is immutable, but trust anchors and policy change).
	SuccessTTL, FailureTTL time.Duration
}

type cached struct {
	v    *Verified
	err  error
	at   time.Time
	pkey string
}

// NewVerifier returns a verifier with a short verdict cache.
func NewVerifier(reg *Registry, policy func() Policy) *Verifier {
	return &Verifier{Registry: reg, Policy: policy, cache: map[string]cached{},
		SuccessTTL: 2 * time.Minute, FailureTTL: 15 * time.Second}
}

func policyKey(p Policy) string {
	key := fmt.Sprintf("%d|%s|%v|%v|%d", p.MinPolicyGeneration, p.MaxAge, p.AllowUnverifiedBase, p.RequireDigest, len(p.KitLayers))
	if p.Anchors != nil {
		for _, id := range p.Anchors.KeyIDs() {
			key += "|" + id
			if p.Anchors.IsRevoked(id) {
				key += "!"
			}
		}
	}
	return key
}

// Invalidate drops cached verdicts (after a key rotation or revocation).
func (v *Verifier) Invalidate() {
	v.mu.Lock()
	v.cache = map[string]cached{}
	v.mu.Unlock()
}

// Verify implements Attestor.
func (v *Verifier) Verify(ctx context.Context, image string) (*Verified, error) {
	pol := v.Policy()
	ref, err := ParseRef(image)
	if err != nil {
		return nil, reject(CodeBadReference, "%v", err)
	}
	if pol.Anchors == nil || pol.Anchors.Len() == 0 {
		return nil, reject(CodeUntrustedKey, "no trust anchors are configured")
	}
	if ref.Digest == "" && pol.RequireDigest {
		return nil, reject(CodeUnpinned, "%s names a tag; pin the template image by digest", image)
	}
	digest := ref.Digest
	if digest == "" {
		d, err := v.Registry.Digest(ctx, ref)
		if err != nil {
			return nil, registryRejection("resolve the image tag", err)
		}
		digest = d
	}
	ck, pk := digest, policyKey(pol)
	v.mu.Lock()
	if c, ok := v.cache[ck]; ok && c.pkey == pk {
		ttl := v.SuccessTTL
		if c.err != nil {
			ttl = v.FailureTTL
		}
		if pol.now().Sub(c.at) < ttl {
			v.mu.Unlock()
			return c.v, c.err
		}
	}
	v.mu.Unlock()

	out, err := v.verify(ctx, pol, ref, digest)
	if out != nil {
		out.Image, out.Pinned = image, ref.Digest != ""
	}
	// A registry outage is never cached as a failure of the template.
	if r, ok := AsRejection(err); !ok || !r.Retryable {
		v.mu.Lock()
		v.cache[ck] = cached{v: out, err: err, at: pol.now(), pkey: pk}
		v.mu.Unlock()
	}
	return out, err
}

func registryRejection(what string, err error) *Rejection {
	if errors.Is(err, ErrNotFound) {
		return reject(CodeNoAttestation, "%s: not found in the registry", what)
	}
	r := reject(CodeRegistry, "%s: %v", what, err)
	r.Retryable = true
	return r
}

func (v *Verifier) verify(ctx context.Context, pol Policy, ref Ref, digest string) (*Verified, error) {
	envs, err := v.Registry.GetAttestations(ctx, ref, digest)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, reject(CodeNoAttestation, "%s has no attestation", ref.Name()+"@"+digest)
		}
		return nil, registryRejection("read the attestation", err)
	}
	if len(envs) == 0 {
		return nil, reject(CodeNoAttestation, "%s has no readable attestation", ref.Name()+"@"+digest)
	}
	var last error
	for _, env := range envs {
		ok, err := v.check(ctx, pol, ref, digest, env)
		if err == nil {
			return ok, nil
		}
		last = err
	}
	return nil, last
}

// check runs every rule against one envelope.
func (v *Verifier) check(ctx context.Context, pol Policy, ref Ref, digest string, env *Envelope) (*Verified, error) {
	now := pol.now()
	anchor, payload, err := env.verifyWith(pol.Anchors, now)
	switch {
	case errors.Is(err, errAnchorRevoked):
		return nil, reject(CodeKeyRevoked, "the signing key %s is revoked", short(anchorID(anchor)))
	case errors.Is(err, errAnchorExpired), errors.Is(err, errAnchorNotYetValid):
		return nil, reject(CodeKeyExpired, "%v", err)
	case errors.Is(err, errBadSignature):
		return nil, reject(CodeBadSignature, "%v", err)
	case err != nil:
		return nil, reject(CodeUntrustedKey, "%v", err)
	}
	st, err := ParseStatement(payload)
	if err != nil {
		return nil, reject(CodeBadStatement, "%v", err)
	}
	if st.PredicateType != PredicateType {
		return nil, reject(CodeBadStatement, "predicate type %q is not a DefenseClaw template attestation", st.PredicateType)
	}
	sub, err := st.SubjectDigest()
	if err != nil {
		return nil, reject(CodeBadStatement, "%v", err)
	}
	if sub != digest {
		return nil, reject(CodeSubjectMismach, "the attestation is for %s, not %s", short(sub), short(digest))
	}
	p := st.Predicate
	if pol.MinPolicyGeneration > 0 && p.Policy.Generation < pol.MinPolicyGeneration {
		return nil, reject(CodeStalePolicy, "scanned under policy generation %d, the cluster needs %d or newer", p.Policy.Generation, pol.MinPolicyGeneration)
	}
	if pol.MaxAge > 0 && now.Sub(p.Builder.BuiltAt) > pol.MaxAge {
		return nil, reject(CodeTooOld, "built %s ago, the limit is %s", now.Sub(p.Builder.BuiltAt).Round(time.Hour), pol.MaxAge)
	}
	if pol.AcceptKit != nil {
		if err := pol.AcceptKit(p.Kit.Version); err != nil {
			return nil, reject(CodeKitNotAccepted, "%v", err)
		}
	}
	if want, ok := pol.KitLayers[p.Kit.Version]; ok && want != p.Kit.LayerDiffID {
		return nil, reject(CodeKitLayer, "kit %s layer %s is not the released layer", p.Kit.Version, short(p.Kit.LayerDiffID))
	}
	if p.Base.Trust != BaseTrustAttested && p.Base.Trust != BaseTrustAllowlisted && !pol.AllowUnverifiedBase {
		return nil, reject(CodeBaseUntrusted, "base image %s is neither allowlisted nor attested", p.Base.Ref)
	}
	if p.Scan.Verdict == VerdictBlock {
		return nil, reject(CodeScanBlocked, "the build scan verdict is block")
	}
	if !p.Hooks.RootOwned {
		return nil, reject(CodeHooksNotRoot, "hook or settings files are not root-owned in the image")
	}
	if !p.Hooks.PhoneHomeOff {
		return nil, reject(CodePhoneHome, "phone-home or auto-update switches are not all off")
	}
	// The statement is about this digest; make sure the image it describes
	// actually carries the kit layer it names, at the place it names.
	if err := v.checkImage(ctx, ref, digest, p.Kit); err != nil {
		return nil, err
	}
	return &Verified{Digest: digest, Statement: st, KeyID: anchor.KeyID, KeyName: anchor.Name, CheckedAt: now}, nil
}

func anchorID(a *Anchor) string {
	if a == nil {
		return ""
	}
	return a.KeyID
}

func (v *Verifier) checkImage(ctx context.Context, ref Ref, digest string, kit KitInfo) error {
	img, err := v.Registry.Image(ctx, ref.WithDigest(digest), DefaultPlatform)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return reject(CodeImageMismatch, "the image manifest is gone from the registry")
		}
		return registryRejection("read the image", err)
	}
	if img.Digest != digest {
		// The digest named an index; its attested platform image is another digest.
		return reject(CodeImageMismatch, "the attested digest is an index, attest and use the platform manifest")
	}
	layers := img.Manifest.Layers
	if kit.LayerIndex < 0 || kit.LayerIndex >= len(layers) || layers[kit.LayerIndex].Digest != kit.LayerDigest {
		return reject(CodeImageMismatch, "the image has no layer %s at position %d", short(kit.LayerDigest), kit.LayerIndex)
	}
	diffs, err := img.Config.DiffIDs()
	if err != nil || kit.LayerIndex >= len(diffs) || diffs[kit.LayerIndex] != kit.LayerDiffID {
		return reject(CodeImageMismatch, "the image config does not carry the attested kit layer")
	}
	return nil
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

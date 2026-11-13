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

package controller

import (
	"context"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// TemplateAttestor admits a template only when every container image is
// pinned by digest, verifies against the trust anchors (attest.Attestor,
// lane A9) and the verified digest is the very digest the container runs,
// and when every image volume is one the admin allows (PLAN §5.3 step 2).
// Repository allow lists per profile are checked by the controller, which
// knows the actor's profile (see ImagesAllowed).
type TemplateAttestor struct {
	Verifier attest.Attestor
	// VolumeImages are repository globs allowed as image volumes without
	// an attestation.
	VolumeImages []string
	// Registries are the registry hosts the attestations may come from
	// (AllowedRegistries). Empty refuses every template: the image
	// reference is untrusted input, so the controller dials only hosts the
	// admin named (GAP-0131).
	Registries []string
}

var _ Attestor = (*TemplateAttestor)(nil)

// Attest implements Attestor. A refusal is an Attestation with Attested
// false and a Reason; the error is reserved for nothing (the controller
// treats both the same way: no policy).
func (t *TemplateAttestor) Attest(ctx context.Context, tmpl *ateapi.ActorTemplate) (Attestation, error) {
	cs := tmpl.GetContainers()
	if len(cs) == 0 {
		return Attestation{Reason: "the template has no container"}, nil
	}
	var out Attestation
	for i, c := range cs {
		img := c.GetImage()
		ref, err := attest.ParseRef(img)
		if err != nil {
			return Attestation{Reason: fmt.Sprintf("container %d: %v", i, err)}, nil
		}
		if ref.Digest == "" {
			return Attestation{Reason: fmt.Sprintf("container %d image %s is not pinned by digest", i, ref.Name())}, nil
		}
		if len(t.Registries) == 0 {
			return Attestation{Digest: ref.Digest, Reason: "substrate.templates.allowed_images names no registry host: no template is admitted"}, nil
		}
		if !slices.Contains(t.Registries, ref.Registry) {
			return Attestation{Digest: ref.Digest, Reason: fmt.Sprintf("container %d image registry %s is not in substrate.templates.allowed_images", i, ref.Registry)}, nil
		}
		v, err := t.Verifier.Verify(ctx, img)
		if err != nil {
			reason, retry := err.Error(), false
			if r, ok := attest.AsRejection(err); ok {
				reason, retry = r.Code+": "+r.Detail, r.Retryable
			}
			return Attestation{Digest: ref.Digest, Retryable: retry, Reason: fmt.Sprintf("container %d image %s: %s", i, ref.Name(), reason)}, nil
		}
		// The container runs ref.Digest; the attestation is about v.Digest.
		// They must be the same digest (an index or a moved tag is not).
		if v == nil || v.Digest != ref.Digest {
			got := ""
			if v != nil {
				got = v.Digest
			}
			return Attestation{Digest: ref.Digest,
				Reason: fmt.Sprintf("container %d runs %s but the attestation is for %s", i, ref.Digest, got)}, nil
		}
		if !v.ValidUntil.IsZero() && (out.ValidUntil.IsZero() || v.ValidUntil.Before(out.ValidUntil)) {
			out.ValidUntil = v.ValidUntil
		}
		if st := v.Statement; st != nil {
			for _, it := range st.Predicate.Scan.Items {
				if it.Kind == config.AdmissionTypeSkill && it.Digest != "" && it.Verdict != attest.VerdictBlock && !slices.Contains(out.SkillDigests, it.Digest) {
					out.SkillDigests = append(out.SkillDigests, it.Digest)
				}
			}
		}
		if i == 0 {
			out.Digest = v.Digest
			if st := v.Statement; st != nil {
				out.Connector = st.Predicate.Template.Connector
				out.KitVersion = st.Predicate.Kit.Version
			}
		}
	}
	for _, vol := range tmpl.GetVolumes() {
		src := vol.GetImage()
		if src == nil {
			continue
		}
		ref, err := attest.ParseRef(src.GetReference())
		if err != nil || ref.Digest == "" {
			return Attestation{Reason: fmt.Sprintf("image volume %s is not a digest-pinned reference", vol.GetName())}, nil
		}
		if !MatchImage(t.VolumeImages, ref.Name()) {
			return Attestation{Reason: fmt.Sprintf("image volume %s (%s) is not in substrate.templates.volume_images", vol.GetName(), ref.Name())}, nil
		}
	}
	out.Attested = true
	return out, nil
}

// MatchImage reports whether a repository name ("registry/path") matches
// one of the globs.
func MatchImage(globs []string, repo string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, repo); err == nil && ok {
			return true
		}
	}
	return false
}

// ImagesAllowed applies substrate.templates.allowed_images (empty = any)
// and the profile's profile_images entry (absent = no narrowing) to every
// container repository of an attested template. It returns the first
// repository not allowed.
func ImagesAllowed(t config.SubstrateTemplatesConfig, profile string, images []string) (string, bool) {
	narrow, hasProfile := t.ProfileImages[profile]
	for _, repo := range images {
		if len(t.AllowedImages) > 0 && !MatchImage(t.AllowedImages, repo) {
			return repo, false
		}
		if hasProfile && !MatchImage(narrow, repo) {
			return repo, false
		}
	}
	return "", true
}

// AnchorFile reads a trust bundle and re-reads it when its size or
// modification time changes (a Secret update swaps the file).
type AnchorFile struct {
	Path string

	mu      sync.Mutex
	mod     time.Time
	size    int64
	anchors *attest.TrustAnchors
	err     error
}

// Get returns the current anchors, or an error when the file is missing
// or bad (the verifier then refuses every template: fail closed).
func (a *AnchorFile) Get() (*attest.TrustAnchors, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fi, err := os.Stat(a.Path)
	if err != nil {
		a.anchors, a.err, a.mod, a.size = nil, fmt.Errorf("trust anchors: %w", err), time.Time{}, -1
		return nil, a.err
	}
	if a.anchors != nil || a.err != nil {
		if fi.ModTime().Equal(a.mod) && fi.Size() == a.size {
			return a.anchors, a.err
		}
	}
	a.mod, a.size = fi.ModTime(), fi.Size()
	a.anchors, a.err = attest.LoadAnchors(a.Path)
	return a.anchors, a.err
}

// VerifierFromConfig builds the attestation verifier for substrate.templates
// (anchors from the admin-only Secret, digest pins required). The kit
// version is judged by the controller (N and N-1, with the migrate hint).
func VerifierFromConfig(t config.SubstrateTemplatesConfig) (*attest.Verifier, *AnchorFile) {
	af := &AnchorFile{Path: t.EffectiveTrustAnchors()}
	reg := attest.NewRegistry(attest.RegistryOptions{PlainHTTP: t.PlainHTTPRegistries})
	maxAge := t.EffectiveMaxAge()
	registries := AllowedRegistries(t)
	revoked := map[string]bool{}
	for _, d := range t.RevokedDigests {
		revoked[strings.ToLower(strings.TrimSpace(d))] = true
	}
	return attest.NewVerifier(reg, func() attest.Policy {
		anchors, _ := af.Get() // nil anchors: Verify refuses (untrusted_signer)
		return attest.Policy{Anchors: anchors, MinPolicyGeneration: t.MinPolicyGeneration, MaxAge: maxAge,
			AllowUnverifiedBase: t.AllowUnverifiedBase, AllowedRegistries: registries, RevokedDigests: revoked}
	}), af
}

// AllowedRegistries are the registry hosts the verifier may connect to:
// the hosts of allowed_images (a glob in the host part is refused by config
// validation and skipped here). The image reference is untrusted input (an
// atespace editor writes the template), so only hosts the admin named are
// dialed; none named means no template is admitted (GAP-0131).
func AllowedRegistries(t config.SubstrateTemplatesConfig) []string {
	set := map[string]bool{}
	for _, g := range t.AllowedImages {
		host, _, ok := strings.Cut(g, "/")
		if !ok || strings.ContainsAny(host, "*?[") {
			continue
		}
		set[host] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

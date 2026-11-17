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
	"github.com/defenseclaw/defenseclaw/internal/substrate/regauth"
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
//
// Besides the image, the container spec must match what was attested
// (GAP-0354): every env variable is one the actor environment allowlist
// permits (attest.CheckEnv: the kit's variables with the kit's value where it
// fixes one, and the ordinary base-image settings), and the process is the
// image's attested entrypoint and arguments (a different command, or extra
// arguments, is refused). Those refusals, and the image environment's
// (attest.Rejection.Allowlist, GAP-0355), carry Allowlist with every other
// field filled, so the controller keeps an actor admitted before the
// upgrade running while it refuses new ones.
func (t *TemplateAttestor) Attest(ctx context.Context, tmpl *ateapi.ActorTemplate) (Attestation, error) {
	cs := tmpl.GetContainers()
	if len(cs) == 0 {
		return Attestation{Reason: "the template has no container"}, nil
	}
	var out Attestation
	allowlist := ""
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
			r, ok := attest.AsRejection(err)
			if ok {
				reason, retry = r.Code+": "+r.Detail, r.Retryable
			}
			if !ok || !r.Allowlist || v == nil {
				return Attestation{Digest: ref.Digest, Retryable: retry, Reason: fmt.Sprintf("container %d image %s: %s", i, ref.Name(), reason)}, nil
			}
			if allowlist == "" {
				allowlist = fmt.Sprintf("container %d image %s: %s", i, ref.Name(), reason)
			}
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
		if why := ContainerSpecRefusal(c, v); why != "" && allowlist == "" {
			allowlist = fmt.Sprintf("container %d: %s", i, why)
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
				out.AgentVersion = st.Predicate.Template.AgentVersion
				out.HookContract = st.Predicate.Kit.HookContract
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
	if allowlist != "" {
		out.Reason, out.Allowlist = allowlist, true
		return out, nil
	}
	out.Attested = true
	return out, nil
}

// maxArgvShown bounds an argv in a refusal.
const maxArgvShown = 200

// ContainerSpecRefusal says why a container spec does not match what was
// attested about its image (GAP-0354), "" when it does: an env variable the
// actor environment allowlist does not permit, or a process other than the
// image's attested ENTRYPOINT and CMD. Substrate runs command + args when
// command is set, ENTRYPOINT + args when only args is, and ENTRYPOINT +
// CMD otherwise; the result must be ENTRYPOINT + CMD.
func ContainerSpecRefusal(c *ateapi.Container, v *attest.Verified) string {
	env := map[string]string{}
	for _, e := range c.GetEnv() {
		env[e.GetName()] = e.GetValue()
	}
	if bad := attest.CheckEnv(env); len(bad) > 0 {
		return "env sets variables the actor environment allowlist does not permit: " + attest.FormatEnvRefusals(bad) +
			"; remove them from the template (the kit sets what the agent needs)"
	}
	want := append(append([]string{}, v.Entrypoint...), v.Cmd...)
	cmd, args := c.GetCommand(), c.GetArgs()
	var got []string
	switch {
	case len(cmd) > 0:
		got = append(append(got, cmd...), args...)
	case len(args) > 0:
		got = append(append(got, v.Entrypoint...), args...)
	default:
		return ""
	}
	if slices.Equal(got, want) {
		return ""
	}
	if len(cmd) > 0 && !slices.Equal(cmd, v.Entrypoint) {
		return fmt.Sprintf("command %s is not the attested entrypoint %s; remove command from the template (the image starts the relay)", argvText(cmd), argvText(v.Entrypoint))
	}
	return fmt.Sprintf("args %s are not the attested arguments %s; remove args from the template", argvText(args), argvText(v.Cmd))
}

func argvText(a []string) string {
	s := fmt.Sprintf("%q", a)
	if len(s) > maxArgvShown {
		s = s[:maxArgvShown] + "…"
	}
	return s
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
// It is the one verifier of the controller and the gateway's create path,
// so both read attestations with the same registry logins
// (substrate.templates.registry_auth; anonymous when unset, GAP-0190).
func VerifierFromConfig(t config.SubstrateTemplatesConfig) (*attest.Verifier, *AnchorFile) {
	af := &AnchorFile{Path: t.EffectiveTrustAnchors()}
	reg := attest.NewRegistry(registryOptions(t))
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

// registryOptions are the verifier's registry client options.
func registryOptions(t config.SubstrateTemplatesConfig) attest.RegistryOptions {
	return attest.RegistryOptions{PlainHTTP: t.PlainHTTPRegistries, Source: regauth.FromConfig(t.RegistryAuth)}
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

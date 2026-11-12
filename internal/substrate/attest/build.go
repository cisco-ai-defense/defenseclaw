// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// KitSpec is the actor kit layer to add: the files, the paths of the base
// image to drop, and the image settings. A5's kit.ActorOverlay produces it.
type KitSpec struct {
	Version      string
	HookContract string
	Files        []LayerFile
	// Remove are paths of the base image the layer drops (whiteouts); only
	// those that exist in the base are written.
	Remove []string
	// Env is set on the image (existing keys are replaced).
	Env map[string]string
	// User, Workdir and Entrypoint, when set, replace the base's.
	User       string
	Workdir    string
	Entrypoint []string
	Cmd        []string
	// HomeOwners maps a home folder to the uid and gid that own the parent
	// folders of files below it.
	HomeOwners map[string][2]int
	// UserFiles are the layer files that belong to the image user, not root
	// (so the root-owned check skips them).
	UserFiles map[string]bool
	// PhoneHome are the environment switches that must be set in the final
	// image (it may include the Env above).
	PhoneHome map[string]string
	// ConfigSwitches are file contents that must be present, by path.
	ConfigSwitches map[string][]string
}

// BuildOptions configure Build.
type BuildOptions struct {
	Registry *Registry
	// Base is the image to start from; Target the tag to push (host/repo:tag).
	Base   string
	Target string

	Template TemplateInfo
	Kit      KitSpec
	Signer   *Signer

	// Scan options. Skill is required.
	Skill     scanner.Scanner
	MCPStatic scanner.Scanner
	Admission AdmissionFunc
	Compiled  map[string]policy.CompiledAdmission
	BlockList []policy.ListEntry
	AllowList []policy.ListEntry
	// AllowedMCPHosts are remote MCP hosts an admin allows.
	AllowedMCPHosts []string
	// BlockAtOrAbove: see ScanOptions; empty means HIGH here, FloorNone turns it off.
	BlockAtOrAbove scanner.Severity

	// TrustedBases are base image digests (sha256:...) the admin trusts.
	TrustedBases []string
	// BaseAttestor, when set, lets a base that carries its own valid
	// attestation count as trusted.
	BaseAttestor Attestor
	// AllowUnverifiedBase builds on a base that is neither; the statement
	// says so and the controller refuses it unless its policy allows it.
	AllowUnverifiedBase bool

	PolicyGeneration int64
	BuilderID        string
	Platform         Platform
	Limits           Limits
	Now              func() time.Time

	// DryRun scans the composed image and stops before pushing anything.
	DryRun bool
}

// BuildResult is the outcome of Build.
type BuildResult struct {
	Image     *Image
	Digest    string
	Target    string
	Kit       KitInfo
	Base      BaseInfo
	Report    *ScanReport
	Statement *Statement
	Envelope  *Envelope
	// Pushed is true when the image and the attestation are in the registry.
	Pushed bool
}

// Build errors callers can match.
var (
	ErrBaseUnverified = errors.New("the base image is neither on the trusted list nor attested")
	ErrScanBlocked    = errors.New("the build scan blocked the image")
	ErrHooksNotSafe   = errors.New("the hook and settings files or the phone-home switches are not as required")
)

// BuildBlocked is returned with the report when the scan or the hook checks
// refuse the image. Nothing was pushed.
type BuildBlocked struct {
	Cause  error
	Report *ScanReport
}

func (b *BuildBlocked) Error() string {
	var parts []string
	for _, it := range b.Report.Blocked() {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", it.Kind, it.Name, it.Reason))
	}
	if !b.Report.Hooks.RootOwned {
		for _, f := range b.Report.Hooks.Files {
			if !f.OK {
				parts = append(parts, fmt.Sprintf("%s: %s", f.Path, f.Note))
			}
		}
	}
	if !b.Report.Hooks.PhoneHomeOff {
		for _, s := range b.Report.Hooks.Switches {
			if !s.OK {
				parts = append(parts, "switch "+s.Name+" is not set")
			}
		}
	}
	return b.Cause.Error() + ": " + strings.Join(parts, "; ")
}

func (b *BuildBlocked) Unwrap() error { return b.Cause }

// Build composes base + kit, scans the result, and only then pushes the image
// and its signed attestation. A blocked image is never pushed.
func Build(ctx context.Context, o BuildOptions) (*BuildResult, error) {
	if o.Registry == nil || o.Signer == nil && !o.DryRun {
		return nil, errors.New("build: a registry and a signing key are required")
	}
	if o.Platform == (Platform{}) {
		o.Platform = DefaultPlatform
	}
	if o.BlockAtOrAbove == "" {
		o.BlockAtOrAbove = scanner.SeverityHigh
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	baseRef, err := ParseRef(o.Base)
	if err != nil {
		return nil, err
	}
	target, err := ParseRef(o.Target)
	if err != nil {
		return nil, err
	}
	if target.Tag == "" {
		return nil, errors.New("build: the target needs a tag")
	}
	base, err := o.Registry.Image(ctx, baseRef, o.Platform)
	if err != nil {
		return nil, fmt.Errorf("build: base image: %w", err)
	}
	baseInfo, err := judgeBase(ctx, o, base)
	if err != nil {
		return nil, err
	}

	fsys, err := o.Registry.OpenFS(ctx, base, o.Limits)
	if err != nil {
		return nil, fmt.Errorf("build: read the base image: %w", err)
	}
	defer fsys.Close()

	// Whiteouts only for what the base has.
	var whiteouts []string
	for _, p := range o.Kit.Remove {
		if _, ok := fsys.Lookup(p); ok {
			whiteouts = append(whiteouts, p)
		}
	}
	layer, err := BuildLayer(o.Kit.Files, whiteouts, o.Kit.HomeOwners, func(p string) bool { _, ok := fsys.Lookup(p); return ok })
	if err != nil {
		return nil, err
	}
	if err := fsys.AddLayerGzip(layer.Gzip); err != nil {
		return nil, fmt.Errorf("build: compose: %w", err)
	}

	edit := o.configEdit()
	composed, err := ParseConfig(base.ConfigRaw)
	if err != nil {
		return nil, err
	}
	if err := composed.AppendLayer(layer.DiffID, "dc-compose"); err != nil {
		return nil, err
	}
	if err := edit(composed); err != nil {
		return nil, err
	}

	var expected []ExpectedFile
	paths := make([]string, 0, len(o.Kit.Files))
	for _, f := range o.Kit.Files {
		if !o.Kit.UserFiles[f.Path] && f.Symlink == "" && (!f.Dir || (f.UID == 0 && f.GID == 0)) {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		expected = append(expected, ExpectedFile{Path: p})
	}
	rep, err := ScanImage(ctx, fsys, composed, ScanOptions{
		Skill: o.Skill, MCPStatic: o.MCPStatic, Admission: o.Admission, Compiled: o.Compiled,
		BlockList: o.BlockList, AllowList: o.AllowList, AllowedMCPHosts: o.AllowedMCPHosts, BlockAtOrAbove: o.BlockAtOrAbove,
		Connector: o.Template.Connector, Expected: expected, PhoneHome: o.Kit.PhoneHome,
		ConfigSwitches: o.Kit.ConfigSwitches, PolicyGeneration: o.PolicyGeneration, Now: now,
	})
	if err != nil {
		return nil, fmt.Errorf("build: scan: %w", err)
	}
	res := &BuildResult{Report: rep, Base: baseInfo, Target: target.String(),
		Kit: KitInfo{Version: o.Kit.Version, HookContract: o.Kit.HookContract, LayerDigest: layer.Digest,
			LayerDiffID: layer.DiffID, LayerIndex: len(base.Manifest.Layers)}}
	if rep.Summary.Verdict == VerdictBlock {
		return res, &BuildBlocked{Cause: ErrScanBlocked, Report: rep}
	}
	if !rep.HooksOK() {
		return res, &BuildBlocked{Cause: ErrHooksNotSafe, Report: rep}
	}
	if o.DryRun {
		return res, nil
	}

	img, err := o.Registry.AppendLayer(ctx, base, layer, target, "defenseclaw template build", edit)
	if err != nil {
		return res, fmt.Errorf("build: push: %w", err)
	}
	res.Image, res.Digest = img, img.Digest
	st, err := NewStatement(target.Name(), img.Digest, Predicate{
		Template: o.Template, Base: baseInfo, Kit: res.Kit, Hooks: rep.Hooks, Scan: rep.Summary,
		Policy:  PolicyInfo{Generation: o.PolicyGeneration},
		Builder: BuilderInfo{ID: o.BuilderID, BuiltAt: now().UTC()},
	})
	if err != nil {
		return res, err
	}
	env, err := SignStatement(st, o.Signer)
	if err != nil {
		return res, err
	}
	if err := o.Registry.PutAttestation(ctx, target, img.Digest, env); err != nil {
		return res, err
	}
	res.Statement, res.Envelope, res.Pushed = st, env, true
	return res, nil
}

// judgeBase decides the trust of the base image.
func judgeBase(ctx context.Context, o BuildOptions, base *Image) (BaseInfo, error) {
	info := BaseInfo{Ref: o.Base, Digest: base.Digest}
	for _, d := range o.TrustedBases {
		if d == base.Digest || (base.IndexDigest != "" && d == base.IndexDigest) {
			info.Trust = BaseTrustAllowlisted
			return info, nil
		}
	}
	if o.BaseAttestor != nil {
		if v, err := o.BaseAttestor.Verify(ctx, base.Ref.String()); err == nil {
			info.Trust, info.AttestedBy = BaseTrustAttested, v.KeyID
			if v.Statement != nil && v.Statement.Predicate.Base.Trust == BaseTrustUnverified {
				// Built on an unverified base: the weakest link stays the weakest.
				info.Trust = BaseTrustUnverified
				if !o.AllowUnverifiedBase {
					return info, fmt.Errorf("%w: %s is itself built on an unverified base", ErrBaseUnverified, o.Base)
				}
			}
			return info, nil
		}
	}
	if !o.AllowUnverifiedBase {
		return info, fmt.Errorf("%w: %s (digest %s); add the digest to the trusted bases, or build with allow-unverified-base", ErrBaseUnverified, o.Base, short(base.Digest))
	}
	info.Trust = BaseTrustUnverified
	return info, nil
}

// configEdit applies the kit's image settings.
func (o BuildOptions) configEdit() ConfigEdit {
	return func(c *ConfigDoc) error {
		_, _, have, _, err := c.Container()
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(o.Kit.Env))
		for k := range o.Kit.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]string, 0, len(have)+len(keys))
		for _, kv := range have {
			k, _, _ := strings.Cut(kv, "=")
			if _, replaced := o.Kit.Env[k]; !replaced {
				out = append(out, kv)
			}
		}
		for _, k := range keys {
			out = append(out, k+"="+o.Kit.Env[k])
		}
		if len(keys) > 0 {
			if err := c.SetEnv(out); err != nil {
				return err
			}
		}
		if o.Kit.User != "" {
			if err := c.SetUser(o.Kit.User); err != nil {
				return err
			}
		}
		if o.Kit.Workdir != "" {
			if err := c.SetWorkingDir(o.Kit.Workdir); err != nil {
				return err
			}
		}
		if len(o.Kit.Entrypoint) > 0 {
			if err := c.SetEntrypoint(o.Kit.Entrypoint); err != nil {
				return err
			}
		}
		if len(o.Kit.Cmd) > 0 {
			if err := c.SetCmd(o.Kit.Cmd); err != nil {
				return err
			}
		}
		return c.SetLabels(map[string]string{
			"io.defenseclaw.kit.version":   o.Kit.Version,
			"io.defenseclaw.hook-contract": o.Kit.HookContract,
			"io.defenseclaw.connector":     o.Template.Connector,
		})
	}
}

// ScanOnly scans an existing image without building ("template scan").
func ScanOnly(ctx context.Context, reg *Registry, image string, platform Platform, lim Limits, o ScanOptions) (*ScanReport, string, error) {
	ref, err := ParseRef(image)
	if err != nil {
		return nil, "", err
	}
	if platform == (Platform{}) {
		platform = DefaultPlatform
	}
	img, err := reg.Image(ctx, ref, platform)
	if err != nil {
		return nil, "", err
	}
	fsys, err := reg.OpenFS(ctx, img, lim)
	if err != nil {
		return nil, "", err
	}
	defer fsys.Close()
	rep, err := ScanImage(ctx, fsys, img.Config, o)
	return rep, img.Digest, err
}

// PublishOptions configure Publish.
type PublishOptions struct {
	Registry *Registry
	Source   string
	Target   string
	// Verifier checks the source before anything is copied. Required: only
	// an attested image is published.
	Verifier Attestor
}

// Publish copies an attested image, its layers and its attestation to
// another repository or registry and tags it. It copies by digest and checks
// that the digest in the target is the same.
func Publish(ctx context.Context, o PublishOptions) (string, error) {
	if o.Verifier == nil || o.Registry == nil {
		return "", errors.New("publish: a registry and a verifier are required")
	}
	src, err := ParseRef(o.Source)
	if err != nil {
		return "", err
	}
	dst, err := ParseRef(o.Target)
	if err != nil {
		return "", err
	}
	if dst.Tag == "" {
		return "", errors.New("publish: the target needs a tag")
	}
	v, err := o.Verifier.Verify(ctx, o.Source)
	if err != nil {
		return "", fmt.Errorf("publish: %w", err)
	}
	img, err := o.Registry.Image(ctx, src.WithDigest(v.Digest), DefaultPlatform)
	if err != nil {
		return "", err
	}
	if img.Digest != v.Digest {
		return "", errors.New("publish: the attested digest is not a platform image")
	}
	for _, l := range append([]Descriptor{img.Manifest.Config}, img.Manifest.Layers...) {
		if ok, _ := o.Registry.BlobExists(ctx, dst.Registry, dst.Repo, l.Digest); ok {
			continue
		}
		rc, size, err := o.Registry.Blob(ctx, src.Registry, src.Repo, l.Digest)
		if err != nil {
			return "", fmt.Errorf("publish: %w", err)
		}
		if size <= 0 {
			size = l.Size
		}
		err = o.Registry.PutBlob(ctx, dst.Registry, dst.Repo, l.Digest, rc, size)
		_ = rc.Close()
		if err != nil {
			return "", fmt.Errorf("publish: %w", err)
		}
	}
	got, err := o.Registry.PutManifest(ctx, dst.WithDigest(v.Digest), img.Manifest.MediaType, img.ManifestRaw)
	if err != nil {
		return "", err
	}
	if got != v.Digest {
		return "", fmt.Errorf("publish: the target stored %s, not %s", short(got), short(v.Digest))
	}
	envs, err := o.Registry.GetAttestations(ctx, src, v.Digest)
	if err != nil {
		return "", err
	}
	for _, e := range envs {
		if err := o.Registry.PutAttestation(ctx, dst, v.Digest, e); err != nil {
			return "", err
		}
	}
	if _, err := o.Registry.PutManifest(ctx, dst, img.Manifest.MediaType, img.ManifestRaw); err != nil {
		return "", err
	}
	return dst.Name() + "@" + v.Digest, nil
}

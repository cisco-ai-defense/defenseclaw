// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

func sandboxPublicationFixture(t *testing.T) *Sidecar {
	t.Helper()
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	resetConnectorRuleCategories(t)
	previous := currentGeneration()
	previousErr, _ := liveReloadError.Load().(string)
	t.Cleanup(func() {
		liveGeneration.Store(previous)
		liveReloadError.Store(previousErr)
		if previous != nil {
			applyGenerationProviders(previous.Providers)
		}
		audit.SetPolicyStamp(nil)
	})
	cfg := &config.Config{
		ConfigVersion: 9, DataDir: t.TempDir(),
		Gateway: config.GatewayConfig{Token: "fixed-public-test-token"},
		OpenShell: config.OpenShellConfig{Enabled: true, LLM: config.OpenShellLLMNone,
			Workdir: config.OpenShellWorkdirConfig{Mode: config.OpenShellWorkdirCopy}},
	}
	s := &Sidecar{}
	s.publishGeneration(&Generation{Config: s.publishConfig(cfg), ConfigGen: 987654,
		Digest: "sha256:" + strings.Repeat("a", 64)})
	return s
}

func TestSandboxPublicationUsesActualCounterAndRevokesBeforeCommit(t *testing.T) {
	s := sandboxPublicationFixture(t)
	var order []string
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
		order = append(order, "revoke")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	first := owner.current()
	if first.Generation != s.Generation().N || first.Generation == s.Generation().ConfigGen || first.SnapshotID == s.Generation().Digest {
		t.Fatal("owner confused the actual publication counter with metadata or policy digest")
	}
	for range 2 {
		before := owner.current()
		err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
			order = append(order, "commit")
			if len(order)%2 != 0 || order[len(order)-2] != "revoke" {
				t.Fatal("configuration changed before revocation")
			}
			next := cloneConfig(s.currentConfig())
			next.OpenShell.Egress.Block = append(next.OpenShell.Egress.Block, "fixed.example")
			applied := s.publishConfig(next)
			if owner.current() != (sandboxruntime.PolicyAuthorityBinding{}) {
				t.Fatal("config-before-generation publication gap acquired authority")
			}
			s.publishGeneration(&Generation{Config: applied, ConfigGen: 987654,
				Digest: "sha256:" + strings.Repeat("a", 64)})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		after := owner.current()
		if after.Generation != s.Generation().N || after.Generation <= before.Generation || after.SnapshotID != first.SnapshotID {
			t.Fatal("rotation did not bind the actual new publication and same owner epoch")
		}
	}
}

func TestSandboxPublicationFailureClosesOwnerBeforeFurtherCommit(t *testing.T) {
	for _, failure := range []string{"revoke", "cancel-during-revoke", "partial-config", "outside-config", "published-no-token"} {
		t.Run(failure, func(t *testing.T) {
			s := sandboxPublicationFixture(t)
			if failure == "published-no-token" {
				t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			revocations, commits := 0, 0
			owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
				revocations++
				switch failure {
				case "revoke":
					return errors.New("fixed revocation failure")
				case "cancel-during-revoke":
					cancel()
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if failure == "outside-config" {
				s.publishConfig(cloneConfig(s.currentConfig()))
			}
			err = s.publishSandboxAuthority(ctx, func(context.Context) error {
				commits++
				next := cloneConfig(s.currentConfig())
				if failure == "published-no-token" {
					next.Gateway.Token = ""
					s.publishGeneration(&Generation{Config: s.publishConfig(next)})
					return nil
				}
				s.publishConfig(next)
				return errors.New("fixed incomplete publication")
			})
			if err == nil {
				t.Fatal("incomplete native publication was accepted")
			}
			wantCommits := 0
			if failure == "partial-config" || failure == "published-no-token" {
				wantCommits = 1
			}
			if commits != wantCommits || failure == "outside-config" && revocations != 0 {
				t.Fatal("native publication crossed a failed precondition")
			}
			before := revocations
			if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
				t.Fatal("closed native gate ran another commit")
				return nil
			}); err == nil || revocations != before {
				t.Fatal("native publication failure did not remain closed")
			}
			if _, _, _, err := owner.resolve(packs.Flags{}, sandboxruntime.PolicyOptions{}); failure == "partial-config" && !errors.Is(err, errSandboxPublication) {
				t.Fatal("partial configuration acquired a resolved policy")
			}
		})
	}
}

func TestSandboxPublicationKeepsLegacyCommitAndRejectsEarlyReload(t *testing.T) {
	s := sandboxPublicationFixture(t)
	sentinel := errors.New("fixed legacy commit result")
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error { return sentinel }); err != sentinel || s.sandboxLaunchOwner.Load() != nil {
		t.Fatal("nil native owner changed the existing commit path")
	}
	if _, err := s.installSandboxLaunchOwner(func(context.Context) error {
		t.Fatal("rejected reload revoked native sessions")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg := s.currentConfig()
	if err := s.applyConfigReloadSnapshot(t.Context(), cfg, cloneConfig(cfg), ConfigDiff{}, configReloadSource{}); err == nil {
		t.Fatal("reload accepted absent validated source")
	}
}

func TestSandboxPublicationRejectsUnpairedOrLateInstallationAndTokenWrite(t *testing.T) {
	for _, invalid := range []string{"no-token", "unpaired-config", "unpaired-global", "late-worker", "no-revocation"} {
		t.Run(invalid, func(t *testing.T) {
			s := sandboxPublicationFixture(t)
			revoke := func(context.Context) error { return nil }
			switch invalid {
			case "no-token":
				t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
				cfg := cloneConfig(s.currentConfig())
				cfg.Gateway.Token = ""
				s.publishGeneration(&Generation{Config: s.publishConfig(cfg)})
			case "unpaired-config":
				s.publishConfig(cloneConfig(s.currentConfig()))
			case "unpaired-global":
				publishGeneration(&Generation{Config: s.currentConfig()})
			case "late-worker":
				s.configMgr = &ConfigManager{}
			case "no-revocation":
				revoke = nil
			}
			if _, err := s.installSandboxLaunchOwner(revoke); err == nil || s.sandboxLaunchOwner.Load() != nil {
				t.Fatal("native owner installation crossed an incomplete startup")
			}
		})
	}
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil }); err == nil || s.sandboxLaunchOwner.Load() != owner {
		t.Fatal("another owner replaced live native authority")
	}
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	next := cloneConfig(s.currentConfig())
	next.Gateway.Token = ""
	s.publishConfig(next) // simulate an invalid out-of-band writer, never authorize it
	if _, err := s.ensureGatewayTokenSynthesis(); !errors.Is(err, errSandboxPublication) {
		t.Fatal("missing token bypassed installed native authority")
	}
	if _, err := os.Stat(filepath.Join(next.DataDir, ".env")); !errors.Is(err, os.ErrNotExist) || s.currentConfig().Gateway.Token != "" || os.Getenv("DEFENSECLAW_GATEWAY_TOKEN") != "" {
		t.Fatal("refused native token publication wrote state")
	}
}

func TestSandboxPublicationRejectsDifferentProcessWideGeneration(t *testing.T) {
	for _, publisher := range []string{"other-sidecar", "metadata-refresh"} {
		t.Run(publisher, func(t *testing.T) {
			s := sandboxPublicationFixture(t)
			owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
				t.Fatal("unpaired global authority reached revocation")
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			original := s.Generation()
			if publisher == "other-sidecar" {
				other := &Sidecar{}
				other.publishGeneration(&Generation{Config: other.publishConfig(cloneConfig(s.currentConfig()))})
			} else {
				// A metadata-only global replacement also cannot silently acquire
				// the original Sidecar's native authority, even with the same N.
				next := *original
				next.ConfigGen++
				liveGeneration.Store(&next)
			}
			if s.Generation() != original || s.currentConfig() != original.Config || currentGeneration() == original {
				t.Fatal("fixture did not isolate the process-wide authority change")
			}
			if owner.current() != (sandboxruntime.PolicyAuthorityBinding{}) {
				t.Fatal("stale Sidecar retained native authority after global publication")
			}
			if _, _, _, err := owner.resolve(packs.Flags{Harness: "must-not-resolve"}, sandboxruntime.PolicyOptions{}); !errors.Is(err, errSandboxPublication) {
				t.Fatal("unpaired process-wide publication reached policy resolution")
			}
			if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
				t.Fatal("unpaired global authority entered a reload commit")
				return nil
			}); err == nil {
				t.Fatal("unpaired global authority did not close the launch gate")
			}
		})
	}
}

func TestSandboxPublicationResolvesOwnedRunWithoutRestampingAuthority(t *testing.T) {
	s := sandboxPublicationFixture(t)
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	options := sandboxruntime.PolicyOptions{Harness: sandboxruntime.HarnessIdentity{
		Version: "fixed-synthetic-harness", HookContract: "fixed-synthetic-hooks",
		Artifact: sandboxruntime.ArtifactIdentity{Kind: sandboxruntime.OCIImage, Digest: "sha256:" + strings.Repeat("b", 64)},
	}}
	run, policy, _, err := owner.resolve(packs.Flags{Harness: "claudecode"}, options)
	if err != nil || run == nil || policy == nil || policy.Digest() == "" {
		t.Fatal("paired publication did not produce one owned policy", err)
	}
	if _, _, err := sandboxruntime.BindResolvedExecutionPolicy(run, options); err == nil {
		t.Fatal("zero-authority caller options replaced captured host authority")
	}
	options.Authority = owner.current()
	bound, _, err := sandboxruntime.BindResolvedExecutionPolicy(run, options)
	if err != nil || bound.Digest() != policy.Digest() {
		t.Fatal("returned run and policy differ", err)
	}
	if _, _, _, err := owner.resolve(packs.Flags{Harness: "claudecode"}, options); !errors.Is(err, errSandboxPublication) {
		t.Fatal("caller supplied a host authority binding")
	}
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		s.publishGeneration(&Generation{Config: s.publishConfig(cloneConfig(s.currentConfig()))})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	options.Authority = owner.current()
	if _, _, err := sandboxruntime.BindResolvedExecutionPolicy(run, options); err == nil {
		t.Fatal("old run was stamped with the new actual generation")
	}
	s.publishConfig(cloneConfig(s.currentConfig()))
	if _, _, _, err := owner.resolve(packs.Flags{Harness: "must-not-resolve"}, sandboxruntime.PolicyOptions{}); !errors.Is(err, errSandboxPublication) {
		t.Fatal("unpaired config reached the pack resolver")
	}
}

func TestSandboxPublicationDetectsOutOfBandResolvedTokenChanges(t *testing.T) {
	for _, name := range []string{"FIXED_TEST_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"} {
		t.Run(name, func(t *testing.T) {
			s := sandboxPublicationFixture(t)
			t.Setenv(name, "fixed-public-test-token-a")
			if name == "FIXED_TEST_GATEWAY_TOKEN" {
				next := cloneConfig(s.currentConfig())
				next.Gateway.TokenEnv = name
				s.publishGeneration(&Generation{Config: s.publishConfig(next)})
			}
			owner, err := s.installSandboxLaunchOwner(func(context.Context) error {
				t.Fatal("changed token crossed launch authority before refusal")
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			before := owner.current()
			t.Setenv(name, "fixed-public-test-token-b")
			after := owner.current()
			if after.Generation != before.Generation || after.SnapshotID == before.SnapshotID || strings.Contains(after.SnapshotID, "fixed-public-test-token") {
				t.Fatal("opaque authority did not detect a live resolved-token change")
			}
			if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
				t.Fatal("changed token entered a publication under the old authority")
				return nil
			}); err == nil {
				t.Fatal("out-of-band gateway credential change retained launch authority")
			}
		})
	}
}

func TestSandboxPublicationRotatesTokenOnlyWithAdvancingActualGeneration(t *testing.T) {
	s := sandboxPublicationFixture(t)
	revocations := 0
	owner, err := s.installSandboxLaunchOwner(func(context.Context) error { revocations++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	before := owner.current()
	if err := s.publishSandboxAuthority(t.Context(), func(context.Context) error {
		next := cloneConfig(s.currentConfig())
		next.Gateway.Token = "fixed-public-test-token-next"
		s.publishGeneration(&Generation{Config: s.publishConfig(next)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after := owner.current()
	if revocations != 1 || after.Generation != s.Generation().N || after.Generation <= before.Generation || after.SnapshotID == before.SnapshotID {
		t.Fatal("gateway token rotation did not revoke and advance the actual publication")
	}
}

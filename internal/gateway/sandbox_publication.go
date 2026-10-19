// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

var errSandboxPublication = errors.New("native sandbox authority requires a complete gateway publication")

// sidecarSandboxLaunchOwner belongs to this gateway, not a request or guest.
// The future native controller must install it during serial startup, after
// token synthesis and before ConfigManager or any worker starts. Installation
// alone never qualifies a backend. Managed daemons need their own adoption
// transaction; a gateway's process counter is not their policy generation.
// revoke runs with ConfigManager and LaunchGate locks held: it must be bounded,
// stop only its owned grants/workloads and never reenter either owner.
type sidecarSandboxLaunchOwner struct {
	sidecar *Sidecar
	key     [32]byte
	gate    *sandboxruntime.LaunchGate
	revoke  func(context.Context) error
}

func (s *Sidecar) installSandboxLaunchOwner(revoke func(context.Context) error) (*sidecarSandboxLaunchOwner, error) {
	if s == nil || revoke == nil || s.configMgr != nil || s.sandboxLaunchOwner.Load() != nil {
		return nil, errSandboxPublication
	}
	g := s.Generation()
	if g == nil || currentGeneration() != g || g.N == 0 || g.Config == nil || g.Config != s.currentConfig() || strings.TrimSpace(g.Config.Gateway.ResolvedToken()) == "" {
		return nil, errSandboxPublication
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errSandboxPublication
	}
	owner := &sidecarSandboxLaunchOwner{sidecar: s, key: nonce, revoke: revoke}
	gate, err := sandboxruntime.NewLaunchGate(owner.current)
	if err != nil {
		return nil, err
	}
	owner.gate = gate
	if !s.sandboxLaunchOwner.CompareAndSwap(nil, owner) {
		return nil, errSandboxPublication
	}
	return owner, nil
}

// current reads Config and N from one actual publication. cfgCurrent can move
// before Generation during commit: such a gap is never native launch authority.
// Process-wide scanners and providers must use this same generation, too.
// The opaque epoch also binds the resolved gateway token: changing a live env
// override outside a publication changes authority. A private random HMAC key
// prevents the public binding from becoming a token fingerprint or verifier.
func (o *sidecarSandboxLaunchOwner) current() sandboxruntime.PolicyAuthorityBinding {
	if o == nil || o.sidecar == nil {
		return sandboxruntime.PolicyAuthorityBinding{}
	}
	g := o.sidecar.Generation()
	if g == nil || currentGeneration() != g || g.N == 0 || g.Config == nil || g.Config != o.sidecar.currentConfig() {
		return sandboxruntime.PolicyAuthorityBinding{}
	}
	token := g.Config.Gateway.ResolvedToken()
	if strings.TrimSpace(token) == "" {
		return sandboxruntime.PolicyAuthorityBinding{}
	}
	mac := hmac.New(sha256.New, o.key[:])
	_, _ = mac.Write([]byte("defenseclaw-sandbox-gateway-authority-v1\x00"))
	_, _ = mac.Write([]byte(token))
	return sandboxruntime.PolicyAuthorityBinding{SnapshotID: "gateway-" + hex.EncodeToString(mac.Sum(nil)), Generation: g.N}
}

// resolve captures one applied Config/N pair and one run-specific evaluator.
// The run's own digest binds packs, request/repository inputs and resolved host
// facts; it is separate from Generation.Digest. Existing pack pins still apply.
// RegisterPrepared and Launch must use this owner's gate: a rotation after this
// final check makes the captured binding stale and admission refuses it.
func (o *sidecarSandboxLaunchOwner) resolve(flags packs.Flags, options sandboxruntime.PolicyOptions) (*sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, []packs.Violation, error) {
	if o == nil || o.sidecar == nil || options.Authority != (sandboxruntime.PolicyAuthorityBinding{}) {
		return nil, nil, nil, errSandboxPublication
	}
	g := o.sidecar.Generation()
	binding := o.current()
	if g == nil || binding.Generation == 0 || g.N != binding.Generation || g.Config != o.sidecar.currentConfig() || strings.TrimSpace(g.Config.Gateway.ResolvedToken()) == "" {
		return nil, nil, nil, errSandboxPublication
	}
	options.Authority = binding
	run, violations, err := sandboxruntime.ResolveHostRun(g.Config, flags, options)
	if err != nil {
		return nil, nil, violations, err
	}
	policy, violations, err := sandboxruntime.BindResolvedExecutionPolicy(run, options)
	if err != nil {
		return nil, nil, violations, err
	}
	if o.sidecar.Generation() != g || o.current() != binding {
		return nil, nil, violations, errSandboxPublication
	}
	return run, policy, violations, nil
}

// publishSandboxAuthority wraps the real reload commit, including token/v8
// changes before publishConfig and all work after publishGeneration. Candidate
// rejection and asset no-ops occur before this method. The nil-owner path keeps
// existing OpenShell behavior and starts no worker, timer or listener.
func (s *Sidecar) publishSandboxAuthority(ctx context.Context, commit func(context.Context) error) error {
	owner := s.sandboxLaunchOwner.Load()
	if owner == nil {
		return commit(ctx)
	}
	return owner.gate.RotatePublished(ctx, func(ctx context.Context) (sandboxruntime.PolicyAuthorityBinding, error) {
		if err := owner.revoke(ctx); err != nil {
			return sandboxruntime.PolicyAuthorityBinding{}, err
		}
		if err := ctx.Err(); err != nil {
			return sandboxruntime.PolicyAuthorityBinding{}, err
		}
		if err := commit(ctx); err != nil {
			return sandboxruntime.PolicyAuthorityBinding{}, err
		}
		return owner.current(), nil
	})
}

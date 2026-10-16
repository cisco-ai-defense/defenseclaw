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

package gateway

// The hook-contract gate and the sandbox-only layout (#1069, PR #1070).
//
// In the layout the OpenShell sandbox documentation recommends - no agent
// installed on the host, the agent inside the harness image - the guardrail
// could not be put into action mode. Both admission paths asked for the
// connector's host agent version, found none, resolved the contract to
// "unversioned" and refused - even though the host held a stronger fact than a
// probe produces: the harness image DefenseClaw itself built, pinned a harness
// version into, and verified by proving that a denied tool call does not run
// (image.Builder.VerifyHooks, which is what sets Record.HookFireVerified).
//
// This file supplies that fact to those two paths. It is deliberately narrow:
//
//   - it applies only when the host has no agent: the last discovery looked
//     for the connector's agent and found no binary
//     (connector.CachedAgentNotFound), and no agent executable is recorded.
//     A host agent whose version could not be read, a missing discovery cache
//     and a cache without the connector's entry keep the unversioned verdict,
//     so a host verdict always keeps its authority and the lock never pairs
//     the image's harness version with a host executable. This is the Python
//     setup gate's rule too (the image is used only for an agent discovery
//     reports as not installed);
//   - it applies only when the connector's effective guardrail mode is action,
//     which is the mode that refuses an unversioned contract;
//   - it accepts only the image a sandbox started now would run: the record of
//     exactly the build context this config, this host user and this release
//     render (image.Store.Current), whose hooks were fire-verified (and, for
//     an image built for the MicroVM driver, whose MicroVM scenario passed),
//     whose tag Docker still resolves to the verified image ID, and whose
//     harness version resolves to a Known sandbox contract.
//
// Everything else keeps refusing exactly as before: an unknown host version, an
// installed agent with no readable version, no discovery record, a missing or
// unverified image, an image of another release, of another pinned
// harness version or base image, an image rebuilt since its probe, a harness
// version without a reviewed contract, and (independently, in the callers) a
// contract that drifted from the lock.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
)

// sandboxEvidenceInspectTimeout bounds the one `docker image inspect` the
// admission runs per candidate image, so a stalled Docker daemon refuses the
// evidence instead of holding the guardrail start.
const sandboxEvidenceInspectTimeout = 10 * time.Second

// sandboxHarnessContract is the hook contract of a connector's verified
// harness image, together with the record it came from so a caller can name
// its evidence.
type sandboxHarnessContract struct {
	Resolution connector.HookContractResolution
	Record     image.Record
}

// sandboxEvidenceHost is everything outside the config that names the
// current image: the platform (which compute drivers can run the sandbox),
// the run-as identity baked into the image, the release that renders its
// hooks, and the Docker lookup that confirms a tag still names the verified
// image. Tests replace it.
type sandboxEvidenceHost struct {
	GOOS    string
	UID     int
	GID     int
	Release string
	// ImageID returns the image ID Docker's tag resolves to.
	ImageID func(ctx context.Context, tag string) (string, error)
}

// currentSandboxEvidenceHost is this process's host.
func currentSandboxEvidenceHost() sandboxEvidenceHost {
	return sandboxEvidenceHost{
		GOOS: runtime.GOOS, UID: os.Getuid(), GID: os.Getgid(),
		Release: manager.ImageVersion(), ImageID: dockerImageID,
	}
}

// sandboxEvidenceHostFunc is the host the sidecar reads; tests replace it.
var sandboxEvidenceHostFunc = currentSandboxEvidenceHost

// dockerImageID asks Docker for the image ID tag names.
func dockerImageID(ctx context.Context, tag string) (string, error) {
	var stdout, stderr strings.Builder
	if err := (image.CLI{}).Run(ctx, nil, &stdout, &stderr, "image", "inspect", "--format", "{{.Id}}", tag); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

// sandboxEvidenceTargets lists the image kinds (MicroVM or not) a sandbox
// of this host can run: macOS runs the MicroVM driver only (unless the
// docker driver is configured), Linux the docker driver or the MicroVM
// driver, and only the docker driver when enterprise.openshell.driver says
// docker (GAP-0451; vm and auto may fall back to docker). Other platforms
// run no OpenShell sandbox. cli/defenseclaw/sandbox_images.py image_kinds
// mirrors it.
func sandboxEvidenceTargets(cfg *config.Config, goos string) []bool {
	switch goos {
	case "darwin":
		if cfg.Enterprise.OpenShell.SandboxDriver(goos) == config.EnterpriseOpenShellDriverDocker {
			return []bool{false}
		}
		return []bool{true}
	case "linux":
		if strings.EqualFold(strings.TrimSpace(cfg.Enterprise.OpenShell.Driver), config.EnterpriseOpenShellDriverDocker) {
			return []bool{false}
		}
		return []bool{false, true}
	}
	return nil
}

// sandboxHarnessHookContract returns the contract of the connector's current
// verified harness image, when that contract is Known. No image, an image
// that is not current, not verified or rebuilt since, or an unknown contract
// are all reported as (false, nil): the caller keeps its host-based verdict.
func sandboxHarnessHookContract(cfg *config.Config, connectorName string) (sandboxHarnessContract, bool, error) {
	return sandboxHarnessHookContractFor(cfg, connectorName, sandboxEvidenceHostFunc())
}

// sandboxHarnessHookContractFor is sandboxHarnessHookContract on host.
func sandboxHarnessHookContractFor(cfg *config.Config, connectorName string, host sandboxEvidenceHost) (sandboxHarnessContract, bool, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" || name == "" {
		return sandboxHarnessContract{}, false, nil
	}
	spec, ok := harness.Get(name)
	if !ok {
		return sandboxHarnessContract{}, false, nil
	}
	targets := sandboxEvidenceTargets(cfg, host.GOOS)
	if len(targets) == 0 {
		return sandboxHarnessContract{}, false, nil
	}
	store := image.NewStore(cfg.DataDir)
	// No store means no image was ever built here; do not create one (Owner
	// would).
	if _, err := os.Lstat(store.Path()); errors.Is(err, os.ErrNotExist) {
		return sandboxHarnessContract{}, false, nil
	} else if err != nil {
		return sandboxHarnessContract{}, false, fmt.Errorf("sandbox harness hook contract: %w", err)
	}
	owner, err := store.Owner()
	if err != nil {
		return sandboxHarnessContract{}, false, fmt.Errorf("sandbox harness hook contract: %w", err)
	}
	for _, microVM := range targets {
		// The same BuildSpec the sandbox manager selects its image with
		// (manager.Manager.image, sandboxcli builderImages.spec).
		c, err := image.NewContext(image.BuildSpec{
			Harness: spec, HarnessVersion: cfg.OpenShell.Image.HarnessVersions[spec.Name], BaseImage: cfg.OpenShell.Image.Base,
			UID: host.UID, GID: host.GID, IngressPort: cfg.OpenShellIngressPort(), FailMode: connector.SandboxFailMode,
			DefenseClawVersion: host.Release, Owner: owner, MicroVM: microVM,
		})
		if err != nil {
			// A pinned harness version without a reviewed sandbox contract, a
			// root run-as identity or an invalid release renders no image a
			// sandbox could run.
			continue
		}
		rec, ok, err := store.Current(c)
		if err != nil {
			return sandboxHarnessContract{}, false, fmt.Errorf("sandbox harness hook contract: %w", err)
		}
		if !ok || !rec.HookFireVerified || (rec.MicroVM && !rec.MicroVMVerified) {
			continue
		}
		resolution := connector.ResolveSandboxHookContract(rec.Connector, strings.TrimSpace(rec.HarnessVersion))
		if resolution.Status != connector.HookCompatibilityKnown {
			continue
		}
		// A rebuild moves the tag before the new image is verified, and a
		// failed one can leave the old verified record behind a tag that
		// is gone: the record is evidence only while Docker still names its
		// image (image.Builder.Current).
		if host.ImageID == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), sandboxEvidenceInspectTimeout)
		id, err := host.ImageID(ctx, rec.Tag)
		cancel()
		if err != nil || id == "" || id != rec.ImageID {
			continue
		}
		resolution.Reason = harnessEvidenceReason(rec, resolution.Reason)
		return sandboxHarnessContract{Resolution: resolution, Record: rec}, true, nil
	}
	return sandboxHarnessContract{}, false, nil
}

// harnessEvidenceReason names the evidence a sandbox-derived resolution came
// from, appended to whatever the contract table said. It reaches the hook
// contract lock's compatibility_reason and the gateway log, so an operator can
// see why an enforcing hook was installed without a host agent.
func harnessEvidenceReason(rec image.Record, reason string) string {
	evidence := fmt.Sprintf(
		"resolved from the verified harness image %s (harness %s, contract %s, hook-fire probe passed %s)",
		rec.Tag, strings.TrimSpace(rec.HarnessVersion), rec.HookContract,
		rec.HookFireVerifiedAt.UTC().Format(time.RFC3339),
	)
	if strings.TrimSpace(reason) == "" {
		return evidence
	}
	return reason + "; " + evidence
}

// applySandboxHarnessEvidence replaces the unversioned verdict of a host with
// no agent with the current verified harness image's contract, when the
// connector's effective guardrail mode is action. "No agent" means the last
// discovery found no binary (connector.CachedAgentNotFound) and agentExecutable,
// the executable the caller pairs with the version, is empty. Every other case
// returns its inputs unchanged, so a host agent (versioned or not), a host
// without a discovery record, an observe-mode connector and a connector with
// no current verified image behave exactly as before.
func (s *Sidecar) applySandboxHarnessEvidence(connectorName, agentVersion, agentExecutable string, resolution connector.HookContractResolution) (string, connector.HookContractResolution) {
	if s == nil {
		return agentVersion, resolution
	}
	cfg := s.currentConfig()
	if cfg == nil {
		return agentVersion, resolution
	}
	if strings.TrimSpace(agentVersion) != "" || resolution.Status == connector.HookCompatibilityKnown {
		return agentVersion, resolution
	}
	if strings.TrimSpace(agentExecutable) != "" || !connector.CachedAgentNotFound(cfg.DataDir, connectorName) {
		return agentVersion, resolution
	}
	if !strings.EqualFold(strings.TrimSpace(cfg.EffectiveGuardrailModeForConnector(connectorName)), "action") {
		return agentVersion, resolution
	}
	evidence, ok, err := sandboxHarnessHookContract(cfg, connectorName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[guardrail] connector %s: sandbox harness evidence unreadable: %v\n", connectorName, err)
		return agentVersion, resolution
	}
	if !ok {
		return agentVersion, resolution
	}
	fmt.Fprintf(os.Stderr,
		"[guardrail] connector %s: action mode admitted without a host agent, on the verified harness image %s (harness %s, contract %s, hook-fire probe passed %s)\n",
		connectorName, evidence.Record.Tag, strings.TrimSpace(evidence.Record.HarnessVersion),
		evidence.Resolution.Contract.ContractID, evidence.Record.HookFireVerifiedAt.UTC().Format(time.RFC3339))
	return strings.TrimSpace(evidence.Record.HarnessVersion), evidence.Resolution
}

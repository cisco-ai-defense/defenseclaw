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

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

const (
	evidenceTestOwner   = "0123456789abcdef"
	evidenceTestRelease = "1.0.2"
	evidenceTestImageID = "sha256:b5c5beadc6252084bf397c610cc7a214b62dd4a07213a1ef50d98c1f52eb453e"
)

func evidenceTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.Mode = "action"
	return cfg
}

// evidenceTestHost is a Linux host whose Docker names every tag in ids.
func evidenceTestHost(ids map[string]string) sandboxEvidenceHost {
	return sandboxEvidenceHost{
		GOOS: "linux", UID: 1000, GID: 1000, Release: evidenceTestRelease,
		ImageID: func(_ context.Context, tag string) (string, error) {
			if id, ok := ids[tag]; ok {
				return id, nil
			}
			return "", errors.New("no such image")
		},
	}
}

// currentRecord is the record image.Builder writes for the image a sandbox
// of cfg on host runs, verified unless the caller changes it.
func currentRecord(t *testing.T, cfg *config.Config, host sandboxEvidenceHost, name string, microVM bool) image.Record {
	t.Helper()
	if runtime.GOOS == "windows" {
		// image.NewContext renders the sandbox artifacts, which a Windows host
		// refuses to do: it runs no OpenShell sandbox, so it has no image
		// evidence either (the product's NewContext error is a refusal).
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	spec, ok := harness.Get(name)
	if !ok {
		t.Fatalf("no %s harness", name)
	}
	c, err := image.NewContext(image.BuildSpec{
		Harness: spec, HarnessVersion: cfg.OpenShell.Image.HarnessVersions[name], BaseImage: cfg.OpenShell.Image.Base,
		UID: host.UID, GID: host.GID, IngressPort: cfg.OpenShellIngressPort(), FailMode: connector.SandboxFailMode,
		DefenseClawVersion: host.Release, Owner: evidenceTestOwner, MicroVM: microVM,
	})
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	return image.Record{
		Tag: c.Tag, ImageID: evidenceTestImageID, ContentHash: c.ContentHash, Connector: spec.Name,
		HarnessVersion: c.HarnessVersion, HookContract: c.Contract, BaseImage: c.Spec.BaseImage,
		UID: c.Spec.UID, GID: c.Spec.GID, IngressPort: c.Spec.IngressPort, DefenseClawVersion: c.Spec.DefenseClawVersion,
		FailMode: c.Spec.FailMode, Owner: c.Spec.Owner, MicroVM: microVM,
		BuiltAt:          time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC),
		HookFireVerified: true, HookFireVerifiedAt: time.Date(2026, 10, 13, 10, 1, 0, 0, time.UTC),
		MicroVMVerified: microVM,
	}
}

// writeImageStore writes the image store image.Store reads.
func writeImageStore(t *testing.T, dataDir string, records ...image.Record) {
	t.Helper()
	dir := filepath.Join(dataDir, "sandboxes")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if records == nil {
		records = []image.Record{}
	}
	body, err := json.Marshal(map[string]any{"version": 1, "owner": evidenceTestOwner, "images": records})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images.json"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestSandboxHarnessHookContractAcceptsTheCurrentVerifiedImage is #1069: no
// host agent, but the image a sandbox would run now had its hooks proven to
// fire.
func TestSandboxHarnessHookContractAcceptsTheCurrentVerifiedImage(t *testing.T) {
	cfg := evidenceTestConfig(t)
	host := evidenceTestHost(nil)
	rec := currentRecord(t, cfg, host, "claudecode", false)
	host = evidenceTestHost(map[string]string{rec.Tag: rec.ImageID})
	writeImageStore(t, cfg.DataDir, rec)

	evidence, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host)
	if err != nil || !ok {
		t.Fatalf("the current verified image was not accepted (ok=%v err=%v)", ok, err)
	}
	if evidence.Record.Tag != rec.Tag {
		t.Errorf("tag = %q, want %q", evidence.Record.Tag, rec.Tag)
	}
	if evidence.Resolution.Status != connector.HookCompatibilityKnown || evidence.Resolution.Contract.ContractID != rec.HookContract {
		t.Errorf("resolution = %+v, want Known %s", evidence.Resolution, rec.HookContract)
	}
}

func TestSandboxHarnessHookContractRefusesAnImageThatIsNotCurrentAndVerified(t *testing.T) {
	type tc struct {
		name string
		// mutate changes the stored records, the config after the build, or
		// the host; it returns the records to store.
		mutate func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, rec image.Record) []image.Record
	}
	cases := []tc{
		{"no store", func(*testing.T, *config.Config, *sandboxEvidenceHost, image.Record) []image.Record { return nil }},
		{"hooks not verified", func(_ *testing.T, _ *config.Config, _ *sandboxEvidenceHost, rec image.Record) []image.Record {
			rec.HookFireVerified = false
			return []image.Record{rec}
		}},
		{"built by another release", func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, _ image.Record) []image.Record {
			old := *host
			old.Release = "1.0.1"
			return []image.Record{currentRecord(t, cfg, old, "claudecode", false)}
		}},
		{"base image changed after the build", func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, _ image.Record) []image.Record {
			// Built while the config named another base image; a sandbox
			// would run (and build) one on the configured base now.
			based := *cfg
			based.OpenShell.Image.Base = "registry.example/base@sha256:" + strings.Repeat("ab", 32)
			return []image.Record{currentRecord(t, &based, *host, "claudecode", false)}
		}},
		{"rebuilt: the tag names another image", func(_ *testing.T, _ *config.Config, host *sandboxEvidenceHost, rec image.Record) []image.Record {
			host.ImageID = func(context.Context, string) (string, error) { return "sha256:ffff", nil }
			return []image.Record{rec}
		}},
		{"tag gone", func(_ *testing.T, _ *config.Config, host *sandboxEvidenceHost, rec image.Record) []image.Record {
			host.ImageID = func(context.Context, string) (string, error) { return "", errors.New("no such image") }
			return []image.Record{rec}
		}},
		{"another connector's image", func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, _ image.Record) []image.Record {
			return []image.Record{currentRecord(t, cfg, *host, "codex", false)}
		}},
		{"another host user's image", func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, _ image.Record) []image.Record {
			other := *host
			other.UID, other.GID = 1001, 1001
			return []image.Record{currentRecord(t, cfg, other, "claudecode", false)}
		}},
		{"MicroVM image whose MicroVM scenario did not pass", func(t *testing.T, cfg *config.Config, host *sandboxEvidenceHost, _ image.Record) []image.Record {
			vm := currentRecord(t, cfg, *host, "claudecode", true)
			vm.MicroVMVerified = false
			vm.MicroVMInconclusive = "the probe settled nothing"
			return []image.Record{vm}
		}},
		{"macOS with only a docker-driver image", func(_ *testing.T, _ *config.Config, host *sandboxEvidenceHost, rec image.Record) []image.Record {
			host.GOOS = "darwin"
			return []image.Record{rec}
		}},
		{"Windows runs no sandbox", func(_ *testing.T, _ *config.Config, host *sandboxEvidenceHost, rec image.Record) []image.Record {
			host.GOOS = "windows"
			return []image.Record{rec}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := evidenceTestConfig(t)
			rec := currentRecord(t, cfg, evidenceTestHost(nil), "claudecode", false)
			host := evidenceTestHost(nil)
			host.ImageID = func(_ context.Context, tag string) (string, error) { return evidenceTestImageID, nil }
			records := c.mutate(t, cfg, &host, rec)
			if records != nil {
				writeImageStore(t, cfg.DataDir, records...)
			}
			if evidence, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host); err != nil {
				t.Fatalf("unexpected error: %v", err)
			} else if ok {
				t.Fatalf("refusal case accepted evidence: %+v", evidence.Record)
			}
		})
	}
}

// TestSandboxHarnessHookContractAcceptsAMicroVMVerifiedImageOnMacOS: a Mac
// runs the MicroVM driver, so its evidence is the MicroVM image, and only
// once that image's MicroVM scenario passed.
func TestSandboxHarnessHookContractAcceptsAMicroVMVerifiedImageOnMacOS(t *testing.T) {
	cfg := evidenceTestConfig(t)
	host := evidenceTestHost(nil)
	host.GOOS = "darwin"
	vm := currentRecord(t, cfg, host, "claudecode", true)
	host.ImageID = func(context.Context, string) (string, error) { return vm.ImageID, nil }
	writeImageStore(t, cfg.DataDir, vm)
	evidence, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host)
	if err != nil || !ok || !evidence.Record.MicroVM {
		t.Fatalf("MicroVM-verified image not accepted on macOS (ok=%v err=%v rec=%+v)", ok, err, evidence.Record)
	}
}

// TestSandboxHarnessHookContractHonorsAnExplicitDockerDriverOnLinux: the
// docker driver runs no MicroVM image, so on a Linux host configured for it
// a verified MicroVM image is no evidence; its docker image still is
// (GAP-0451).
func TestSandboxHarnessHookContractHonorsAnExplicitDockerDriverOnLinux(t *testing.T) {
	cfg := evidenceTestConfig(t)
	host := evidenceTestHost(nil)
	vm := currentRecord(t, cfg, host, "claudecode", true)
	host.ImageID = func(context.Context, string) (string, error) { return vm.ImageID, nil }
	writeImageStore(t, cfg.DataDir, vm)
	for _, driver := range []string{"", "auto", "vm"} {
		cfg.Enterprise.OpenShell.Driver = driver
		if evidence, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host); err != nil || !ok || !evidence.Record.MicroVM {
			t.Fatalf("driver %q: MicroVM-verified image not accepted on Linux (ok=%v err=%v)", driver, ok, err)
		}
	}
	for _, driver := range []string{"docker", " Docker "} {
		cfg.Enterprise.OpenShell.Driver = driver
		if _, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host); err != nil || ok {
			t.Fatalf("driver %q: MicroVM image accepted for the docker driver (ok=%v err=%v)", driver, ok, err)
		}
	}
	docker := currentRecord(t, cfg, host, "claudecode", false)
	writeImageStore(t, cfg.DataDir, vm, docker)
	if evidence, ok, err := sandboxHarnessHookContractFor(cfg, "claudecode", host); err != nil || !ok || evidence.Record.MicroVM {
		t.Fatalf("docker driver: docker image not accepted (ok=%v err=%v rec=%+v)", ok, err, evidence.Record)
	}
}

// writeAgentDiscovery writes the agent_discovery.json entry discovery records
// for connector name (connector.LoadCachedAgentVersion and
// connector.CachedAgentNotFound read it).
func writeAgentDiscovery(t *testing.T, dataDir, name string, entry map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"agents": map[string]any{name: entry}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// agentNotFound is the entry discovery records when it looked and found no
// binary.
var agentNotFound = map[string]any{"installed": false, "binary_path": "", "version": ""}

// evidenceSidecar is a sidecar of cfg whose host has the current verified
// claudecode image; it returns that image's record.
func evidenceSidecar(t *testing.T, cfg *config.Config) (*Sidecar, image.Record) {
	t.Helper()
	host := evidenceTestHost(nil)
	rec := currentRecord(t, cfg, host, "claudecode", false)
	host.ImageID = func(context.Context, string) (string, error) { return rec.ImageID, nil }
	writeImageStore(t, cfg.DataDir, rec)
	prev := sandboxEvidenceHostFunc
	sandboxEvidenceHostFunc = func() sandboxEvidenceHost { return host }
	t.Cleanup(func() { sandboxEvidenceHostFunc = prev })
	return &Sidecar{cfg: cfg}, rec
}

// applyAsTheCallersDo runs applySandboxHarnessEvidence on the version,
// executable and resolution runGuardrail and connectorSetupOptsChecked read
// from the data dir.
func applyAsTheCallersDo(s *Sidecar, name string) (string, string, connector.HookContractResolution) {
	version := connector.LoadCachedAgentVersion(s.cfg.DataDir, name)
	executable := connector.LoadCachedAgentExecutable(s.cfg.DataDir, name)
	v, r := s.applySandboxHarnessEvidence(name, version, executable, connector.ResolveHookContract(name, version))
	return v, executable, r
}

// TestApplySandboxHarnessEvidenceKeepsTheHostVerdict: a host agent version,
// when there is one, decides; observe mode never looks at images.
func TestApplySandboxHarnessEvidenceKeepsTheHostVerdict(t *testing.T) {
	cfg := evidenceTestConfig(t)
	s, _ := evidenceSidecar(t, cfg)
	unversioned := connector.ResolveHookContract("claudecode", "")

	// A host agent whose version is outside every contract keeps its verdict.
	writeAgentDiscovery(t, cfg.DataDir, "claudecode", map[string]any{"installed": true, "binary_path": "/usr/local/bin/claude", "version": "0.0.1"})
	hostUnknown := connector.ResolveHookContract("claudecode", "0.0.1")
	if v, r := s.applySandboxHarnessEvidence("claudecode", "0.0.1", "/usr/local/bin/claude", hostUnknown); v != "0.0.1" || r.Status != hostUnknown.Status {
		t.Fatalf("host verdict replaced: version %q status %q", v, r.Status)
	}
	// Observe mode keeps the unversioned verdict, even where discovery found
	// no agent.
	writeAgentDiscovery(t, cfg.DataDir, "claudecode", agentNotFound)
	cfg.Guardrail.Mode = "observe"
	if v, r := s.applySandboxHarnessEvidence("claudecode", "", "", unversioned); v != "" || r.Status != unversioned.Status {
		t.Fatalf("observe mode used sandbox evidence: version %q status %q", v, r.Status)
	}
}

// TestApplySandboxHarnessEvidenceAcceptsTheImageWhenDiscoveryFoundNoAgent is
// the sandbox-only layout: discovery looked and recorded installed:false with
// no binary path, so in action mode the current verified image's harness
// version and contract are used, and no host executable is paired with them.
func TestApplySandboxHarnessEvidenceAcceptsTheImageWhenDiscoveryFoundNoAgent(t *testing.T) {
	cfg := evidenceTestConfig(t)
	s, rec := evidenceSidecar(t, cfg)
	writeAgentDiscovery(t, cfg.DataDir, "claudecode", agentNotFound)
	v, exe, r := applyAsTheCallersDo(s, "claudecode")
	if v != rec.HarnessVersion || exe != "" || r.Status != connector.HookCompatibilityKnown || r.Contract.ContractID != rec.HookContract {
		t.Fatalf("sandbox evidence not applied: version %q executable %q status %q contract %q", v, exe, r.Status, r.Contract.ContractID)
	}
}

// TestApplySandboxHarnessEvidenceNeedsDiscoveryToFindNoAgent: the image stands
// in only for a host where discovery looked and found no binary. An installed
// agent whose version could not be read, or a host with no discovery record,
// keeps the unversioned verdict (which action mode refuses), even with a
// current verified image.
func TestApplySandboxHarnessEvidenceNeedsDiscoveryToFindNoAgent(t *testing.T) {
	cases := []struct {
		name string
		// discovery is the claudecode entry to record; nil writes no cache.
		discovery map[string]any
		// otherEntry records discovery for another agent only.
		otherEntry bool
		// executable overrides the cached executable the caller passes.
		executable string
	}{
		{name: "installed agent with no readable version", discovery: map[string]any{"installed": true, "binary_path": "/usr/local/bin/claude", "version": ""}},
		{name: "no discovery cache"},
		{name: "discovery without the connector's entry", otherEntry: true},
		{name: "entry that does not say installed", discovery: map[string]any{"binary_path": "", "version": ""}},
		{name: "not installed but a binary path is recorded", discovery: map[string]any{"installed": false, "binary_path": "/usr/local/bin/claude", "version": ""}},
		{name: "discovery found nothing but an executable is recorded", discovery: agentNotFound, executable: "/opt/claude/bin/claude"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := evidenceTestConfig(t)
			s, _ := evidenceSidecar(t, cfg)
			switch {
			case c.otherEntry:
				writeAgentDiscovery(t, cfg.DataDir, "codex", agentNotFound)
			case c.discovery != nil:
				writeAgentDiscovery(t, cfg.DataDir, "claudecode", c.discovery)
			}
			version := connector.LoadCachedAgentVersion(cfg.DataDir, "claudecode")
			executable := connector.LoadCachedAgentExecutable(cfg.DataDir, "claudecode")
			if c.executable != "" {
				executable = c.executable
			}
			unversioned := connector.ResolveHookContract("claudecode", version)
			if unversioned.Status == connector.HookCompatibilityKnown {
				t.Fatalf("fixture resolves to a known contract: %+v", unversioned)
			}
			v, r := s.applySandboxHarnessEvidence("claudecode", version, executable, unversioned)
			if v != version || r.Status != unversioned.Status || r.Contract.ContractID != unversioned.Contract.ContractID {
				t.Fatalf("image evidence replaced the host verdict: version %q status %q contract %q (executable %q)",
					v, r.Status, r.Contract.ContractID, executable)
			}
		})
	}
}

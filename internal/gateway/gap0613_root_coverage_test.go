// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

func TestGAP0613SharedUnavailableSkillRootCoversEveryConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, false, false, false)
}

// An explicit gateway.watcher skill dir replaces every connector's own
// folders, so an unavailable one is admission coverage lost for every
// configured connector, not only the primary one.
func TestGAP0613ExplicitSharedSkillRootCoversEveryConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, true, false, false)
}

// A connector named only under enterprise.machine_policy.connectors is
// protected by a standalone managed gateway, so it depends on an explicit
// skill dir exactly like an active connector does.
func TestGAP0613ExplicitSkillRootCoversMachinePolicyOnlyConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, true, true, false)
}

// The same with no active connector at all: the machine policy names the only
// protected connector, and the explicit root is still its only coverage.
func TestGAP0613ExplicitSkillRootCoversMachinePolicyOnlyConnectorWithNoActiveConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, true, true, true)
}

func assertSharedUnavailableSkillRootCoversEveryConnector(t *testing.T, explicit, policyOnly, noActive bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	shared := filepath.Join(home, "shared")
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(shared, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, filepath.Dir(root)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {}, "amp": {},
	}
	if policyOnly {
		cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}}
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
		cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"amp": {}}
	}
	wantNames := []string{"claudecode", "amp"}
	if noActive {
		cfg.Claw.Mode, cfg.Guardrail.Connector, cfg.Guardrail.Connectors = "", "", nil
		if got := cfg.ActiveConnectors(); len(got) != 0 {
			t.Fatalf("active connectors = %v, want none", got)
		}
		wantNames = []string{"amp"}
	}
	cfg.Gateway.Watcher.Enabled = true
	cfg.Gateway.Watcher.Skill.Enabled = true
	if explicit {
		cfg.Gateway.Watcher.Skill.Dirs = []string{root}
	}
	cfg.Gateway.Watcher.Plugin.Enabled = false
	cfg.Watch.RescanEnabled = false
	s := &Sidecar{cfg: cfg, store: store, logger: logger, health: NewSidecarHealth()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runWatcher(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("runWatcher: %v", err)
		}
	}()
	var rootIssue watcher.RootCoverageIssue
	deadline := time.After(5 * time.Second)
	for {
		if current := s.installWatcher.Load(); current != nil {
			for _, issue := range current.RootCoverageIssues() {
				if issue.Kind == "skill" && issue.Path == root {
					rootIssue = issue
					break
				}
			}
		}
		if rootIssue.Path != "" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("shared unavailable skill root was not reported")
		case <-time.After(10 * time.Millisecond):
		}
	}
	coverage := func() []watcher.RootCoverageIssue { return []watcher.RootCoverageIssue{rootIssue} }
	for _, tc := range []struct {
		name, tier string
		managed    bool
		block      bool
	}{
		{"strict", "strict", false, true},
		{"managed", "default", true, true},
		{"default", "default", false, false},
		{"permissive", "permissive", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := config.DefaultConfig()
			policy.AssetPolicy = config.DefaultAssetPolicy()
			policy.Guardrail.RulePack = tc.tier
			if tc.managed {
				policy.DeploymentMode = managed.DeploymentModeManagedEnterprise
				policy.Enterprise.Profile = managed.ProfileStandalone
			}
			api := &APIServer{store: store, logger: logger, scannerCfg: policy, rootCoverage: coverage}
			for _, source := range []struct {
				name, path string
				blocked    bool
			}{
				{"name-only", "", tc.block},
				{"known-path", filepath.Join(root, "ordinary"), tc.block},
				{"outside-path", filepath.Join(home, "outside", "ordinary"), false},
			} {
				probe := nativeSkillToolProbe("amp", "skill", map[string]interface{}{"name": "ordinary"})
				if !probe.Matched {
					t.Fatal("Amp skill selection was not recognized")
				}
				probe.SourcePath = source.path
				decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "amp", probe)
				if blocked != source.blocked || blocked && (decision.Action != "block" || decision.Source != "watch-root-unavailable") {
					t.Errorf("%s: blocked=%v decision=%+v, want blocked=%v", source.name, blocked, decision, source.blocked)
				}
			}
		})
	}
	names, ok := s.health.Snapshot().Watcher.Details["admission_scanning_off"].([]string)
	if !ok {
		t.Fatalf("watcher health affected connectors = %v", names)
	}
	for _, want := range wantNames {
		if !slices.Contains(names, want) {
			t.Errorf("watcher health affected connectors = %v, missing %s", names, want)
		}
	}
	// GAP-0905: the folder other accounts can write reaches health, so doctor
	// and status can name it with the chmod.
	physical, err := filepath.EvalSymlinks(shared)
	if err != nil {
		t.Fatal(err)
	}
	if rootIssue.Ancestor != physical {
		t.Errorf("root issue ancestor = %q, want %q", rootIssue.Ancestor, physical)
	}
	if folders, _ := s.health.Snapshot().Watcher.Details["admission_root_writable_folders"].([]string); !slices.Equal(folders, []string{physical}) {
		t.Errorf("watcher health writable folders = %v, want [%s]", folders, physical)
	}
}

// Every configured connector consumes each explicit skill and plugin dir,
// while the event owner of an explicit dir stays the primary connector.
func TestGAP0613ExplicitRootsListEveryConfiguredConnector(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {}, "amp": {}, "codex": {},
	}
	skillRoot, pluginRoot := filepath.Join(home, "skills"), filepath.Join(home, "plugins")
	wcfg := cfg.Gateway.Watcher
	wcfg.Enabled = true
	wcfg.Skill.Enabled, wcfg.Skill.Dirs = true, []string{skillRoot}
	wcfg.Plugin.Enabled, wcfg.Plugin.Dirs = true, []string{pluginRoot}
	conns := watcherConnectors(connector.NewDefaultRegistry(), cfg)
	if len(conns) != 3 {
		t.Fatalf("configured connectors = %d, want 3", len(conns))
	}
	skillDirs, pluginDirs, roots, src, consumers := resolveWatcherDirsForConnectors(cfg, conns, wcfg)
	if !slices.Equal(skillDirs, []string{skillRoot}) || !slices.Equal(pluginDirs, []string{pluginRoot}) {
		t.Fatalf("explicit dirs = %v %v", skillDirs, pluginDirs)
	}
	if _, tagged := roots[skillRoot]; tagged {
		t.Errorf("explicit skill dir got an event owner: %v", roots)
	}
	if _, tagged := roots[pluginRoot]; tagged {
		t.Errorf("explicit plugin dir got an event owner: %v", roots)
	}
	enrolled := &enrolledWatchSet{consumers: []watcher.RootConsumer{{Kind: "skill", Path: filepath.Join(home, "user", ".claude", "skills"), Connector: "claudecode"}}}
	for name, list := range map[string][]watcher.RootConsumer{
		"per-user": consumers,
		"enrolled": enrolledRootConsumers(enrolled, consumers, src),
	} {
		for _, kind := range []struct{ kind, path string }{{"skill", skillRoot}, {"plugin", pluginRoot}} {
			for _, conn := range []string{"claudecode", "amp", "codex"} {
				if !slices.ContainsFunc(list, func(c watcher.RootConsumer) bool {
					return c.Kind == kind.kind && c.Path == kind.path && c.Connector == conn
				}) {
					t.Errorf("%s: explicit %s dir missing %s consumer: %+v", name, kind.kind, conn, list)
				}
			}
		}
	}
	// A connector only the standalone machine policy names, and an enrolled
	// connector with no folder of its own, also consume each explicit dir.
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"cursor": {}}
	enrolled.connectors = []string{"claudecode", "kiro"}
	_, _, _, src, consumers = resolveWatcherDirsForConnectors(cfg, conns, wcfg)
	for name, list := range map[string][]watcher.RootConsumer{
		"per-user": consumers,
		"enrolled": enrolledRootConsumers(enrolled, consumers, src),
	} {
		want := []string{"cursor"}
		if name == "enrolled" {
			want = append(want, "kiro")
		}
		for _, conn := range want {
			for _, kind := range []struct{ kind, path string }{{"skill", skillRoot}, {"plugin", pluginRoot}} {
				if !slices.Contains(list, watcher.RootConsumer{Kind: kind.kind, Path: kind.path, Connector: conn}) {
					t.Errorf("%s: explicit %s dir missing %s consumer: %+v", name, kind.kind, conn, list)
				}
			}
		}
	}
	if got := enrolledRootConsumers(enrolled, consumers, src); !slices.Contains(got, enrolled.consumers[0]) {
		t.Errorf("enrolled consumers lost the enrolled user root: %+v", got)
	}
	// Without explicit dirs a managed watcher does not watch the gateway's
	// own connector folders, so they add no consumers there.
	wcfg.Skill.Dirs, wcfg.Plugin.Dirs = nil, nil
	_, _, _, src, consumers = resolveWatcherDirsForConnectors(cfg, conns, wcfg)
	if got := enrolledRootConsumers(enrolled, consumers, src); !slices.Equal(got, enrolled.consumers) {
		t.Errorf("enrolled consumers with connector-discovered dirs = %+v, want %+v", got, enrolled.consumers)
	}
}

func TestGAP0613UnavailableRootDegradesWatcherHealthUntilRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	cfg.Gateway.Watcher.Skill.Enabled = true
	cfg.Gateway.Watcher.Plugin.Enabled = false
	cfg.Watch.DebounceMs = 50
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude-dir")
	root := filepath.Join(home, ".claude", "skills")
	if err := os.MkdirAll(filepath.Join(target, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Dir(root)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg.Gateway.Watcher.Skill.Dirs = []string{root}
	store, err := audit.NewStore(filepath.Join(cfg.DataDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := &Sidecar{cfg: cfg, store: store, logger: audit.NewLogger(store), health: NewSidecarHealth()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.runWatcher(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("runWatcher: %v", err)
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		watcher := s.health.Snapshot().Watcher
		if watcher.State == StateDegraded && watcher.Details["watch_roots_unavailable"] == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("unavailable watcher health = %+v", watcher)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(5 * time.Second)
	for {
		watcher := s.health.Snapshot().Watcher
		if watcher.State == StateRunning && watcher.Details["watch_roots_unavailable"] == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("recovered watcher health = %+v", watcher)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestGAP0613UnavailableRootRuntimePolicyMatrix(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	issue := watcher.RootCoverageIssue{Kind: "skill", Path: root, Connector: "claudecode"}
	for _, tc := range []struct {
		name, tier, profile, sourcePath string
		managed, wantBlock              bool
	}{
		{"balanced", "default", "", filepath.Join(root, "ordinary"), false, false},
		{"permissive", "permissive", "", filepath.Join(root, "ordinary"), false, false},
		{"strict", "strict", "", filepath.Join(root, "ordinary"), false, true},
		{"strict-other-root", "strict", "", filepath.Join(t.TempDir(), "ordinary"), false, false},
		{"managed", "default", managed.ProfileStandalone, filepath.Join(root, "ordinary"), true, true},
		{"secure-client", "strict", managed.ProfileSecureClient, filepath.Join(root, "ordinary"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AssetPolicy = config.DefaultAssetPolicy()
			cfg.Guardrail.RulePack = tc.tier
			if tc.managed {
				cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				cfg.Enterprise.Profile = tc.profile
			}
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
				rootCoverage: func() []watcher.RootCoverageIssue { return []watcher.RootCoverageIssue{issue} }}
			decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
				Matched: true, SkillName: "ordinary", SourcePath: tc.sourcePath,
			})
			if blocked != tc.wantBlock || (blocked && (decision.Action != "block" || decision.Source != "watch-root-unavailable")) {
				t.Fatalf("blocked=%v decision=%+v, want blocked=%v", blocked, decision, tc.wantBlock)
			}
		})
	}
}

func TestGAP0613StrictUnavailableRootRequiresProvenOutsidePath(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	for _, tc := range []struct {
		name, tier, source string
		blocked            bool
	}{
		{"strict-root-itself", "strict", root, true},
		{"strict-clean-inside", "strict", filepath.Join(root, "ordinary"), true},
		{"strict-parent-inside", "strict", root + string(filepath.Separator) + ".." + string(filepath.Separator) + "skills" + string(filepath.Separator) + "ordinary", true},
		{"strict-relative-unknown", "strict", filepath.Join("skills", "ordinary"), true},
		{"strict-proven-outside", "strict", filepath.Join(t.TempDir(), "ordinary"), false},
		{"balanced-relative", "default", filepath.Join("skills", "ordinary"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AssetPolicy = config.DefaultAssetPolicy()
			cfg.Guardrail.RulePack = tc.tier
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
				rootCoverage: func() []watcher.RootCoverageIssue {
					return []watcher.RootCoverageIssue{{Kind: "skill", Path: root, Connector: "claudecode"}}
				}}
			decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
				Matched: true, SkillName: "ordinary", SourcePath: tc.source,
			})
			if blocked != tc.blocked || blocked && decision.Action != "block" {
				t.Fatalf("source=%q blocked=%v decision=%+v, want blocked=%v", tc.source, blocked, decision, tc.blocked)
			}
		})
	}
}

func TestGAP0613UnavailableRootAliasesStayCovered(t *testing.T) {
	home := t.TempDir()
	physicalRoot := filepath.Join(home, "shared", "skills")
	linkedRoot := filepath.Join(home, ".claude", "skills")
	linkedParent := filepath.Join(home, "linked-agent")
	linkedParentRoot := filepath.Join(linkedParent, "skills")
	rootAlias := filepath.Join(home, "other", "skills")
	parentAlias := filepath.Join(home, "shared-alias")
	for _, dir := range []string{
		filepath.Join(physicalRoot, "ordinary"), filepath.Dir(linkedRoot), filepath.Dir(rootAlias),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(physicalRoot), 0o777); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{
		{linkedRoot, physicalRoot},
		{linkedParent, filepath.Dir(physicalRoot)},
		{rootAlias, physicalRoot},
		{parentAlias, filepath.Dir(physicalRoot)},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := skillrootsafe.Resolve(linkedRoot, nil); err == nil {
			t.Fatal("unavailable linked root was accepted")
		}
	}
	missingAlias := filepath.Join(home, "missing-alias")
	if err := os.Symlink(filepath.Join(physicalRoot, "pending"), missingAlias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	store, logger := newNativeSkillRuntimeTestStore(t)
	for _, root := range []string{linkedRoot, linkedParentRoot} {
		t.Run(filepath.Base(filepath.Dir(root)), func(t *testing.T) {
			for _, tier := range []string{"strict", "managed", "default", "permissive"} {
				t.Run(tier, func(t *testing.T) {
					cfg := config.DefaultConfig()
					cfg.AssetPolicy = config.DefaultAssetPolicy()
					cfg.Guardrail.RulePack = tier
					if tier == "managed" {
						cfg.Guardrail.RulePack = "default"
						cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
						cfg.Enterprise.Profile = managed.ProfileStandalone
					}
					api := &APIServer{store: store, logger: logger, scannerCfg: cfg,
						rootCoverage: func() []watcher.RootCoverageIssue {
							return []watcher.RootCoverageIssue{{Kind: "skill", Path: root, Connector: "claudecode"}}
						}}
					for _, source := range []struct {
						name, path string
						underRoot  bool
					}{
						{"physical", filepath.Join(physicalRoot, "ordinary"), true},
						{"root-alias", filepath.Join(rootAlias, "ordinary"), true},
						{"parent-alias", filepath.Join(parentAlias, "skills", "ordinary"), true},
						{"unresolved-alias", filepath.Join(missingAlias, "ordinary"), true},
						{"outside", filepath.Join(home, "outside", "ordinary"), false},
					} {
						t.Run(source.name, func(t *testing.T) {
							name, path, _ := assetfacts.SkillSelection(map[string]interface{}{"skill_name": "ordinary", "skill_path": source.path})
							if name != "ordinary" || path != source.path {
								t.Fatalf("hook source changed: %q %q", name, path)
							}
							decision, blocked := api.runtimeSkillAssetPolicyDecision(context.Background(), "claudecode", skillRuntimeProbe{
								Matched: true, SkillName: name, SourcePath: path,
							})
							wantBlock := (tier == "strict" || tier == "managed") && source.underRoot
							if blocked != wantBlock || wantBlock && (decision.Action != "block" || decision.Source != "watch-root-unavailable") {
								t.Fatalf("source=%q blocked=%v decision=%+v, want blocked=%v", path, blocked, decision, wantBlock)
							}
						})
					}
				})
			}
		})
	}
}

// With no active connector, the connectors only the standalone machine policy
// names are still consumers and the event owner of each explicit folder
// (round 6): the resolver used to return before reaching them.
func TestGAP0613ExplicitRootsCoverMachinePolicyConnectorsWithNoActiveConnector(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	skillRoot, pluginRoot := filepath.Join(home, "skills"), filepath.Join(home, "plugins")
	newCfg := func(managedProfile bool) *config.Config {
		cfg := config.DefaultConfig()
		cfg.DataDir = t.TempDir()
		cfg.Claw.Mode, cfg.Guardrail.Connector, cfg.Guardrail.Connectors = "", "", nil
		if managedProfile {
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"codex": {}, "amp": {}}
		}
		return cfg
	}
	wcfgFor := func(cfg *config.Config, explicit bool) config.GatewayWatcherConfig {
		wcfg := cfg.Gateway.Watcher
		wcfg.Enabled = true
		wcfg.Skill.Enabled, wcfg.Plugin.Enabled = true, true
		if explicit {
			wcfg.Skill.Dirs, wcfg.Plugin.Dirs = []string{skillRoot}, []string{pluginRoot}
		}
		return wcfg
	}
	cfg := newCfg(true)
	if got := cfg.ActiveConnectors(); len(got) != 0 {
		t.Fatalf("active connectors = %v, want none", got)
	}
	conns := watcherConnectors(connector.NewDefaultRegistry(), cfg)
	if len(conns) != 0 {
		t.Fatalf("resolved connectors = %d, want 0", len(conns))
	}
	wcfg := wcfgFor(cfg, true)
	skillDirs, pluginDirs, roots, src, consumers := resolveWatcherDirsForConnectors(cfg, conns, wcfg)
	if !slices.Equal(skillDirs, []string{skillRoot}) || !slices.Equal(pluginDirs, []string{pluginRoot}) {
		t.Fatalf("explicit dirs = %v %v", skillDirs, pluginDirs)
	}
	enrolled := &enrolledWatchSet{}
	for name, list := range map[string][]watcher.RootConsumer{
		"per-user": consumers,
		"enrolled": enrolledRootConsumers(enrolled, consumers, src),
	} {
		for _, conn := range []string{"amp", "codex"} {
			for _, kind := range []struct{ kind, path string }{{"skill", skillRoot}, {"plugin", pluginRoot}} {
				if !slices.Contains(list, watcher.RootConsumer{Kind: kind.kind, Path: kind.path, Connector: conn}) {
					t.Errorf("%s: explicit %s dir missing %s consumer: %+v", name, kind.kind, conn, list)
				}
			}
		}
	}
	// One owner for the events of each explicit folder: the first of the
	// sorted protected connectors, so its connector-scoped rules apply.
	if roots[skillRoot] != "amp" || roots[pluginRoot] != "amp" {
		t.Errorf("explicit dirs event owner = %v, want amp", roots)
	}
	// Benign twins: a gateway outside the standalone profile protects no
	// connector it does not run, and folders discovered rather than named
	// have no connector to cover.
	for name, tc := range map[string]struct {
		cfg      *config.Config
		explicit bool
	}{
		"not-standalone": {newCfg(false), true},
		"no-explicit":    {newCfg(true), false},
	} {
		_, _, roots, _, consumers := resolveWatcherDirsForConnectors(tc.cfg, nil, wcfgFor(tc.cfg, tc.explicit))
		if len(consumers) != 0 || len(roots) != 0 {
			t.Errorf("%s: consumers=%+v roots=%v, want none", name, consumers, roots)
		}
	}
}

// A trusted explicit root whose only connector is named by machine policy:
// the connector-scoped asset rule decides its admission (round 6). The twin
// has an active connector the rule is not scoped to, and stays admitted.
// Every consumer of a shared root applies its own rules (round 8): the rule
// of the second machine-policy connector, or of one that is also active and
// loads the root, rejects the skill; a rule scoped to a connector that does
// not load the root does not.
func TestGAP0613TrustedExplicitRootAppliesMachinePolicyConnectorAssetRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, tc := range []struct {
		name, active string
		machine      []string
		rule         string
		rejected     bool
	}{
		{"machine-policy-only-connector", "", []string{"amp"}, "amp", true},
		{"second-machine-policy-connector", "", []string{"amp", "codex"}, "codex", true},
		{"machine-policy-connector-beside-active-connector", "claudecode", []string{"amp"}, "amp", true},
		{"rule-for-connector-that-does-not-load-the-root", "claudecode", []string{"amp"}, "cursor", false},
		{"rule-for-connector-outside-machine-policy", "", []string{"amp", "codex"}, "cursor", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testenv.SetHome(t, home)
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			root := filepath.Join(t.TempDir(), "skills")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			cfg := config.DefaultConfig()
			cfg.DataDir = t.TempDir()
			cfg.Claw.Mode, cfg.Guardrail.Connector, cfg.Guardrail.Connectors = "", tc.active, nil
			if tc.active != "" {
				cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{tc.active: {}}
			}
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{}
			for _, name := range tc.machine {
				cfg.Enterprise.MachinePolicy.Connectors[name] = config.EnterpriseConnectorPolicy{}
			}
			cfg.AssetPolicy = config.DefaultAssetPolicy()
			cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "blocked-skill", Connector: tc.rule, Reason: "protected"}}
			if got := cfg.EvaluateAssetPolicy(config.AssetPolicyInput{TargetType: "skill", Name: "blocked-skill", Connector: tc.rule, RuntimeSurface: "watcher"}); got.Action != "block" {
				t.Fatalf("%s deny rule decision = %+v", tc.rule, got)
			}
			cfg.Gateway.Watcher.Enabled = true
			cfg.Gateway.Watcher.Skill.Enabled = true
			cfg.Gateway.Watcher.Skill.TakeAction = true
			cfg.Gateway.Watcher.Skill.Dirs = []string{root}
			cfg.Gateway.Watcher.Plugin.Enabled = false
			cfg.Watch.DebounceMs = 50
			store, logger := newNativeSkillRuntimeTestStore(t)
			s := &Sidecar{cfg: cfg, store: store, logger: logger, health: NewSidecarHealth()}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.runWatcher(ctx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("runWatcher: %v", err)
				}
			}()
			deadline := time.After(10 * time.Second)
			for s.health.Snapshot().Watcher.State != StateRunning {
				select {
				case <-deadline:
					t.Fatalf("watcher health = %+v", s.health.Snapshot().Watcher)
				case <-time.After(10 * time.Millisecond):
				}
			}
			stage := filepath.Join(t.TempDir(), "blocked-skill")
			if err := os.MkdirAll(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stage, "SKILL.md"), []byte("---\nname: blocked-skill\n---\n# test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "blocked-skill")
			rejected := func() bool {
				events, err := store.ListEvents(200)
				if err != nil {
					t.Fatal(err)
				}
				for _, event := range events {
					if event.Action == string(audit.ActionInstallRejected) && strings.Contains(event.Target, "blocked-skill") {
						return true
					}
				}
				return false
			}
			// Let the watch register, then move the skill in whole.
			time.Sleep(500 * time.Millisecond)
			if err := os.Rename(stage, target); err != nil {
				t.Fatal(err)
			}
			wait := 3 * time.Second
			if tc.rejected {
				wait = 15 * time.Second
			}
			end := time.After(wait)
			for !rejected() {
				select {
				case <-end:
					if tc.rejected {
						t.Fatalf("%s-scoped denied skill was not rejected in a root that connector loads", tc.rule)
					}
					return
				case <-time.After(50 * time.Millisecond):
				}
			}
			if !tc.rejected {
				t.Fatal("skill was rejected by a rule scoped to a connector that does not own the root")
			}
		})
	}
}

// The standalone managed Windows watcher tags enrolled users folders as event
// owners; the explicit folders owner from the shared-root resolution must
// join that map rather than be dropped (round 8). An enrolled folder keeps its
// owner, and a config with active connectors (which tags no explicit folder)
// adds nothing.
func TestGAP0613EnrolledWatcherKeepsExplicitRootOwner(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	explicit := filepath.Join(home, "shared", "skills")
	enrolledRoot := filepath.Join(home, "user", ".claude", "skills")
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Claw.Mode, cfg.Guardrail.Connector, cfg.Guardrail.Connectors = "", "", nil
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{"amp": {}, "codex": {}}
	wcfg := cfg.Gateway.Watcher
	wcfg.Enabled = true
	wcfg.Skill.Enabled, wcfg.Skill.Dirs = true, []string{explicit}
	wcfg.Plugin.Enabled = false
	_, _, roots, src, consumers := resolveWatcherDirsForConnectors(cfg, nil, wcfg)
	enrolled := &enrolledWatchSet{
		roots:      map[string]string{enrolledRoot: "claudecode"},
		consumers:  []watcher.RootConsumer{{Kind: "skill", Path: enrolledRoot, Connector: "claudecode"}},
		connectors: []string{"claudecode"},
	}
	owners := enrolledRootOwners(enrolled, roots, consumers, src)
	if owners[explicit] != "amp" || owners[enrolledRoot] != "claudecode" || len(owners) != 2 {
		t.Fatalf("owners = %v, want the explicit folder owned by amp beside the enrolled one", owners)
	}
	if len(enrolled.roots) != 1 {
		t.Errorf("enrolled owner map was modified: %v", enrolled.roots)
	}
	// Every machine-policy connector and the enrolled one consume the folder.
	list := enrolledRootConsumers(enrolled, consumers, src)
	for _, name := range []string{"amp", "codex", "claudecode"} {
		if !slices.Contains(list, watcher.RootConsumer{Kind: "skill", Path: explicit, Connector: name}) {
			t.Errorf("explicit folder missing %s consumer: %+v", name, list)
		}
	}
	// An enrolled folder that is also the explicit folder keeps its owner.
	enrolled.roots[explicit] = "claudecode"
	if owners := enrolledRootOwners(enrolled, roots, consumers, src); owners[explicit] != "claudecode" {
		t.Errorf("enrolled owner replaced: %v", owners)
	}
	// Without an explicit owner (an active connector) nothing is added.
	delete(enrolled.roots, explicit)
	if owners := enrolledRootOwners(enrolled, map[string]string{}, consumers, src); len(owners) != 1 {
		t.Errorf("owners without explicit owner = %v", owners)
	}
	if owners := enrolledRootOwners(&enrolledWatchSet{}, map[string]string{}, nil, src); len(owners) != 0 {
		t.Errorf("empty enrolled set owners = %v", owners)
	}
}

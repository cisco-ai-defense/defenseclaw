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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

func TestGAP0613SharedUnavailableSkillRootCoversEveryConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, false)
}

// An explicit gateway.watcher skill dir replaces every connector's own
// folders, so an unavailable one is admission coverage lost for every
// configured connector, not only the primary one.
func TestGAP0613ExplicitSharedSkillRootCoversEveryConnector(t *testing.T) {
	assertSharedUnavailableSkillRootCoversEveryConnector(t, true)
}

func assertSharedUnavailableSkillRootCoversEveryConnector(t *testing.T, explicit bool) {
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
	if names, ok := s.health.Snapshot().Watcher.Details["admission_scanning_off"].([]string); !ok || !slices.Contains(names, "claudecode") || !slices.Contains(names, "amp") {
		t.Errorf("watcher health affected connectors = %v", names)
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
							name, path, _ := skillFromMap(map[string]interface{}{"skill_name": "ordinary", "skill_path": source.path})
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

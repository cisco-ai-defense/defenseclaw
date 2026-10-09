//go:build windows

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0491: a running guardian uses the protected config's latest watcher
// settings after a config-only ensure, and refuses removals if reload fails.
func TestEnterpriseHookQuarantineReloadsWatcherConfig(t *testing.T) {
	previous := enterpriseHooksWindowsConfigLoader
	t.Cleanup(func() { enterpriseHooksWindowsConfigLoader = previous })
	startup := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: "C:\\data"}
	startup.Enterprise.Profile = managed.ProfileStandalone
	latest := *startup
	latest.Gateway.Watcher.Skill.Enabled = true
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return &latest, nil }
	got, err := enterpriseHookQuarantineCurrentConfig(startup)
	if err != nil || !got.Gateway.Watcher.Skill.Enabled {
		t.Fatalf("guardian kept stale watcher config: %+v, %v", got, err)
	}
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return nil, errors.New("reload failed") }
	if _, err := enterpriseHookQuarantineCurrentConfig(startup); err == nil {
		t.Fatal("guardian accepted a removal without a current protected config")
	}
}

// A deferred removal uses the hot config's quarantine directory when the
// user signs in, not the guardian's startup directory.
func TestEnterpriseHookQuarantineDeferredRetryUsesCurrentConfig(t *testing.T) {
	previous := enterpriseHooksWindowsConfigLoader
	t.Cleanup(func() { enterpriseHooksWindowsConfigLoader = previous })
	startup := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: `C:\data`, QuarantineDir: `C:\old-quarantine`}
	startup.Enterprise.Profile = managed.ProfileStandalone
	latest := *startup
	latest.QuarantineDir = `C:\new-quarantine`
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return &latest, nil }
	request := enforce.QuarantineRemovalRequest{ID: "deferred"}
	called := false
	err := retryEnterpriseHookQuarantineRemoval(startup, request, func(got *config.Config, passed enforce.QuarantineRemovalRequest) error {
		called = true
		if got.QuarantineDir != latest.QuarantineDir || passed.ID != request.ID {
			t.Fatalf("deferred retry got config %q, request %+v", got.QuarantineDir, passed)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("deferred retry = %v, called = %v", err, called)
	}
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return nil, errors.New("protected config unavailable") }
	called = false
	if err := retryEnterpriseHookQuarantineRemoval(startup, request, func(*config.Config, enforce.QuarantineRemovalRequest) error {
		called = true
		return nil
	}); err == nil || called {
		t.Fatalf("retry after failed reload = %v, called = %v", err, called)
	}
}

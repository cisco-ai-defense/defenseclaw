//go:build windows

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

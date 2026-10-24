// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The answer to a per-user command on a managed Linux or macOS host names
// the administrator's form of the command only where that form reads the
// managed deployment, and never to an administrator, who just ran it
// (GAP-1037: root's `connector verify` was told to run `sudo ...
// connector verify`). Every answer names managed status and verify.
func TestManagedUnixConfigLoadErrorNamesOnlyAWorkingAdminCommand(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	restore, restoreWindows, restoreTrust := managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted
	restoreDeployment, restoreUID := managedStandaloneAdminDeployment, managedHostCallerUID
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	managedHostRecordTrusted = func(string) error { return nil }
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, &managed.RuntimeDescriptor{ServiceUID: 990}, nil
	}
	defer func() {
		managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted = restore, restoreWindows, restoreTrust
		managedStandaloneAdminDeployment, managedHostCallerUID = restoreDeployment, restoreUID
	}()
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.ConfigPathEnv, "")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := fmt.Errorf("read v8 config /root/.defenseclaw/config.yaml: %w", fs.ErrNotExist)
	gateway := managedHostGatewayCommand()
	for _, tc := range []struct {
		name    string
		uid     int
		path    []string
		asAdmin bool
	}{
		{name: "root's connector verify", uid: 0, path: []string{"connector", "verify"}},
		{name: "a standard user's connector verify", uid: 1000, path: []string{"connector", "verify"}},
		{name: "the service account's connector verify", uid: 990, path: []string{"connector", "verify"}},
		{name: "a standard user's audit export (GAP-1196)", uid: 1000, path: []string{"audit", "export"}, asAdmin: true},
		{name: "root's audit export", uid: 0, path: []string{"audit", "export"}},
		{name: "a standard user's doctor", uid: 1000, path: []string{"doctor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedHostCallerUID = func() int { return tc.uid }
			parent := &cobra.Command{Use: "defenseclaw-gateway"}
			cmd := parent
			for _, use := range tc.path {
				child := &cobra.Command{Use: use}
				cmd.AddCommand(child)
				cmd = child
			}
			command := strings.Join(tc.path, " ")
			err := managedWindowsConfigLoadError(cmd, missing)
			if err == missing {
				t.Fatal("the managed answer was not given")
			}
			message := err.Error()
			if got := strings.Contains(message, "sudo "+gateway+" "+command+"`"); got != tc.asAdmin {
				t.Fatalf("names `sudo ... %s` = %v, want %v: %s", command, got, tc.asAdmin, message)
			}
			for _, want := range []string{"`" + command + "` has no per-user gateway", "enterprise " + managedHostPlatform() + " status`", "enterprise " + managedHostPlatform() + " verify`"} {
				if !strings.Contains(message, want) {
					t.Fatalf("answer lacks %q: %s", want, message)
				}
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHostDescriptorPath is where a standalone managed deployment
// publishes its runtime descriptor on this OS ("" where the check does not
// apply). A seam for tests.
var managedHostDescriptorPath = func() string {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return ""
	}
	return layout.DescriptorPath
}

// refusePerUserGatewayOnManagedHost keeps a per-user gateway from running
// on a host whose DefenseClaw is managed by the organization. A per-user
// gateway would compete with the managed services for the loopback port and
// the agents' hooks. The managed services themselves carry the
// managed_enterprise deployment pin and pass.
func refusePerUserGatewayOnManagedHost() error {
	if err := refusePerUserGatewayBesideEnterprise(); err != nil {
		return err
	}
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return nil
	}
	if where, present := managedHostWindowsStandalone(); present {
		return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so the per-user gateway is disabled; "+
			"an administrator can check the managed deployment with `defenseclaw-gateway enterprise windows status --profile standalone`", where)
	}
	path, present := managedHostUnixRecord(os.Stderr)
	if !present {
		return nil
	}
	return managedHostUnixRefusal(path)
}

// managedHostUnixRecord returns the unix standalone runtime descriptor when
// this host has one an administrator wrote. An untrusted record is reported
// to warn (when non-nil) and ignored.
// addManagedWindowsSetupAnswer gives a Windows standalone managed computer an
// answer to the per-user `defenseclaw setup ...` commands. Its payload ships
// this binary as defenseclaw.exe and no per-user CLI, so `defenseclaw setup
// rotate-token` printed `unknown command "setup" ... Did you mean this? stop`.
// Other hosts, Secure Client included, get no such command.
func addManagedWindowsSetupAnswer(root *cobra.Command) {
	where, present := managedHostWindowsStandalone()
	if !present {
		return
	}
	for _, command := range root.Commands() {
		if command.Name() == "setup" {
			return
		}
	}
	root.AddCommand(&cobra.Command{
		Use:                "setup",
		Hidden:             true,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so per-user setup "+
				"commands are not available; your administrator manages its connectors and credentials. "+
				"Rotating the credentials of a managed Windows deployment is not available yet. Nothing was changed", where)
		},
	})
}

func managedHostUnixRecord(warn io.Writer) (string, bool) {
	path := managedHostDescriptorPath()
	if path == "" {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	if err := managedHostRecordTrusted(path); err != nil {
		if warn != nil {
			fmt.Fprintf(warn, "[defenseclaw] ignoring an untrusted managed runtime descriptor: %v\n", err)
		}
		return "", false
	}
	return path, true
}

// refuseGatewayLifecycleOnManagedHost guards the per-user gateway lifecycle:
// the bare daemon, start, stop and restart. It refuses exactly when
// refusePerUserGatewayOnManagedHost does, and on a unix standalone host it
// also refuses a caller that set the managed_enterprise pin by hand. The
// managed gateway service runs as the service account, so the pin counts
// only for that account; anyone else would otherwise get past the refusal
// and fail later on an internal data-dir trust error. When the service
// account cannot be determined the pin is honored, so a managed service
// never fails to start because of this check.
func refuseGatewayLifecycleOnManagedHost() error {
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" || !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return nil
	}
	path, present := managedHostUnixRecord(nil)
	if !present {
		return nil
	}
	serviceUID, known := managedHostServiceUID(path)
	if !known || managedHostCallerUID() == serviceUID {
		return nil
	}
	return managedHostUnixRefusal(path)
}

// managedHostServiceUID returns the uid of the standalone gateway service
// account: the descriptor's service_uid, or the layout's service account
// when the descriptor does not parse. A seam for tests.
var managedHostServiceUID = func(descriptorPath string) (int, bool) {
	if data, err := readManagedHostDescriptor(descriptorPath); err == nil {
		if descriptor, err := managed.ParseRuntimeDescriptor(data); err == nil && descriptor.ServiceUID >= 0 {
			return descriptor.ServiceUID, true
		}
	}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return 0, false
	}
	account, err := user.Lookup(layout.ServiceUser)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid < 0 {
		return 0, false
	}
	return uid, true
}

// readManagedHostDescriptor reads the small public runtime descriptor.
func readManagedHostDescriptor(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, managedHostDescriptorReadLimit))
}

// managedHostDescriptorReadLimit bounds the descriptor read; the parser
// rejects anything above its own 64 KiB limit.
const managedHostDescriptorReadLimit = 64<<10 + 1

// managedHostCallerUID is this process's effective uid (-1 on Windows). A
// seam for tests.
var managedHostCallerUID = os.Geteuid

// managedHostUnixRefusal is the unix standalone refusal. A standard user is
// told who can check the deployment; an administrator is told how to
// restart, repair and check the managed gateway, which runs as a system
// service rather than through the per-user start/stop/restart commands.
func managedHostUnixRefusal(record string) error {
	gateway, platform := managedHostGatewayCommand(), managedHostPlatform()
	if managedHostCallerUID() == 0 {
		return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so the per-user gateway is disabled; "+
			"the managed gateway runs as a system service: restart it with `%s` or repair the deployment with `%s enterprise %s repair`, "+
			"and check it with `%s enterprise %s status`",
			record, managedHostServiceRestartCommand(), gateway, platform, gateway, platform)
	}
	return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so the per-user gateway is disabled; "+
		"an administrator can check the managed deployment with `sudo %s enterprise %s status`", record, gateway, platform)
}

// managedHostServiceRestartCommand restarts the standalone gateway service:
// the systemd unit on Linux, the launchd daemon on macOS.
func managedHostServiceRestartCommand() string {
	if runtime.GOOS == "darwin" {
		return "launchctl kickstart -k system/" + managedHostDarwinGatewayLabel
	}
	return "systemctl restart " + managedHostLinuxGatewayUnit
}

// The standalone gateway service names (internal/enterpriseunix installs
// them; packaging/systemd/defenseclaw-gateway.service is the unit).
const (
	managedHostLinuxGatewayUnit   = "defenseclaw-gateway.service"
	managedHostDarwinGatewayLabel = "com.cisco.defenseclaw.gateway"
)

// managedHostPlatform names this OS the way the `enterprise` command group
// does ("linux" or "macos").
func managedHostPlatform() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return "linux"
}

// managedHostGatewayCommand is the absolute path of the installed standalone
// gateway. The package puts no DefenseClaw command on PATH, and sudo's
// secure_path does not include the install directory, so a bare
// `defenseclaw-gateway` in a hint fails with "command not found".
func managedHostGatewayCommand() string {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return "defenseclaw-gateway"
	}
	return layout.BinDir + "/defenseclaw-gateway"
}

// managedRecordTrusted reports whether a managed-deployment record at path
// can only have been written by an administrator. validateFile checks the
// record and its ancestors; validateDir checks a directory that admits no
// writer other than an administrator and whose ancestors cannot be replaced.
//
// A standard user cannot inspect an administrator-only record, or the
// administrator-only directory holding it. For that caller the nearest
// ancestor strictly below stop that it can inspect decides: when that
// directory admits only administrator writers, everything below it was
// created by an administrator. Any other trust failure (a user-owned file,
// a user-writable directory, a reparse point) or reaching stop without such a
// directory means the record could have been planted, so it is untrusted.
func managedRecordTrusted(path, stop string, validateFile, validateDir func(string) error) error {
	err := validateFile(path)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	stop = filepath.Clean(stop)
	for dir := filepath.Dir(filepath.Clean(path)); pathStrictlyWithin(dir, stop); dir = filepath.Dir(dir) {
		dirErr := validateDir(dir)
		if dirErr == nil {
			return nil
		}
		if !errors.Is(dirErr, fs.ErrPermission) {
			return dirErr
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return fmt.Errorf("%s cannot be inspected and no administrator-only directory below %s holds it: %w", path, stop, err)
}

// managedStandaloneRecordCounts decides whether a recorded Windows
// standalone deployment disables the per-user gateway, and names what proves
// it. The record counts when recordTrusted shows that an administrator wrote
// it. A standard user usually cannot show that. It cannot read the security
// settings of the administrator-only product directory under %ProgramData%.
// The vendor directory above that one often keeps the ProgramData
// create-child grant for Users, so the ancestor walk ends at a directory a
// user could have written. For that caller the gateway service decides
// instead. Only an administrator can register a service, so a gateway service
// that runs the standalone gateway executable proves the deployment is real.
// standaloneService describes that service or says why there is none. A
// planted record on a host without the service still counts for nothing.
func managedStandaloneRecordCounts(record string, recordTrusted func(string) error, standaloneService func() (string, error)) (string, error) {
	recordErr := recordTrusted(record)
	if recordErr == nil {
		return record, nil
	}
	service, serviceErr := standaloneService()
	if serviceErr == nil {
		return service, nil
	}
	return "", fmt.Errorf("%w; no administrator-registered standalone gateway service confirms it: %v", recordErr, serviceErr)
}

// standaloneGatewayServiceImageMatches checks that a service's registered
// image path launches exactly gatewayPath. The lifecycle registers the
// standalone gateway as its quoted executable path. The Secure Client profile
// uses the same service name with its own executable, so the path is what
// tells the two apart.
func standaloneGatewayServiceImageMatches(imagePath, gatewayPath string) error {
	executable := serviceImageExecutable(imagePath)
	if executable == "" || gatewayPath == "" || !strings.EqualFold(executable, gatewayPath) {
		return fmt.Errorf("service image %q does not run %s", imagePath, gatewayPath)
	}
	return nil
}

// serviceImageExecutable returns the executable of a service image path: the
// quoted first token, or the text before the first blank when it is unquoted.
func serviceImageExecutable(imagePath string) string {
	image := strings.TrimSpace(imagePath)
	if strings.HasPrefix(image, `"`) {
		end := strings.IndexByte(image[1:], '"')
		if end < 0 {
			return ""
		}
		return image[1 : 1+end]
	}
	if index := strings.IndexAny(image, " \t"); index >= 0 {
		return image[:index]
	}
	return image
}

// pathStrictlyWithin reports whether dir lies below root (not root itself).
func pathStrictlyWithin(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// managedStandaloneAdminDeployment returns this OS's unix standalone layout
// and the host's runtime descriptor after the same administrator-ownership
// checks the managed config gets. A host without a standalone deployment
// returns managed.ErrNoRuntimeDescriptor. A seam for tests.
var managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return managed.StandaloneLayout{}, nil, managed.ErrNoRuntimeDescriptor
	}
	descriptor, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath)
	if err != nil {
		return layout, nil, err
	}
	return layout, descriptor, nil
}

// managedStandaloneAdminCaller reports whether this host runs a trusted
// unix standalone deployment and the caller administers it: uid 0 or the
// gateway service account the descriptor names. A descriptor that fails
// its trust checks is reported to an administrator on warn and ignored.
func managedStandaloneAdminCaller(warn io.Writer) (managed.StandaloneLayout, bool) {
	layout, descriptor, err := managedStandaloneAdminDeployment()
	uid := managedHostCallerUID()
	if err != nil {
		if warn != nil && uid == 0 && !errors.Is(err, managed.ErrNoRuntimeDescriptor) {
			fmt.Fprintf(warn, "[defenseclaw] ignoring the managed runtime descriptor: %v\n", err)
		}
		return layout, false
	}
	if uid == 0 || (descriptor.ServiceUID >= 0 && uid == descriptor.ServiceUID) {
		return layout, true
	}
	return layout, false
}

// applyManagedStandaloneAdminEnv points an administrator's read-only admin
// commands (status, audit, enterprise hooks) at the standalone deployment
// when the caller named no config and no data dir. It sets the same pins
// the managed services run with: the managed config and data dir, the
// deployment mode and profile, and the hook guardian authorization
// directory. Without it root reads its own ~/.defenseclaw/config.yaml and
// the Linux default manifest, which a standalone host never has. Values
// the caller already set are kept.
func applyManagedStandaloneAdminEnv(warn io.Writer) bool {
	if strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" || strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME")) != "" {
		return false
	}
	layout, admin := managedStandaloneAdminCaller(warn)
	if !admin {
		return false
	}
	for _, pin := range []struct{ key, value string }{
		{managed.ConfigPathEnv, layout.ConfigPath},
		{"DEFENSECLAW_HOME", layout.DataDir},
		{managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise},
		{managed.EnterpriseProfileEnv, managed.ProfileStandalone},
		{managed.HookGuardianAuthorizationDirEnv, layout.GuardianAuthDir},
	} {
		if strings.TrimSpace(os.Getenv(pin.key)) == "" {
			if err := os.Setenv(pin.key, pin.value); err != nil {
				return false
			}
		}
	}
	return true
}

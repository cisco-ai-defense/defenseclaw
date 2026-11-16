// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// bundleFloorRefusedExit is the exit code of floor-check when the package
// version is below the confirmed bundle's release floor (or the floor cannot
// be read). The package scripts refuse on any other non-zero code too
// (floorCheckMarker).
const bundleFloorRefusedExit = 3

// floorCheckMarker is in every gateway binary that has floor-check (an
// annotation of the command keeps it there). The package scripts look for it
// in the installed gateway without running it: a gateway that carries it must
// pass the check (exit 0), so one that cannot run (application control,
// killed, crashed) refuses the install, while a gateway before 1.0.4 is not
// asked. Keep floor_check_marker in packaging/linux/preinstall.sh,
// packaging/linux/apt-downgrade-guard.sh and the macOS pkg preinstall
// (scripts/build-macos-enterprise-pkg.sh) the same.
const floorCheckMarker = "defenseclaw-package-floor-check/1"

// floorCheckMarkerAnnotation holds floorCheckMarker on the command.
const floorCheckMarkerAnnotation = "defenseclaw.package-floor-check"

// newEnterpriseBundleFloorCheckCommand is the release floor check the Linux
// and macOS package scripts run with the installed gateway before any file
// is replaced: a device that takes signed bundles must not go below the release
// its confirmed bundle requires (min_product_version).
func newEnterpriseBundleFloorCheckCommand() *cobra.Command {
	var version string
	cmd := &cobra.Command{
		Use:          "floor-check",
		Short:        "Check a package version against the confirmed bundle's release floor (package scripts)",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Annotations:  map[string]string{"defenseclaw.skip-daemon-bootstrap": "true", floorCheckMarkerAnnotation: floorCheckMarker},
		RunE: func(_ *cobra.Command, _ []string) error {
			if strings.TrimSpace(version) == "" {
				return bundleUsage("--product-version is required")
			}
			// The trust anchors decide, not the runtime descriptor: a
			// --keep-state uninstall removes the descriptor and keeps the
			// anchors and the confirmed bundle a reinstall resumes under.
			if bundleSecureClient() {
				return nil
			}
			env, err := newUnixLifecycleEnv(runtime.GOOS)
			if err != nil {
				return withExitCode(&enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}, bundleFloorRefusedExit)
			}
			return withExitCode(env.BundleProductFloorRefusal(strings.TrimSpace(version)), bundleFloorRefusedExit)
		},
	}
	cmd.Flags().StringVar(&version, "product-version", "", "the DefenseClaw version about to be installed")
	cmd.SetFlagErrorFunc(lifecycleFlagError)
	return cmd
}

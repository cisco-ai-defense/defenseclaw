// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package winpackage

import "errors"

const (
	ProductVendorDir                = `Cisco\Cisco Secure Client`
	ProductLeafDir                  = "DefenseClaw"
	ServiceName                     = "DefenseClawGateway"
	ServiceDisplayName              = "Cisco DefenseClaw Gateway"
	EventLogSource                  = "DefenseClaw"
	DeploymentModeEnv               = "DEFENSECLAW_DEPLOYMENT_MODE"
	DeploymentModeManagedEnterprise = "managed_enterprise"
)

var errNotWindows = errors.New("windows packaging paths are only available on windows")

func InstallRoot() (string, error) { return "", errNotWindows }
func DataRoot() (string, error)    { return "", errNotWindows }

func BinDir(string) string          { return "" }
func ConfigPath(string) string      { return "" }
func RuntimeDir(string) string      { return "" }
func HookManifestPath(string) string { return "" }
func HookStateDir(string) string    { return "" }
func LogDir(string) string          { return "" }
func LogFile(string, string) string { return "" }

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// AdminStatusHint is the command an administrator runs on goos to see the
// standalone deployment: the lifecycle status of the platform, which names
// what inspects each account. It is the one source of the command a status
// text hands a standard user, so a text never names a command another
// platform has, or none (GAP-0979: the status text named a command that no
// platform ships).
//
//   - windows: the managed CLI by its absolute path, in an elevated PowerShell
//     prompt; Setup puts no DefenseClaw command on PATH.
//   - darwin and linux: the managed gateway by its absolute path under sudo.
func AdminStatusHint(goos string) string {
	switch goos {
	case "windows":
		return "`" + WindowsAdminCommand("enterprise", "windows", "status", "--profile", "standalone") + "` in an elevated PowerShell prompt"
	case "darwin":
		return "`sudo " + StandaloneGatewayPath("darwin") + " enterprise macos status`"
	}
	return "`sudo " + StandaloneGatewayPath("linux") + " enterprise linux status`"
}

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
	"path"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	semanticRecursiveDeleteExpression        = `f.commands.exists(c, c.argv_complete && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DELETE in c.operations && f.paths.exists(p, p.command_id == c.id && p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_DELETE))`
	semanticSudoDiscoveryElevationExpression = `f.commands.exists(c, c.argv_complete && ((c.program == 'sudo' && ('-l' in c.argv || '--list' in c.argv || defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_PRIVILEGE in c.operations)) || (c.program == 'find' && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_SEARCH in c.operations) || (c.program == 'getcap' && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_SEARCH in c.operations)))`
	semanticAccessControlExpression          = `f.commands.exists(c, c.argv_complete && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_PERMISSION_CHANGE in c.operations && f.paths.exists(p, p.command_id == c.id && p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_METADATA))`
	semanticDDDiskWriteExpression            = `f.commands.exists(c, c.argv_complete && c.program == 'dd' && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DISK_WRITE in c.operations && f.paths.exists(p, p.command_id == c.id && p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE && p.flavor == defenseclaw.guardrail.semantic.v1.PathFlavor.PATH_FLAVOR_DEVICE))`
	semanticFilesystemWipeExpression         = `f.commands.exists(c, c.argv_complete && c.program in ['mkfs', 'mkfs.ext2', 'mkfs.ext3', 'mkfs.ext4', 'mke2fs', 'mkfs.xfs', 'mkfs.btrfs', 'mkfs.f2fs', 'mkfs.vfat', 'mkdosfs', 'mkfs.ntfs', 'mkntfs', 'mkswap', 'mkfs.exfat', 'mkexfatfs'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DISK_WRITE in c.operations && f.paths.exists(p, p.command_id == c.id && p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE && p.flavor == defenseclaw.guardrail.semantic.v1.PathFlavor.PATH_FLAVOR_DEVICE))`
	semanticDeviceWipeExpression             = `f.commands.exists(c, c.argv_complete && c.program in ['wipefs', 'sgdisk', 'shred', 'blkdiscard', 'tee', 'cryptsetup', 'hdparm', 'nvme', 'parted', 'diskutil', 'format', 'format-volume', 'clear-disk'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DISK_WRITE in c.operations && f.paths.exists(p, p.command_id == c.id && p.access == defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE && p.flavor == defenseclaw.guardrail.semantic.v1.PathFlavor.PATH_FLAVOR_DEVICE))`
	semanticNetworkSweepExpression           = `f.commands.exists(c, c.argv_complete && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_NETWORK_SCAN in c.operations && f.network.exists(n, n.command_id == c.id && n.action == defenseclaw.guardrail.semantic.v1.NetworkAction.NETWORK_ACTION_SCAN && n.target_kind in [defenseclaw.guardrail.semantic.v1.NetworkTargetKind.NETWORK_TARGET_KIND_MULTI_ADDRESS_CIDR, defenseclaw.guardrail.semantic.v1.NetworkTargetKind.NETWORK_TARGET_KIND_RANGE, defenseclaw.guardrail.semantic.v1.NetworkTargetKind.NETWORK_TARGET_KIND_LIST, defenseclaw.guardrail.semantic.v1.NetworkTargetKind.NETWORK_TARGET_KIND_GENERATED]))`
	semanticContainerHostEscapeExpression    = `f.commands.exists(c, c.argv_complete && c.program in ['docker', 'podman', 'nerdctl'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_CONTAINER_RUN in c.operations && c.argv.exists(a, a == '--privileged' || a.startsWith('--privileged=')) && f.paths.exists(p, p.command_id == c.id && p.access in [defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_READ, defenseclaw.guardrail.semantic.v1.PathAccess.PATH_ACCESS_WRITE] && (p.normalized == '/' || p.resolved == '/')))`
	semanticCryptominingExpression           = `f.commands.exists(c, c.argv_complete && c.program in ['docker', 'podman', 'nerdctl'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_CONTAINER_RUN in c.operations)`
	semanticMassProcessTerminationExpression = `f.commands.exists(c, c.argv_complete && c.program in ['kill', 'stop-process', 'taskkill'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_PROCESS_KILL in c.operations)`
	semanticPrivilegedAccountExpression      = `f.commands.exists(c, c.argv_complete && c.program in ['useradd', 'usermod', 'gpasswd', 'groupmems', 'adduser', 'dseditgroup', 'dscl', 'net', 'net1', 'add-localgroupmember', 'add-adgroupmember'] && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_ACCOUNT_CHANGE in c.operations)`
)

var semanticReconImpactOwners = map[string]semanticOwner{
	"CMD-RM-RF": {
		equivalentAliases: []string{
			"CMD-WIN-REMOVE-ITEM-RF",
			"CMD-WIN-RMDIR-SQ",
		},
		prerequisite:     recursiveDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-SUDO": {
		prerequisite:     sudoOrRootPrivilegeDiscoveryPrerequisite,
		suppressFallback: sudoOrRootPrivilegeDiscoverySafeNegative,
	},
	"CMD-CHMOD-WORLD": reconImpactOwnerWithAliases(
		actionfacts.OperationPermissionChange,
		accessControlMutationDisposition,
		"CMD-CHOWN-ROOT",
	),
	"CMD-DD-IF": {
		prerequisite:     ddDiskWritePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-MKFS": {
		prerequisite:     filesystemWipePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"CMD-DEVICE-WIPE": {
		prerequisite:     destructiveDeviceWritePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"recon.network_sweep": {
		prerequisite:     networkSweepPrerequisite,
		suppressFallback: networkSweepSafeNegative,
	},
	"privilege.container_host_escape": reconImpactOwnerWithSafeNegative(
		actionfacts.OperationContainerRun,
		containerHostEscapeDisposition,
		containerRunDisposition,
	),
	"impact.cryptomining_launch": {
		prerequisite: reconImpactOwnerPrerequisite(
			actionfacts.OperationContainerRun,
			cryptominingLaunchDisposition,
		),
		suppressFallback: cryptominingSafeNegative,
	},
	"impact.mass_process_termination": reconImpactOwner(
		actionfacts.OperationProcessKill,
		broadProcessTerminationDisposition,
	),
	"persistence.privileged_account_change": reconImpactOwner(
		actionfacts.OperationAccountChange,
		privilegedAccountDisposition,
	),
}

type reconImpactDisposition func(
	actionfacts.Facts,
	actionfacts.CommandFact,
) (matched, determinate bool)

func reconImpactOwner(
	operation actionfacts.OperationKind,
	disposition reconImpactDisposition,
) semanticOwner {
	return reconImpactOwnerWithSafeNegative(
		operation,
		disposition,
		disposition,
	)
}

func reconImpactOwnerWithAliases(
	operation actionfacts.OperationKind,
	disposition reconImpactDisposition,
	aliases ...string,
) semanticOwner {
	owner := reconImpactOwner(operation, disposition)
	owner.equivalentAliases = append([]string(nil), aliases...)
	return owner
}

func reconImpactOwnerWithSafeNegative(
	operation actionfacts.OperationKind,
	disposition reconImpactDisposition,
	safeNegative reconImpactDisposition,
) semanticOwner {
	return semanticOwner{
		prerequisite:     reconImpactOwnerPrerequisite(operation, disposition),
		suppressFallback: reconImpactOwnerSafeNegative(operation, safeNegative),
	}
}

func reconImpactOwnerPrerequisite(
	operation actionfacts.OperationKind,
	disposition reconImpactDisposition,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		for _, command := range facts.Commands {
			if reconImpactExecutingOwned(command) &&
				hasOperation(command, operation) {
				if matched, _ := disposition(facts, command); matched {
					return true
				}
			}
		}
		return false
	}
}

func reconImpactOwnerSafeNegative(
	operation actionfacts.OperationKind,
	disposition reconImpactDisposition,
) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		if !facts.Authoritative() {
			return false
		}
		for _, command := range facts.Commands {
			if !hasOperation(command, operation) {
				continue
			}
			if _, determinate := disposition(facts, command); !determinate {
				return false
			}
		}
		return true
	}
}

func recursiveDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) ||
			!hasOperation(command, actionfacts.OperationDelete) ||
			!recursiveForceDeleteFlags(command) {
			continue
		}
		if commandOwnsPath(
			facts,
			command.ID,
			actionfacts.PathAccessDelete,
			func(candidate actionfacts.PathFact) bool {
				return deleteTargetIsCriticalScope(facts, candidate)
			},
		) {
			return true
		}
	}
	return false
}

func recursiveForceDeleteFlags(command actionfacts.CommandFact) bool {
	switch {
	case command.Dialect != actionfacts.DialectPowerShell &&
		oneOfFold(command.Program, "rm"):
		return posixRecursiveForceFlags(command.Argv)
	case command.Dialect == actionfacts.DialectPowerShell &&
		oneOfFold(
			command.Program,
			"remove-item", "ri", "rm", "del", "erase", "rd", "rmdir",
		):
		return powerShellRecursiveForceFlags(command.Argv)
	case command.Dialect == actionfacts.DialectCMD &&
		oneOfFold(command.Program, "rmdir", "rd"):
		return cmdRecursiveQuietFlags(command.Argv)
	default:
		return false
	}
}

func posixRecursiveForceFlags(argv []string) bool {
	recursive := false
	force := false
	options := true
	for _, argument := range argv[1:] {
		if options && argument == "--" {
			options = false
			continue
		}
		if !options || argument == "-" || !strings.HasPrefix(argument, "-") {
			continue
		}
		switch argument {
		case "--recursive":
			recursive = true
		case "--force":
			force = true
		default:
			if strings.HasPrefix(argument, "--") {
				continue
			}
			for _, flag := range argument[1:] {
				recursive = recursive || flag == 'r' || flag == 'R'
				force = force || flag == 'f'
			}
		}
	}
	return recursive && force
}

func powerShellRecursiveForceFlags(argv []string) bool {
	recurse := false
	force := false
	valueOptions := map[string]struct{}{
		"-path": {}, "-literalpath": {}, "-filter": {}, "-include": {},
		"-exclude": {}, "-credential": {}, "-erroraction": {},
		"-errorvariable": {}, "-informationaction": {},
		"-informationvariable": {}, "-outbuffer": {}, "-outvariable": {},
		"-pipelinevariable": {}, "-progressaction": {}, "-warningaction": {},
		"-warningvariable": {},
	}
	for index := 1; index < len(argv); index++ {
		key, joinedValue, joined := splitPowerShellOption(argv[index])
		if _, consumes := valueOptions[key]; consumes {
			if !joined && index+1 < len(argv) {
				index++
			} else if joinedValue == "" {
				return false
			}
			continue
		}
		switch key {
		case "-recurse", "-rec":
			recurse = powerShellSwitchValueEnabled(joinedValue, joined)
		case "-force", "-fo":
			force = powerShellSwitchValueEnabled(joinedValue, joined)
		}
	}
	return recurse && force
}

func powerShellSwitchValueEnabled(value string, joined bool) bool {
	if !joined {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "$true", "true", "1":
		return true
	default:
		return false
	}
}

func cmdRecursiveQuietFlags(argv []string) bool {
	recursive := false
	quiet := false
	for _, argument := range argv[1:] {
		switch strings.ToLower(argument) {
		case "/s":
			recursive = true
		case "/q":
			quiet = true
		}
	}
	return recursive && quiet
}

func deleteTargetIsCriticalScope(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := canonicalSemanticPath(semanticPathValue(candidate))
	if value == "/" || windowsDriveRoot(value) {
		return true
	}
	switch strings.TrimRight(value, "/") {
	case "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
		"/mnt", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
		"/applications", "/library", "/system", "/users",
		"c:/program files", "c:/program files (x86)", "c:/programdata",
		"c:/users", "c:/windows":
		return true
	}
	home := strings.TrimRight(canonicalSemanticPath(facts.ActiveHome), "/")
	return home != "" &&
		strings.TrimRight(value, "/") == home
}

func windowsDriveRoot(value string) bool {
	value = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), `\`, "/")
	return len(value) == 2 && value[1] == ':' ||
		len(value) == 3 && value[1] == ':' && value[2] == '/'
}

func sudoDiscoveryOrElevationDisposition(
	_ actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	if !oneOfFold(command.Program, "sudo") {
		return false, false
	}
	argv := command.Argv
	if len(argv) < 2 {
		return false, false
	}
	valueOptions := map[string]struct{}{
		"-C": {}, "--close-from": {}, "-D": {}, "--chdir": {},
		"-g": {}, "--group": {}, "--host": {},
		"-p": {}, "--prompt": {}, "-R": {}, "--chroot": {},
		"-r": {}, "--role": {}, "-t": {}, "--type": {},
		"-T": {}, "--command-timeout": {}, "-U": {}, "--other-user": {},
		"-u": {}, "--user": {},
	}
	flagOptions := map[string]struct{}{
		"-A": {}, "--askpass": {}, "-b": {}, "--background": {},
		"-E": {}, "--preserve-env": {}, "-H": {}, "--set-home": {},
		"-K": {}, "--remove-timestamp": {}, "-k": {}, "--reset-timestamp": {},
		"-n": {}, "--non-interactive": {}, "-P": {}, "--preserve-groups": {},
		"-S": {}, "--stdin": {}, "-v": {}, "--validate": {},
	}

	discovery := false
	shellMode := false
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if argument == "--" {
			index++
			if index >= len(argv) {
				return false, false
			}
			return discovery || shellMode || shellProgram(argv[index]), true
		}
		switch argument {
		case "-l", "-ll", "--list":
			discovery = true
			continue
		case "-s", "--shell", "-i", "--login":
			shellMode = true
			continue
		case "--help", "-V", "--version":
			return false, true
		case "-h":
			// sudo uses -h both for the standalone help form and for a host
			// value. A following non-option token makes the latter exact.
			if index+1 >= len(argv) {
				return false, !discovery && !shellMode
			}
			if argv[index+1] == "" ||
				strings.HasPrefix(argv[index+1], "-") {
				return false, false
			}
			index++
			continue
		}
		key, value, joined := strings.Cut(argument, "=")
		if key == "--preserve-env" && joined {
			if value == "" {
				return false, false
			}
			continue
		}
		if _, consumes := valueOptions[key]; consumes {
			if joined {
				if value == "" {
					return false, false
				}
				continue
			}
			if index+1 >= len(argv) || argv[index+1] == "" {
				return false, false
			}
			index++
			continue
		}
		if _, flag := flagOptions[argument]; flag {
			continue
		}
		if strings.HasPrefix(argument, "-") {
			return false, false
		}
		return discovery || shellMode || shellProgram(argument), true
	}
	if discovery || shellMode {
		return true, true
	}
	return false, true
}

func sudoOrRootPrivilegeDiscoveryPrerequisite(facts actionfacts.Facts) bool {
	if systemRootPrivilegeDiscovery(facts) {
		return true
	}
	return reconImpactOwnerPrerequisite(
		actionfacts.OperationPrivilege,
		sudoDiscoveryOrElevationDisposition,
	)(facts)
}

func sudoOrRootPrivilegeDiscoverySafeNegative(facts actionfacts.Facts) bool {
	if systemRootPrivilegeDiscovery(facts) {
		return false
	}
	return reconImpactOwnerSafeNegative(
		actionfacts.OperationPrivilege,
		sudoDiscoveryOrElevationDisposition,
	)(facts) || facts.Authoritative()
}

func shellProgram(value string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(value, `\`, "/")))
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish":
		return true
	default:
		return false
	}
}

func accessControlMutationDisposition(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	switch strings.ToLower(command.Program) {
	case "chmod":
		mode, ok := firstPOSIXPermissionOperand(command.Argv)
		if !ok {
			return false, false
		}
		parsed, err := strconv.ParseUint(mode, 8, 16)
		if err != nil {
			setID, publicReadWrite, valid := symbolicPermissionRisk(mode)
			if !valid {
				return false, false
			}
			if setID {
				return commandOwnsPath(
					facts,
					command.ID,
					actionfacts.PathAccessMetadata,
					func(candidate actionfacts.PathFact) bool {
						return candidate.Absolute &&
							!isDefiniteFixturePath(facts, candidate)
					},
				), true
			}
			return publicReadWrite &&
				commandOwnsProtectedSecurityPath(facts, command.ID), true
		}
		if len(mode) < 3 || len(mode) > 4 {
			return false, false
		}
		if parsed&06000 != 0 {
			return commandOwnsPath(
				facts,
				command.ID,
				actionfacts.PathAccessMetadata,
				func(candidate actionfacts.PathFact) bool {
					return candidate.Absolute &&
						!isDefiniteFixturePath(facts, candidate)
				},
			), true
		}
		dangerous := parsed&0002 != 0 || parsed&0011 != 0
		if !dangerous && parsed&0004 != 0 {
			dangerous = commandOwnsPath(
				facts,
				command.ID,
				actionfacts.PathAccessMetadata,
				func(candidate actionfacts.PathFact) bool {
					return privateSecurityMaterial(facts, candidate)
				},
			)
		}
		return dangerous && commandOwnsProtectedSecurityPath(facts, command.ID), true
	case "chown":
		_, ok := firstPOSIXPermissionOperand(command.Argv)
		if !ok {
			return false, false
		}
		return commandOwnsProtectedSecurityPath(facts, command.ID) ||
			recursiveActiveSSHOwnershipChange(facts, command), true
	case "chgrp":
		_, ok := firstPOSIXPermissionOperand(command.Argv)
		if !ok {
			return false, false
		}
		return commandOwnsProtectedSecurityPath(facts, command.ID) ||
			recursiveActiveSSHOwnershipChange(facts, command), true
	case "install":
		mode, ok := posixOptionValue(command.Argv, "-m", "--mode")
		return ok && dangerousAccessControlMode(mode) &&
			commandOwnsPath(
				facts,
				command.ID,
				actionfacts.PathAccessMetadata,
				func(candidate actionfacts.PathFact) bool {
					if installModeSetID(mode) {
						return candidate.Absolute &&
							!isDefiniteFixturePath(facts, candidate)
					}
					return protectedSecurityPath(facts, candidate)
				},
			), ok
	case "setfacl", "set-acl":
		return commandOwnsProtectedSecurityPath(facts, command.ID), true
	case "setcap":
		if len(command.Argv) != 3 {
			return false, false
		}
		return dangerousCapabilityAssignment(command.Argv[1]) &&
			commandOwnsPath(
				facts,
				command.ID,
				actionfacts.PathAccessMetadata,
				func(candidate actionfacts.PathFact) bool {
					return candidate.Absolute &&
						!isDefiniteFixturePath(facts, candidate)
				},
			), true
	case "icacls":
		return dangerousICACLS(command.Argv) &&
			commandOwnsProtectedSecurityPath(facts, command.ID), true
	case "takeown":
		return commandOwnsProtectedSecurityPath(facts, command.ID), true
	default:
		return false, false
	}
}

func symbolicPermissionRisk(mode string) (setID, publicReadWrite, valid bool) {
	if mode == "" {
		return false, false, false
	}
	for _, clause := range strings.Split(strings.ToLower(mode), ",") {
		operator := strings.IndexAny(clause, "+-=")
		if operator < 0 || operator == len(clause)-1 {
			return false, false, false
		}
		who := clause[:operator]
		for _, char := range who {
			if !strings.ContainsRune("ugoa", char) {
				return false, false, false
			}
		}
		permissions := clause[operator+1:]
		for _, char := range permissions {
			if !strings.ContainsRune("rwxstx", char) {
				return false, false, false
			}
		}
		if clause[operator] == '-' {
			continue
		}
		public := who == "" ||
			strings.ContainsAny(who, "oa")
		if strings.ContainsRune(permissions, 's') &&
			(who == "" || strings.ContainsAny(who, "uga")) {
			setID = true
		}
		if public && strings.ContainsAny(permissions, "rw") {
			publicReadWrite = true
		}
	}
	return setID, publicReadWrite, true
}

func recursiveActiveSSHOwnershipChange(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) bool {
	if !hasArgumentFold(command.Argv, "-R") &&
		!hasArgumentFold(command.Argv, "--recursive") {
		return false
	}
	return commandOwnsPath(
		facts,
		command.ID,
		actionfacts.PathAccessMetadata,
		func(candidate actionfacts.PathFact) bool {
			relative, ok := activeHomeRelative(facts, candidate)
			return ok && (relative == ".ssh" ||
				strings.HasPrefix(relative, ".ssh/"))
		},
	)
}

func dangerousAccessControlMode(mode string) bool {
	if parsed, err := strconv.ParseUint(mode, 8, 16); err == nil {
		return parsed&06000 != 0 || parsed&0002 != 0
	}
	lower := strings.ToLower(mode)
	return strings.Contains(lower, "+s") ||
		strings.Contains(lower, "=s") ||
		strings.Contains(lower, "o+w") ||
		strings.Contains(lower, "a+w")
}

func installModeSetID(mode string) bool {
	if parsed, err := strconv.ParseUint(mode, 8, 16); err == nil {
		return parsed&06000 != 0
	}
	lower := strings.ToLower(mode)
	return strings.Contains(lower, "+s") ||
		strings.Contains(lower, "=s")
}

func dangerousCapabilityAssignment(value string) bool {
	lower := strings.ToLower(value)
	if !strings.ContainsAny(lower, "+=") ||
		!strings.ContainsAny(lower, "eip") {
		return false
	}
	for _, capability := range []string{
		"cap_setuid", "cap_setgid", "cap_sys_admin", "cap_dac_override",
		"cap_dac_read_search", "cap_sys_ptrace", "cap_sys_module",
		"cap_sys_rawio", "cap_net_admin", "cap_chown", "cap_fowner",
	} {
		if strings.Contains(lower, capability) {
			return true
		}
	}
	return false
}

func firstPOSIXPermissionOperand(argv []string) (string, bool) {
	options := true
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "--reference=") {
			return "", false
		}
		if options && (argument == "--reference" || argument == "--from") {
			if index+1 >= len(argv) {
				return "", false
			}
			index++
			continue
		}
		if options && strings.HasPrefix(argument, "-") && argument != "-" {
			continue
		}
		return argument, argument != ""
	}
	return "", false
}

func dangerousICACLS(argv []string) bool {
	for index := 2; index < len(argv); index++ {
		switch strings.ToLower(argv[index]) {
		case "/grant", "/grant:r":
			if index+1 >= len(argv) {
				return false
			}
			principal, rights, found := strings.Cut(
				strings.ToLower(argv[index+1]),
				":",
			)
			if !found {
				continue
			}
			if broadWindowsPrincipal(principal) &&
				strings.ContainsAny(strings.ToUpper(rights), "FMW") {
				return true
			}
			index++
		case "/setowner":
			return true
		}
	}
	return false
}

func broadWindowsPrincipal(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	switch value {
	case "everyone", "users", "builtin\\users", "authenticated users",
		"nt authority\\authenticated users", "*s-1-1-0":
		return true
	default:
		return false
	}
}

func commandOwnsProtectedSecurityPath(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	return commandOwnsPath(
		facts,
		commandID,
		actionfacts.PathAccessMetadata,
		func(candidate actionfacts.PathFact) bool {
			return protectedSecurityPath(facts, candidate)
		},
	)
}

func protectedSecurityPath(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	if matchesActiveSudoers(facts, candidate) ||
		matchesActiveAuthorizedKeys(facts, candidate) ||
		matchesActiveAgentConfig(facts, candidate) ||
		matchesActiveDefenseClawState(facts, candidate) ||
		privateSecurityMaterial(facts, candidate) {
		return true
	}
	value := strings.TrimRight(semanticPathValue(candidate), "/")
	switch value {
	case "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/sudoers", "/etc/ssh/sshd_config",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"/var/run/secrets/azure/tokens/azure-identity-token":
		return true
	}
	if strings.HasPrefix(value, "/etc/sudoers.d/") &&
		!strings.Contains(strings.TrimPrefix(value, "/etc/sudoers.d/"), "/") {
		return true
	}
	if strings.HasSuffix(value, "/windows/system32/config/sam") ||
		strings.HasSuffix(value, "/windows/system32/config/security") ||
		strings.HasSuffix(value, "/windows/system32/config/system") ||
		strings.HasSuffix(value, "/programdata/ssh/sshd_config") {
		return true
	}
	return false
}

func privateSecurityMaterial(
	facts actionfacts.Facts,
	candidate actionfacts.PathFact,
) bool {
	value := strings.TrimRight(semanticPathValue(candidate), "/")
	switch value {
	case "/etc/shadow", "/etc/gshadow",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"/var/run/secrets/azure/tokens/azure-identity-token":
		return true
	}
	return matchesActiveAuthorizedKeys(facts, candidate) ||
		matchesActiveSSHPrivateKey(facts, candidate) ||
		matchesActiveAWSCredentials(facts, candidate) ||
		matchesActiveKubeConfig(facts, candidate) ||
		matchesActivePackageCredentialFile(facts, candidate) ||
		matchesActiveGitCredentialFile(facts, candidate) ||
		matchesActiveCloudCredentialFile(facts, candidate) ||
		matchesActiveBrowserSessionStore(facts, candidate)
}

func ddDiskWritePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if reconImpactExecutingOwned(command) &&
			oneOfFold(command.Program, "dd") &&
			hasOperation(command, actionfacts.OperationDiskWrite) &&
			commandOwnsDeviceWrite(facts, command.ID) {
			return true
		}
	}
	return false
}

func filesystemWipePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) ||
			!hasOperation(command, actionfacts.OperationDiskWrite) ||
			!filesystemFormatterProgram(command.Program) {
			continue
		}
		if commandOwnsDeviceWrite(facts, command.ID) {
			return true
		}
	}
	return false
}

func filesystemFormatterProgram(program string) bool {
	switch strings.ToLower(program) {
	case "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mke2fs",
		"mkfs.xfs", "mkfs.btrfs", "mkfs.f2fs", "mkfs.vfat", "mkdosfs",
		"mkfs.ntfs", "mkntfs", "mkswap", "mkfs.exfat", "mkexfatfs":
		return true
	default:
		return false
	}
}

func destructiveDeviceWritePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) ||
			!hasOperation(command, actionfacts.OperationDiskWrite) ||
			!destructiveDeviceWriteProgram(command.Program) {
			continue
		}
		if commandOwnsDeviceWrite(facts, command.ID) {
			return true
		}
	}
	return false
}

func destructiveDeviceWriteProgram(program string) bool {
	switch strings.ToLower(program) {
	case "wipefs", "sgdisk", "shred", "blkdiscard", "tee", "cryptsetup",
		"hdparm", "nvme", "parted", "diskutil", "format",
		"format-volume", "clear-disk":
		return true
	default:
		return false
	}
}

func commandOwnsDeviceWrite(facts actionfacts.Facts, commandID int64) bool {
	return commandOwnsPath(
		facts,
		commandID,
		actionfacts.PathAccessWrite,
		func(candidate actionfacts.PathFact) bool {
			return candidate.Flavor == actionfacts.PathFlavorDevice
		},
	)
}

func networkSweepPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) ||
			!hasOperation(command, actionfacts.OperationNetworkScan) {
			continue
		}
		for _, network := range facts.Network {
			if network.CommandID == command.ID &&
				network.Action == actionfacts.NetworkScan &&
				broadNetworkTarget(network.TargetKind) {
				return true
			}
		}
	}
	return false
}

func networkSweepSafeNegative(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		if !hasOperation(command, actionfacts.OperationNetworkScan) {
			continue
		}
		sawTarget := false
		for _, network := range facts.Network {
			if network.CommandID != command.ID ||
				network.Action != actionfacts.NetworkScan {
				continue
			}
			sawTarget = true
			switch network.TargetKind {
			case actionfacts.NetworkTargetSingleHost,
				actionfacts.NetworkTargetSingleAddressCIDR:
			case actionfacts.NetworkTargetMultiAddressCIDR,
				actionfacts.NetworkTargetRange,
				actionfacts.NetworkTargetList,
				actionfacts.NetworkTargetGenerated:
				return true
			default:
				return false
			}
		}
		if !sawTarget {
			return false
		}
	}
	return true
}

func broadNetworkTarget(kind actionfacts.NetworkTargetKind) bool {
	switch kind {
	case actionfacts.NetworkTargetMultiAddressCIDR,
		actionfacts.NetworkTargetRange,
		actionfacts.NetworkTargetList,
		actionfacts.NetworkTargetGenerated:
		return true
	default:
		return false
	}
}

type containerRunShape struct {
	image      string
	entrypoint string
	privileged bool
}

func containerHostEscapeDisposition(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	shape, determinate := exactContainerRunShape(command)
	if !determinate || !shape.privileged {
		return false, determinate
	}
	return commandOwnsPath(
		facts,
		command.ID,
		"",
		func(candidate actionfacts.PathFact) bool {
			return (candidate.Access == actionfacts.PathAccessRead ||
				candidate.Access == actionfacts.PathAccessWrite) &&
				strings.TrimSpace(semanticPathValue(candidate)) == "/"
		},
	), true
}

func cryptominingLaunchDisposition(
	_ actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	shape, determinate := exactContainerRunShape(command)
	return determinate &&
		(exactMinerName(containerImageBase(shape.image)) ||
			exactMinerName(executableBase(shape.entrypoint))), determinate
}

func cryptominingSafeNegative(facts actionfacts.Facts) bool {
	if cryptominingFallbackProof(actionfacts.Input{}, facts) {
		return false
	}
	return reconImpactOwnerSafeNegative(
		actionfacts.OperationContainerRun,
		containerRunDisposition,
	)(facts)
}

func cryptominingFallbackProof(
	_ actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) {
			continue
		}
		if len(command.Argv) > 0 && exactMinerName(executableBase(command.Program)) &&
			!minerPreviewArguments(command.Argv[1:]) ||
			exactMinerWrapperTarget(command) {
			return true
		}
	}
	return false
}

func exactMinerWrapperTarget(command actionfacts.CommandFact) bool {
	argv := command.Argv
	if len(argv) < 2 {
		return false
	}
	switch executableBase(command.Program) {
	case "nohup":
		index := 1
		if argv[index] == "--" {
			index++
		} else if strings.HasPrefix(argv[index], "-") {
			return false
		}
		return exactMinerInvocationAt(argv, index)
	case "setsid":
		for index := 1; index < len(argv); index++ {
			switch argv[index] {
			case "--":
				index++
				return exactMinerInvocationAt(argv, index)
			case "-c", "--ctty", "-f", "--fork", "-w", "--wait":
				continue
			}
			if strings.HasPrefix(argv[index], "-") {
				return false
			}
			return exactMinerInvocationAt(argv, index)
		}
	case "nice":
		for index := 1; index < len(argv); index++ {
			argument := argv[index]
			switch {
			case argument == "--":
				index++
				return exactMinerInvocationAt(argv, index)
			case argument == "-n" || argument == "--adjustment":
				index++
				if index >= len(argv) {
					return false
				}
			case strings.HasPrefix(argument, "--adjustment="):
				continue
			case strings.HasPrefix(argument, "-"):
				if _, err := strconv.Atoi(strings.TrimPrefix(argument, "-")); err != nil {
					return false
				}
			default:
				return exactMinerInvocationAt(argv, index)
			}
		}
	}
	return false
}

func exactMinerInvocationAt(argv []string, index int) bool {
	return index >= 0 && index < len(argv) &&
		exactMinerName(executableBase(argv[index])) &&
		!minerPreviewArguments(argv[index+1:])
}

func minerPreviewArguments(arguments []string) bool {
	if len(arguments) == 2 && arguments[0] == "--" {
		arguments = arguments[1:]
	}
	if len(arguments) != 1 {
		return false
	}
	switch strings.ToLower(arguments[0]) {
	case "-h", "--help", "-v", "--version":
		return true
	default:
		return false
	}
}

func containerRunDisposition(
	_ actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	_, determinate := exactContainerRunShape(command)
	return false, determinate
}

func exactContainerRunShape(
	command actionfacts.CommandFact,
) (containerRunShape, bool) {
	if !oneOfFold(command.Program, "docker", "podman", "nerdctl") ||
		!command.ArgvComplete {
		return containerRunShape{}, false
	}
	subcommand, index, ok := containerSubcommand(command)
	if !ok || !strings.EqualFold(subcommand, "run") {
		return containerRunShape{}, false
	}
	shape := containerRunShape{}
	for index++; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		if argument == "--" {
			index++
			if index >= len(command.Argv) {
				return containerRunShape{}, false
			}
			shape.image = command.Argv[index]
			return shape, shape.image != ""
		}
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			shape.image = argument
			return shape, shape.image != ""
		}
		key, value, joined := strings.Cut(argument, "=")
		if key == "--privileged" && joined {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return containerRunShape{}, false
			}
			shape.privileged = parsed
			continue
		}
		if containerRunValueOption(key) {
			if joined {
				if value == "" {
					return containerRunShape{}, false
				}
			} else {
				if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
					return containerRunShape{}, false
				}
				index++
				value = command.Argv[index]
			}
			if key == "--entrypoint" {
				shape.entrypoint = value
			}
			continue
		}
		if containerRunFlagOption(argument) {
			shape.privileged = shape.privileged || argument == "--privileged"
			continue
		}
		return containerRunShape{}, false
	}
	return containerRunShape{}, false
}

func containerSubcommand(
	command actionfacts.CommandFact,
) (string, int, bool) {
	for index := 1; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		if argument == "--" {
			index++
			if index >= len(command.Argv) {
				return "", 0, false
			}
			return command.Argv[index], index, true
		}
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			return argument, index, true
		}
		key, value, joined := strings.Cut(argument, "=")
		if containerTopLevelOwnedValue(command.Program, key, argument) {
			if joined {
				if value == "" {
					return "", 0, false
				}
			} else if index+1 >= len(command.Argv) ||
				command.Argv[index+1] == "" {
				return "", 0, false
			} else {
				index++
			}
			continue
		}
		if containerTopLevelOwnedFlag(command.Program, argument) {
			continue
		}
		return "", 0, false
	}
	return "", 0, false
}

func containerTopLevelOwnedValue(program, key, raw string) bool {
	if raw == "-l" {
		return true
	}
	switch key {
	case "--api-cors-header", "--config", "--log-level", "--tlscacert",
		"--tlscert", "--tlskey":
		return true
	case "-H", "--host":
		return oneOfFold(program, "docker")
	case "-c", "--context":
		return oneOfFold(program, "docker")
	case "--url", "--connection":
		return oneOfFold(program, "podman")
	case "-a", "--address":
		return oneOfFold(program, "nerdctl")
	default:
		return false
	}
}

func containerTopLevelOwnedFlag(program, raw string) bool {
	return raw == "-D" || raw == "--debug" || raw == "--tls" ||
		raw == "--tlsverify" ||
		oneOfFold(program, "podman") && raw == "--remote"
}

func containerRunValueOption(key string) bool {
	switch key {
	case "-a", "--add-host", "--annotation", "--attach", "--blkio-weight",
		"--cap-add", "--cap-drop", "--cgroup-parent", "--cidfile", "--cpus",
		"--device", "--dns", "--dns-option", "--dns-search", "--domainname",
		"-e", "--env", "--env-file", "--entrypoint", "-h", "--hostname",
		"-l", "--label", "--label-file", "--link", "--log-driver",
		"--log-opt", "-m", "--memory", "--mount", "--name", "--network",
		"--network-alias", "--platform", "-p", "--publish", "--restart",
		"--runtime", "--security-opt", "--shm-size", "--stop-signal",
		"--stop-timeout", "-u", "--user", "--userns", "-v", "--volume",
		"-w", "--workdir":
		return true
	default:
		return false
	}
}

func containerRunFlagOption(argument string) bool {
	switch argument {
	case "-d", "--detach", "--init", "-i", "--interactive",
		"--oom-kill-disable", "--privileged", "--read-only", "--rm",
		"--tty", "-t":
		return true
	default:
		return false
	}
}

func containerImageBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, `\`, "/")))
	if digest := strings.IndexByte(value, '@'); digest >= 0 {
		value = value[:digest]
	}
	value = path.Base(value)
	if tag := strings.LastIndexByte(value, ':'); tag >= 0 {
		value = value[:tag]
	}
	return value
}

func executableBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, `\`, "/")))
	return path.Base(value)
}

func exactMinerName(value string) bool {
	switch value {
	case "xmrig", "xmrig-proxy", "minerd", "cpuminer", "cpuminer-multi",
		"ethminer", "cgminer", "bfgminer", "t-rex", "lolminer", "nbminer",
		"teamredminer", "phoenixminer", "nanominer":
		return true
	default:
		return false
	}
}

func broadProcessTerminationDisposition(
	facts actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	switch strings.ToLower(command.Program) {
	case "kill":
		return broadKillInvocation(command.Argv), true
	case "stop-process":
		if wildcardStopProcess(command.Argv) {
			return true, true
		}
		return getProcessForcePipeline(facts, command), true
	case "taskkill":
		return broadTaskkill(command.Argv), true
	case "killall", "pkill":
		return false, false
	default:
		return false, false
	}
}

func broadKillInvocation(argv []string) bool {
	targetAll := false
	signalKill := false
	for index := 1; index < len(argv); index++ {
		argument := strings.ToLower(argv[index])
		switch argument {
		case "-1":
			targetAll = true
		case "-9", "-kill", "-sigkill":
			signalKill = true
		case "-s", "--signal":
			if index+1 >= len(argv) {
				return false
			}
			index++
			signalKill = killSignal(argv[index])
		default:
			if strings.HasPrefix(argument, "--signal=") {
				signalKill = killSignal(strings.TrimPrefix(argument, "--signal="))
			}
		}
	}
	return targetAll && signalKill
}

func killSignal(value string) bool {
	switch strings.ToLower(value) {
	case "9", "kill", "sigkill":
		return true
	default:
		return false
	}
}

func wildcardStopProcess(argv []string) bool {
	force := false
	wildcard := false
	for index := 1; index < len(argv); index++ {
		key, value, joined := splitPowerShellOption(argv[index])
		switch key {
		case "-force":
			force = !joined
		case "-name", "-processname":
			if !joined {
				if index+1 >= len(argv) {
					return false
				}
				index++
				value = argv[index]
			}
			wildcard = wildcard || value == "*"
		}
	}
	return force && wildcard
}

func getProcessForcePipeline(
	facts actionfacts.Facts,
	sink actionfacts.CommandFact,
) bool {
	if sink.PipelineID == 0 || !hasArgumentFold(sink.Argv, "-force") {
		return false
	}
	for _, source := range facts.Commands {
		if source.ID != sink.ID &&
			source.PipelineID == sink.PipelineID &&
			oneOfFold(source.Program, "get-process") {
			return true
		}
	}
	return false
}

func broadTaskkill(argv []string) bool {
	force := false
	wildcard := false
	for index := 1; index < len(argv); index++ {
		switch strings.ToLower(argv[index]) {
		case "/f":
			force = true
		case "/im":
			if index+1 >= len(argv) {
				return false
			}
			index++
			wildcard = wildcard || argv[index] == "*"
		}
	}
	return force && wildcard
}

func privilegedAccountDisposition(
	_ actionfacts.Facts,
	command actionfacts.CommandFact,
) (bool, bool) {
	switch strings.ToLower(command.Program) {
	case "useradd":
		return posixOptionHasValue(command.Argv, []string{"-u", "--uid"}, "0"),
			true
	case "usermod":
		if posixOptionHasValue(command.Argv, []string{"-u", "--uid"}, "0") {
			return true, true
		}
		groups, found := posixOptionValue(
			command.Argv,
			"-G", "--groups", "-aG",
		)
		return found && containsPrivilegedPOSIXGroup(groups), true
	case "gpasswd":
		if len(command.Argv) != 4 ||
			!oneOfFold(command.Argv[1], "-a", "--add") {
			return false, false
		}
		return privilegedPOSIXGroup(command.Argv[3]), true
	case "groupmems":
		group, member, ok := groupmemsAddOperands(command.Argv)
		return ok && member != "" && privilegedPOSIXGroup(group), ok
	case "adduser":
		if posixOptionHasValue(
			command.Argv,
			[]string{"-u", "--uid"},
			"0",
		) {
			return true, true
		}
		if len(command.Argv) != 3 {
			return false, false
		}
		return privilegedPOSIXGroup(command.Argv[2]), true
	case "dseditgroup":
		if len(command.Argv) < 4 {
			return false, false
		}
		return privilegedPOSIXGroup(command.Argv[len(command.Argv)-1]), true
	case "dscl":
		if len(command.Argv) != 6 ||
			!strings.EqualFold(command.Argv[2], "-append") ||
			!strings.EqualFold(command.Argv[4], "groupmembership") {
			return false, false
		}
		group := strings.TrimPrefix(
			strings.ToLower(command.Argv[3]),
			"/groups/",
		)
		return privilegedPOSIXGroup(group), true
	case "net", "net1":
		if len(command.Argv) != 5 ||
			!oneOfFold(command.Argv[1], "localgroup") ||
			!oneOfFold(command.Argv[4], "/add") {
			return false, len(command.Argv) >= 2 &&
				oneOfFold(command.Argv[1], "localgroup")
		}
		return privilegedWindowsLocalGroup(command.Argv[2]), true
	case "add-localgroupmember":
		group, groupOK := namedPowerShellValue(command.Argv, "-group", "-sid")
		_, memberOK := namedPowerShellValue(command.Argv, "-member")
		return groupOK && memberOK && privilegedWindowsLocalGroup(group),
			groupOK && memberOK
	case "add-adgroupmember":
		group, groupOK := namedPowerShellValue(command.Argv, "-identity")
		_, memberOK := namedPowerShellValue(command.Argv, "-members")
		return groupOK && memberOK && privilegedWindowsADGroup(group),
			groupOK && memberOK
	default:
		return false, false
	}
}

func groupmemsAddOperands(argv []string) (group, member string, ok bool) {
	if len(argv) != 5 {
		return "", "", false
	}
	for index := 1; index+1 < len(argv); index += 2 {
		switch argv[index] {
		case "-g":
			group = argv[index+1]
		case "-a":
			member = argv[index+1]
		default:
			return "", "", false
		}
	}
	return group, member, group != "" && member != ""
}

func posixOptionHasValue(argv, names []string, expected string) bool {
	value, found := posixOptionValue(argv, names...)
	return found && value == expected
}

func posixOptionValue(argv []string, names ...string) (string, bool) {
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		for _, name := range names {
			if argument == name {
				if index+1 >= len(argv) {
					return "", false
				}
				return argv[index+1], true
			}
			if strings.HasPrefix(name, "--") &&
				strings.HasPrefix(argument, name+"=") {
				value := strings.TrimPrefix(argument, name+"=")
				return value, value != ""
			}
			if name == "-aG" && strings.HasPrefix(argument, "-aG") {
				value := strings.TrimPrefix(argument, "-aG")
				if value != "" {
					return value, true
				}
			}
		}
	}
	return "", false
}

func containsPrivilegedPOSIXGroup(value string) bool {
	for _, group := range strings.Split(value, ",") {
		if privilegedPOSIXGroup(group) {
			return true
		}
	}
	return false
}

func privilegedPOSIXGroup(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "root", "sudo", "wheel", "admin", "docker", "lxd", "incus", "podman":
		return true
	default:
		return false
	}
}

func privilegedWindowsLocalGroup(value string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`))) {
	case "administrators", "remote desktop users", "s-1-5-32-544",
		"*s-1-5-32-544":
		return true
	default:
		return false
	}
}

func privilegedWindowsADGroup(value string) bool {
	switch strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`))) {
	case "domain admins", "enterprise admins", "administrators":
		return true
	default:
		return false
	}
}

func namedPowerShellValue(argv []string, names ...string) (string, bool) {
	for index := 1; index < len(argv); index++ {
		key, value, joined := splitPowerShellOption(argv[index])
		if !oneOfFold(key, names...) {
			continue
		}
		if joined {
			return value, value != ""
		}
		if index+1 >= len(argv) || argv[index+1] == "" ||
			strings.HasPrefix(argv[index+1], "-") {
			return "", false
		}
		return argv[index+1], true
	}
	return "", false
}

// hostNamespaceEntryFallbackProof proves only direct, static PID-1 namespace
// or root entry. It is deliberately separate from semantic ownership because
// an opaque child keeps the whole action non-authoritative.
func hostNamespaceEntryFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 ||
			len(command.Wrappers) != 0 ||
			command.Effect != actionfacts.EffectExecute {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "nsenter":
			if !hasOperation(command, actionfacts.OperationNamespaceEnter) {
				continue
			}
			if commandOwnsPath(
				facts,
				command.ID,
				actionfacts.PathAccessRead,
				func(candidate actionfacts.PathFact) bool {
					value := semanticPathValue(candidate)
					for _, namespace := range []string{
						"mnt", "uts", "ipc", "net", "pid", "user",
						"cgroup", "time",
					} {
						if value == "/proc/1/ns/"+namespace {
							return true
						}
					}
					return false
				},
			) {
				return true
			}
		case "chroot":
			if hasOperation(command, actionfacts.OperationRootChange) &&
				commandOwnsPath(
					facts,
					command.ID,
					actionfacts.PathAccessRead,
					func(candidate actionfacts.PathFact) bool {
						return semanticPathValue(candidate) == "/proc/1/root"
					},
				) {
				return true
			}
		}
	}
	return false
}

// workloadExecFallbackProof recognizes only a complete static outer workload
// selector. The remote child remains opaque, so callers must keep this owner
// detection-only.
func workloadExecFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 ||
			len(command.Wrappers) != 0 ||
			command.Effect != actionfacts.EffectExecute {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "kubectl", "oc":
			if hasOperation(command, actionfacts.OperationWorkloadExec) &&
				staticKubernetesExecOuter(command) {
				return true
			}
		case "crictl":
			if staticCRICTLExecOuter(command.Argv) {
				return true
			}
		case "ctr":
			if staticCTRExecOuter(command.Argv) {
				return true
			}
		case "docker", "podman":
			if hasOperation(command, actionfacts.OperationWorkloadExec) &&
				staticContainerExecOuter(command) &&
				hasRemoteContainerEndpoint(facts, command.ID) {
				return true
			}
		}
	}
	return false
}

func staticKubernetesExecOuter(command actionfacts.CommandFact) bool {
	if hasArgumentFold(command.Argv, "--help") ||
		hasArgumentFold(command.Argv, "--version") {
		return false
	}
	for index, argument := range command.Argv[1:] {
		action := strings.ToLower(argument)
		if action != "exec" && action != "debug" &&
			!(action == "rsh" && oneOfFold(command.Program, "oc")) {
			continue
		}
		if workloadOperandIndex(command.Argv, index+2, "kube") >= 0 {
			return true
		}
	}
	return false
}

func staticCRICTLExecOuter(argv []string) bool {
	if len(argv) < 4 || !oneOfFold(argv[1], "exec") {
		return false
	}
	index := workloadOperandIndex(argv, 2, "crictl")
	return index >= 0 && index+1 < len(argv) && argv[index+1] != ""
}

func staticCTRExecOuter(argv []string) bool {
	if len(argv) < 5 ||
		!oneOfFold(argv[1], "tasks", "task") ||
		!oneOfFold(argv[2], "exec") {
		return false
	}
	index := workloadOperandIndex(argv, 3, "ctr")
	return index >= 0 && index+1 < len(argv) && argv[index+1] != ""
}

func staticContainerExecOuter(command actionfacts.CommandFact) bool {
	subcommand, index, ok := containerSubcommand(command)
	if !ok || !oneOfFold(subcommand, "exec") {
		return false
	}
	index = workloadOperandIndex(command.Argv, index+1, "container")
	return index >= 0 && index+1 < len(command.Argv) &&
		command.Argv[index+1] != ""
}

func workloadOperandIndex(argv []string, start int, family string) int {
	for index := start; index < len(argv); index++ {
		argument := argv[index]
		if argument == "--" {
			continue
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			if staticWorkloadOperand(argument) {
				return index
			}
			return -1
		}
		key, value, joined := strings.Cut(argument, "=")
		if workloadFlagOption(family, argument) {
			continue
		}
		if !workloadValueOption(family, key) {
			return -1
		}
		if joined {
			if value == "" {
				return -1
			}
			continue
		}
		index++
		if index >= len(argv) || argv[index] == "" {
			return -1
		}
	}
	return -1
}

func workloadFlagOption(family, value string) bool {
	switch family {
	case "kube":
		return oneOfFold(value, "-i", "--stdin", "-t", "--tty", "--quiet")
	case "crictl":
		return oneOfFold(
			value,
			"-i", "--interactive", "-t", "--tty", "-s", "--sync",
		)
	case "ctr":
		return oneOfFold(value, "-t", "--tty", "--detach")
	case "container":
		return oneOfFold(
			value,
			"-d", "--detach", "-i", "--interactive", "-t", "--tty",
		)
	default:
		return false
	}
}

func workloadValueOption(family, value string) bool {
	switch family {
	case "kube":
		return oneOfFold(
			value,
			"-c", "--container", "-f", "--filename",
			"--pod-running-timeout", "--profile", "--profile-output",
		)
	case "crictl":
		return oneOfFold(value, "--timeout")
	case "ctr":
		return oneOfFold(value, "--exec-id", "--cwd", "--user")
	case "container":
		return oneOfFold(
			value,
			"--detach-keys", "-e", "--env", "--env-file",
			"-u", "--user", "-w", "--workdir",
		)
	default:
		return false
	}
}

func staticWorkloadOperand(value string) bool {
	return value != "" &&
		!strings.HasPrefix(value, "-") &&
		!strings.ContainsAny(value, "$`*?[]{} \t\r\n")
}

func hasRemoteContainerEndpoint(
	facts actionfacts.Facts,
	commandID int64,
) bool {
	for _, network := range facts.Network {
		if network.CommandID != commandID ||
			network.Action != actionfacts.NetworkConnect {
			continue
		}
		host := strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(network.NormalizedHost)),
			".",
		)
		if network.Scope != actionfacts.NetworkScopeLoopback &&
			network.Scope != actionfacts.NetworkScopeLinkLocal &&
			host != "localhost" &&
			!strings.HasSuffix(host, ".localhost") {
			return true
		}
	}
	return false
}

// forkBombFallbackProof recognizes only canonical executable forms. It never
// scans arbitrary prose, and callers must keep the resulting owner
// detection-only.
func forkBombFallbackProof(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if canonicalShellForkBomb(input.Command) ||
		len(input.Argv) == 3 &&
			shellProgram(input.Argv[0]) &&
			input.Argv[1] == "-c" &&
			canonicalShellForkBomb(input.Argv[2]) {
		return true
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 ||
			len(command.Wrappers) != 0 ||
			command.Effect != actionfacts.EffectExecute {
			continue
		}
		switch strings.ToLower(command.Program) {
		case "perl":
			if exactInterpreterProgram(command.Argv, "fork while fork") {
				return true
			}
		case "ruby":
			if exactInterpreterProgram(command.Argv, "loop { fork }") {
				return true
			}
		}
	}
	return false
}

func canonicalShellForkBomb(value string) bool {
	var compact strings.Builder
	for _, character := range strings.TrimSpace(value) {
		switch character {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			compact.WriteRune(character)
		}
	}
	return compact.String() == ":(){:|:&};:"
}

func exactInterpreterProgram(argv []string, expected string) bool {
	if len(argv) != 3 || argv[1] != "-e" {
		return false
	}
	return strings.Join(strings.Fields(
		strings.TrimSuffix(strings.TrimSpace(argv[2]), ";"),
	), " ") == expected
}

func reconImpactExecutingOwned(command actionfacts.CommandFact) bool {
	return command.Effect == actionfacts.EffectExecute && command.ArgvComplete
}

func commandOwnsPath(
	facts actionfacts.Facts,
	commandID int64,
	access actionfacts.PathAccess,
	matches func(actionfacts.PathFact) bool,
) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID &&
			(access == "" || candidate.Access == access) &&
			matches(candidate) {
			return true
		}
	}
	return false
}

func splitPowerShellOption(value string) (key, optionValue string, joined bool) {
	key, optionValue, joined = strings.Cut(value, ":")
	if !joined {
		key, optionValue, joined = strings.Cut(value, "=")
	}
	return strings.ToLower(key), optionValue, joined
}

func hasArgumentFold(argv []string, expected string) bool {
	for _, argument := range argv {
		if strings.EqualFold(argument, expected) {
			return true
		}
	}
	return false
}

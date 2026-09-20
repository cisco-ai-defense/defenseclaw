// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// ExactWritableHostRootContainerAccess proves that one direct container run
// exposes the host root through a writable bind and immediately uses that
// exact mount as a chroot or to read a reviewed host credential file. A
// writable Docker-daemon bind is already host access; --privileged is not a
// necessary part of this narrower proof.
//
// The parser accepts only closed static argv forms. Dynamic mounts, read-only
// binds, unknown options, detached setup, and unrelated container commands
// abstain.
func ExactWritableHostRootContainerAccess(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	for _, command := range facts.Commands {
		if command.Effect != EffectExecute ||
			!command.ArgvComplete || !hasFactOperation(command, OperationContainerRun) {
			continue
		}
		target, child, ok := exactWritableHostRootContainerRun(command.Argv)
		if ok && exactContainerHostRootChild(child, target, 0) {
			return true
		}
	}
	return false
}

func exactWritableHostRootContainerRun(argv []string) (string, []string, bool) {
	if len(argv) < 5 {
		return "", nil, false
	}
	program := strings.ToLower(path.Base(argv[0]))
	if !equalFoldAny(program, "docker", "podman", "nerdctl") {
		return "", nil, false
	}
	index := 1
	for index < len(argv) && argv[index] != "run" {
		argument := argv[index]
		key, value, joined := strings.Cut(argument, "=")
		if !containerGlobalValueOption(program, key) {
			return "", nil, false
		}
		if joined {
			if value == "" {
				return "", nil, false
			}
		} else {
			index++
			if index >= len(argv) || argv[index] == "" {
				return "", nil, false
			}
		}
		index++
	}
	if index >= len(argv) || argv[index] != "run" {
		return "", nil, false
	}
	index++
	target := ""
	for index < len(argv) {
		argument := argv[index]
		if argument == "--" {
			index++
			break
		}
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			break
		}
		key, value, joined := strings.Cut(argument, "=")
		if key == "-v" || key == "--volume" {
			if !joined {
				index++
				if index >= len(argv) {
					return "", nil, false
				}
				value = argv[index]
			}
			candidate, ok := exactWritableRootBind(value)
			if !ok || target != "" {
				return "", nil, false
			}
			target = candidate
			index++
			continue
		}
		if containerRunValueArgument(key) {
			if joined {
				if value == "" {
					return "", nil, false
				}
			} else {
				index++
				if index >= len(argv) || argv[index] == "" {
					return "", nil, false
				}
			}
			index++
			continue
		}
		if containerRunFlagArgument(argument) {
			index++
			continue
		}
		return "", nil, false
	}
	if target == "" || index >= len(argv) || argv[index] == "" {
		return "", nil, false
	}
	// The first positional is the image. A terminal child is required; merely
	// mounting host root remains dual-use and is left to the existing policy.
	index++
	if index >= len(argv) {
		return "", nil, false
	}
	return target, argv[index:], true
}

func equalFoldAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func containerGlobalValueOption(program, key string) bool {
	switch key {
	case "-l", "--log-level", "--config", "--context":
		return true
	case "-H", "--host":
		return strings.EqualFold(program, "docker")
	case "--url", "--connection":
		return strings.EqualFold(program, "podman")
	case "-a", "--address":
		return strings.EqualFold(program, "nerdctl")
	default:
		return false
	}
}

func containerRunValueArgument(key string) bool {
	switch key {
	case "-a", "--add-host", "--annotation", "--attach", "--blkio-weight",
		"--cap-add", "--cap-drop", "--cgroup-parent", "--cidfile", "--cpus",
		"--device", "--dns", "--dns-option", "--dns-search", "--domainname",
		"-e", "--env", "--env-file", "--entrypoint", "-h", "--hostname",
		"-l", "--label", "--label-file", "--link", "--log-driver",
		"--log-opt", "-m", "--memory", "--name", "--network",
		"--network-alias", "--platform", "-p", "--publish", "--restart",
		"--runtime", "--security-opt", "--shm-size", "--stop-signal",
		"--stop-timeout", "-u", "--user", "--userns", "-w", "--workdir":
		return true
	default:
		return false
	}
}

func containerRunFlagArgument(argument string) bool {
	switch argument {
	case "-d", "--detach", "--init", "-i", "--interactive", "-t", "--tty",
		"-it", "-ti", "--oom-kill-disable", "--privileged", "--read-only",
		"--rm":
		return true
	default:
		if strings.HasPrefix(argument, "--privileged=") {
			value := strings.TrimPrefix(argument, "--privileged=")
			return value == "true" || value == "false" || value == "1" || value == "0"
		}
		return false
	}
}

func exactWritableRootBind(value string) (string, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 && len(parts) != 3 || parts[0] != "/" {
		return "", false
	}
	target := parts[1]
	if target == "" || !strings.HasPrefix(target, "/") || path.Clean(target) != target ||
		target == "/" || hasUnresolvedPathSyntax(target) {
		return "", false
	}
	if len(parts) == 3 && parts[2] != "rw" {
		return "", false
	}
	return target, true
}

func exactContainerHostRootChild(argv []string, target string, depth int) bool {
	if len(argv) == 0 || depth > 1 {
		return false
	}
	program := strings.ToLower(path.Base(argv[0]))
	if program == "chroot" {
		return len(argv) >= 3 && argv[1] == target && argv[2] != "" &&
			!hasUnresolvedPathSyntax(argv[2])
	}
	if program == "cat" && len(argv) == 2 {
		return exactHostCredentialPath(argv[1], target)
	}
	if (program == "sh" || program == "bash") && len(argv) == 3 && argv[1] == "-c" {
		inner := Analyze(Input{Tool: "shell", Command: argv[2], DialectHint: DialectPOSIX})
		if !exactContainerChildParse(inner.Parse) {
			return false
		}
		topLevel := 0
		matched := false
		for _, command := range inner.Commands {
			if command.ParentCommandID != 0 {
				continue
			}
			topLevel++
			matched = matched || command.Kind == CommandKindProcess &&
				!command.ControlFlowUncertain && command.ArgvComplete &&
				exactContainerHostRootChild(command.Argv, target, depth+1)
		}
		return topLevel == 1 && matched
	}
	return false
}

func exactContainerChildParse(result ParseResult) bool {
	if result.Status == StatusComplete && len(result.Issues) == 0 {
		return true
	}
	return result.Status == StatusPartial && len(result.Issues) == 1 &&
		result.Issues[0] == IssueUnsupportedConstruct
}

func exactHostCredentialPath(value, target string) bool {
	if path.Clean(value) != value || !strings.HasPrefix(value, target+"/") {
		return false
	}
	switch strings.TrimPrefix(value, target) {
	case "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers":
		return true
	default:
		return false
	}
}

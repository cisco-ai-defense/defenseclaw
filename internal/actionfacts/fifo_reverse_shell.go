// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strconv"

// ExactPOSIXFIFOReverseShell proves the closed mkfifo → interactive shell →
// netcat feedback loop. The proof requires one shared absolute temporary FIFO,
// exact pipeline flow, a static non-local endpoint, and no wrappers or dynamic
// arguments. It deliberately works over a retained partial parse because the
// only unsupported construct is stderr descriptor duplication.
func ExactPOSIXFIFOReverseShell(facts Facts) bool {
	return exactPOSIXFIFOConnectBackShell(facts) ||
		ExactPOSIXFIFOListenerBindShell(facts)
}

func exactPOSIXFIFOConnectBackShell(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) != 3 {
		return false
	}
	var fifoPath string
	var shellID, netcatID, pipelineID int64
	for _, command := range facts.Commands {
		if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
			len(command.Wrappers) != 0 || command.Kind != CommandKindProcess ||
			command.Effect != EffectExecute || !command.ArgvComplete ||
			!staticArguments(command.Arguments) {
			return false
		}
		switch command.Program {
		case "mkfifo":
			if fifoPath != "" || command.PipelineID != 0 || len(command.Argv) != 2 ||
				len(command.Redirects) != 0 || !exactTemporaryExecutablePath(command.Argv[1]) {
				return false
			}
			fifoPath = command.Argv[1]
		case "sh", "bash":
			if shellID != 0 || command.PipelineID == 0 || len(command.Argv) != 2 ||
				command.Argv[1] != "-i" || !exactFIFOInteractiveShellRedirects(command.Redirects) {
				return false
			}
			shellID = command.ID
			pipelineID = command.PipelineID
		case "nc", "ncat", "netcat":
			if netcatID != 0 || command.PipelineID == 0 || len(command.Argv) != 3 ||
				!exactFIFOOutputRedirect(command.Redirects) ||
				!exactNonLocalNetcatConnect(facts, command.ID) {
				return false
			}
			netcatID = command.ID
			if pipelineID != 0 && pipelineID != command.PipelineID {
				return false
			}
			pipelineID = command.PipelineID
		default:
			return false
		}
	}
	if fifoPath == "" || shellID == 0 || netcatID == 0 || pipelineID == 0 ||
		!hasExactCommandFlow(facts, shellID, netcatID) {
		return false
	}
	var shellReads, netcatWrites bool
	for _, command := range facts.Commands {
		if command.ID == shellID {
			shellReads = redirectMatches(command.Redirects, 0, PathAccessRead, fifoPath)
		}
		if command.ID == netcatID {
			netcatWrites = redirectMatches(command.Redirects, 1, PathAccessWrite, fifoPath)
		}
	}
	return shellReads && netcatWrites
}

// ExactPOSIXFIFOListenerBindShell proves one closed listener → shell → FIFO
// feedback loop. It retains no port or path values and requires the same
// literal temporary FIFO identity on netcat stdin and shell stdout.
func ExactPOSIXFIFOListenerBindShell(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) != 2 ||
		len(facts.Network) != 1 {
		return false
	}
	var listenerID, shellID int64
	var fifoPath string
	var pipelineID int64
	for _, command := range facts.Commands {
		if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
			len(command.Wrappers) != 0 || command.Kind != CommandKindProcess ||
			command.Effect != EffectExecute || !command.ArgvComplete ||
			!allStaticCommandArguments(command) || command.PipelineID == 0 {
			return false
		}
		if pipelineID != 0 && pipelineID != command.PipelineID {
			return false
		}
		pipelineID = command.PipelineID
		switch command.Program {
		case "nc", "ncat", "netcat":
			if listenerID != 0 || !exactFIFOListenerNetcatArgv(command.Argv) ||
				len(command.Redirects) != 1 ||
				!redirectMatches(command.Redirects, 0, PathAccessRead, command.Redirects[0].Target) ||
				!exactTemporaryExecutablePath(command.Redirects[0].Target) {
				return false
			}
			listenerID = command.ID
			fifoPath = command.Redirects[0].Target
		case "sh", "bash":
			if shellID != 0 || !exactFIFOListenerShellArgv(command.Argv) ||
				!exactFIFOOutputRedirect(command.Redirects) {
				return false
			}
			shellID = command.ID
		default:
			return false
		}
	}
	if listenerID == 0 || shellID == 0 || fifoPath == "" ||
		!hasExactCommandFlow(facts, listenerID, shellID) {
		return false
	}
	for _, command := range facts.Commands {
		if command.ID == shellID &&
			!redirectMatches(command.Redirects, 1, PathAccessWrite, fifoPath) {
			return false
		}
	}
	network := facts.Network[0]
	return network.CommandID == listenerID && network.Action == NetworkListen &&
		network.Scheme == "tcp" && network.Host == "" &&
		network.Port >= 1 && network.Port <= 65535
}

func exactFIFOListenerNetcatArgv(argv []string) bool {
	if len(argv) < 3 || !exactFIFOListenerNetcatExecutable(argv[0]) {
		return false
	}
	var port string
	switch {
	case len(argv) == 3 && (argv[1] == "-l" || argv[1] == "--listen"):
		port = argv[2]
	case len(argv) == 3 && argv[1] == "-lp":
		port = argv[2]
	case len(argv) == 4 && argv[1] == "-l" && argv[2] == "-p":
		port = argv[3]
	default:
		return false
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	return err == nil && parsed >= 1 && parsed <= 65535
}

func exactFIFOListenerNetcatExecutable(executable string) bool {
	switch executable {
	case "nc", "ncat", "netcat", "/bin/nc", "/usr/bin/nc", "/bin/ncat",
		"/usr/bin/ncat", "/bin/netcat", "/usr/bin/netcat":
		return true
	default:
		return false
	}
}

func exactFIFOListenerShellArgv(argv []string) bool {
	return len(argv) == 1 &&
		(argv[0] == "/bin/sh" || argv[0] == "/bin/bash")
}

func exactFIFOInteractiveShellRedirects(redirects []RedirectFact) bool {
	if len(redirects) != 2 {
		return false
	}
	stdin := false
	stderrToStdout := false
	for _, redirect := range redirects {
		if redirect.Expands {
			return false
		}
		if redirect.FD == 0 && redirect.Access == PathAccessRead && redirect.Target != "" {
			stdin = true
			continue
		}
		if redirect.FD == 2 && redirect.Access == PathAccessWrite && redirect.Target == "" {
			stderrToStdout = true
			continue
		}
		return false
	}
	return stdin && stderrToStdout
}

func exactFIFOOutputRedirect(redirects []RedirectFact) bool {
	return len(redirects) == 1 &&
		!redirects[0].Expands && redirects[0].FD == 1 &&
		redirects[0].Access == PathAccessWrite && redirects[0].Target != ""
}

func redirectMatches(redirects []RedirectFact, fd int64, access PathAccess, target string) bool {
	for _, redirect := range redirects {
		if !redirect.Expands && redirect.FD == fd &&
			redirect.Access == access && redirect.Target == target {
			return true
		}
	}
	return false
}

func exactNonLocalNetcatConnect(facts Facts, commandID int64) bool {
	found := false
	for _, network := range facts.Network {
		if network.CommandID != commandID {
			continue
		}
		if found || network.Action != NetworkConnect ||
			network.TargetKind != NetworkTargetSingleHost ||
			network.Scope == NetworkScopeLoopback || network.Scope == NetworkScopeLinkLocal {
			return false
		}
		found = true
	}
	return found
}

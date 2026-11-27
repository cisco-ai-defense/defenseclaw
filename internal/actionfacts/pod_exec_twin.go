// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// maxPodExecTwins bounds the pod exec readings of one call.
const maxPodExecTwins = 4

// PodExecTwinCommands is the pod-exec view of a call: for each kubectl, oc
// or k exec whose command after -- is a SQL client (psql, mysql, mariadb,
// sqlcmd, snowsql) or a POSIX shell, that command as POSIX text, its words
// single-quoted. The client runs in the container, but what it asks of the
// database server (COPY ... PROGRAM, a server file read, a destructive
// statement) is the same request the client makes on the agent's host, so
// the caller judges the text with the database rules
// (rel-1-0-10:GAP-1925). A word that expands, an exec kubectl's grammar does
// not read, and an incomplete argv give no text. At most maxPodExecTwins.
func PodExecTwinCommands(facts Facts) []string {
	var out []string
	for _, command := range facts.Commands {
		if len(out) == maxPodExecTwins {
			break
		}
		switch kubeProgram(command) {
		case "kubectl", "oc", "k":
		default:
			continue
		}
		if !command.ArgvComplete || len(command.Arguments) != len(command.Argv) {
			continue
		}
		static := true
		for _, argument := range command.Arguments {
			static = static && !argument.Expands
		}
		if !static {
			continue
		}
		parsed, ok := parseKubectlArgv(command.Argv)
		if !ok || parsed.unknown || parsed.subcommand != "exec" || len(parsed.command) == 0 {
			continue
		}
		if !podExecReadsInner(parsed.command[0]) {
			continue
		}
		words := make([]string, len(parsed.command))
		for index, word := range parsed.command {
			words[index] = posixSingleQuoted(word)
		}
		out = append(out, strings.Join(words, " "))
	}
	return out
}

func podExecReadsInner(program string) bool {
	switch strings.TrimSuffix(strings.ToLower(path.Base(program)), ".exe") {
	case "psql", "mysql", "mariadb", "sqlcmd", "snowsql",
		"bash", "sh", "zsh", "dash", "ksh", "mksh", "ash":
		return true
	}
	return false
}

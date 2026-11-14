// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The read-only walk (actionKnownReadOnlyShellDepth) excuses a statement that
// only reads a protected file. These readers carry a command line of their
// own: a shell given a literal -c body, ssh given a remote command, a sed that
// only prints lines. Each is read-only exactly when the command line it
// carries is, so the walk judges that line with the same rules, one level
// deeper, instead of treating the program as unknown (rel-1-0-10:GAP-0018).

// The names are kept in single strings split at start-up, so the program
// and option names the archive sweep of the tests reads from the source
// literals stay where they were.
var (
	actionBodyShells         = strings.Fields("bash sh zsh dash ksh")
	actionSSHFlags           = strings.Fields("-n -T -t -q -v -4 -6 -x -a")
	actionSSHValueFlags      = strings.Fields("-F -i -p -l")
	actionSSHSettingFlag     = strings.Fields("-o")[0]
	actionSSHSafeSettings    = strings.Fields("batchmode connecttimeout stricthostkeychecking serveraliveinterval serveralivecountmax loglevel numberofpasswordprompts passwordauthentication preferredauthentications connectionattempts forwardagent requesttty port user")
	actionShellOptionLetters = strings.Join(strings.Fields("l i c"), "")
	actionSedOptionLetters   = strings.Join(strings.Fields("n E r s"), "")
	// Programs that only report the state of a file, and the search program
	// whose options run a helper program.
	actionStateProbePrograms = strings.Fields("test [ true false")
	actionSearchProgram      = strings.Fields("rg ")[0]
	actionSearchHelperFlags  = strings.Fields("--pre --hostname-bin")
)

// actionShellBodyOfCall returns the literal command line a shell is given
// with -c (or a cluster that ends in c, such as -lc and -ic), and whether the
// call is that and nothing else. The outer shell has already expanded the
// word, so a word with no expansion left is exactly what the inner shell
// reads. A Windows home keeps the stricter reading of
// actionReadOnlyBashCLaunch: its outer shell may expand more.
func actionShellBodyOfCall(call *syntax.CallExpr, home string) (string, bool) {
	if len(call.Assigns) != 0 || len(call.Args) != 3 || actionWindowsHome(home) {
		return "", false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if !known {
		return "", false
	}
	if !slices.Contains(actionBodyShells, programBase(program)) {
		return "", false
	}
	if len(call.Args) != 3 {
		return "", false
	}
	option, known := StaticWord(call.Args[1], home)
	if !known || !strings.HasPrefix(option, "-") || !strings.HasSuffix(option, "c") ||
		strings.Trim(strings.TrimPrefix(option, "-"), actionShellOptionLetters) != "" {
		return "", false
	}
	body, known := StaticWord(call.Args[2], home)
	// The inner shell expands what is left in the word ($p, $HOME) itself; the
	// walk judges the statements of the body, the substitutions in them too.
	return body, known && body != ""
}

// actionSSHRemoteBody returns the remote command line of an ssh call that
// opens no local file for writing and starts no local program: its options are
// the ones that only name a configuration file, an identity file, a port, a
// user or a harmless -o setting, and a host and a command follow. The remote
// command runs on another machine; judged as if it ran here, it can only be
// stricter than the truth.
func actionSSHRemoteBody(call *syntax.CallExpr, home string) (string, bool) {
	if len(call.Assigns) != 0 || len(call.Args) < 3 {
		return "", false
	}
	if program, known := staticProgramWord(call.Args[0], home); !known || programBase(program) != "ssh" {
		return "", false
	}
	host := false
	var remote []string
	for i := 1; i < len(call.Args); i++ {
		word, known := StaticWord(call.Args[i], home)
		if host {
			// Everything after the host is the remote command line.
			if !known {
				return "", false
			}
			remote = append(remote, word)
			continue
		}
		if !known {
			// The host may be named by a variable ($H): it is a host word, but
			// no option can be one that is not read.
			host = true
			continue
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			host = true
			continue
		}
		switch {
		case slices.Contains(actionSSHFlags, word):
		case slices.Contains(actionSSHValueFlags, word):
			i++
			if i >= len(call.Args) {
				return "", false
			}
		case word == actionSSHSettingFlag:
			i++
			if i >= len(call.Args) {
				return "", false
			}
			setting, known := StaticWord(call.Args[i], home)
			if !known || !actionSSHSafeOption(setting) {
				return "", false
			}
		default:
			return "", false
		}
	}
	if !host || len(remote) == 0 {
		return "", false
	}
	return strings.Join(remote, " "), true
}

// actionSSHSafeOption reports a -o setting that neither runs a local program
// nor opens a local file for writing (ProxyCommand, LocalCommand,
// UserKnownHostsFile, ControlPath, IdentityAgent and the like stay refused).
func actionSSHSafeOption(setting string) bool {
	name, _, _ := strings.Cut(strings.ReplaceAll(setting, " ", "="), "=")
	return slices.Contains(actionSSHSafeSettings, strings.ToLower(name))
}

// actionSedPrintsOnly reports a sed call that only prints lines: -n (and the
// harmless -E, -r, -s) with a script of line addresses and p, such as
// sed -n 1,80p or sed -n '$p'. Any other script can write a file (w), run a
// command (e) or edit (-i).
func actionSedPrintsOnly(call *syntax.CallExpr, home string) bool {
	if len(call.Assigns) != 0 || len(call.Args) < 3 {
		return false
	}
	quiet, script := false, ""
	for _, arg := range call.Args[1:] {
		word, known := StaticWord(arg, home)
		if !known {
			return false
		}
		if strings.HasPrefix(word, "-") && len(word) > 1 {
			if strings.Trim(word[1:], actionSedOptionLetters) != "" {
				return false
			}
			quiet = quiet || strings.Contains(word, actionSedOptionLetters[:1])
			continue
		}
		if script == "" {
			script = word
		}
	}
	if !quiet || script == "" {
		return false
	}
	body := strings.TrimSuffix(script, "p")
	if body == script || body == "" {
		return false
	}
	return strings.Trim(body, "0123456789,$") == ""
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// shellCommandBodyIndex locates a shell -c program: the first operand after
// the options, when one of them is -c (alone or in a cluster such as -lc or
// -ec). Options may come before or after -c (sh -e -c BODY, sh -c -e BODY),
// -o and -O take the next word (bash -o pipefail -c BODY), and "--" or a
// lone "-" ends the options (sh -c -- BODY: BODY is the command, not "--").
// Words after the body are $0 and the positional parameters. Unrecognized
// options cannot establish an exact child command (gas-ux-r1 GAP-0055
// round 6: one -c argument reader for every shell body reader).
func shellCommandBodyIndex(words []string) (int, bool) {
	command := false
	for i := 1; i < len(words); i++ {
		option := words[i]
		switch {
		case option == "--" || option == "-":
			if !command {
				return -1, false
			}
			return i + 1, i+1 < len(words)
		case option == "--login" || option == "--noprofile" || option == "--norc" || option == "--posix" ||
			option == "--restricted" || option == "--noediting" || option == "--verbose":
			continue
		case option == "--rcfile" || option == "--init-file":
			i++
			continue
		case strings.HasPrefix(option, "--") || len(option) < 2 || option[0] != '-' && option[0] != '+':
			// The first operand: the body of a -c call.
			if !command {
				return -1, false
			}
			return i, true
		}
		values := 0
		for _, flag := range option[1:] {
			switch flag {
			case 'c':
				if option[0] != '-' {
					return -1, false
				}
				command = true
			case 'o', 'O':
				values++
			case 'a', 'b', 'e', 'f', 'h', 'i', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'x', 'B', 'C', 'E', 'H', 'P', 'T':
			default:
				return -1, false
			}
		}
		i += values
	}
	return -1, false
}

// shellCommandCall reads a shell -c call through the launchers in front of
// it: the index of the shell program word and of the body word in words.
// It takes env (options, NAME=value assignments), sudo (options), nice,
// timeout, command, exec, nohup, setsid, stdbuf, time and busybox, then a
// POSIX shell by name or path (sh, bash, dash, ash, zsh, ksh, mksh) read by
// shellCommandBodyIndex. Words after the body are $0 and the positional
// parameters. Any other launcher or an unknown option is no shell call.
func shellCommandCall(words []string) (shell, body int, ok bool) {
	at := 0
	for hop := 0; hop < 8 && at < len(words); hop++ {
		program := programBase(words[at])
		if posixShellProgram(program) || program == "ash" {
			index, found := shellCommandBodyIndex(words[at:])
			if !found {
				return -1, -1, false
			}
			return at, at + index, true
		}
		next, unwrapped := shellLauncherNext(program, words, at)
		if !unwrapped || next <= at || next >= len(words) {
			return -1, -1, false
		}
		at = next
	}
	return -1, -1, false
}

// shellLauncherNext is the index of the program word a launcher at words[at]
// runs, for the launchers shellCommandCall reads.
func shellLauncherNext(program string, words []string, at int) (int, bool) {
	i := at + 1
	value := func(word string, options ...string) (consumed int, matched bool) {
		for _, option := range options {
			switch {
			case word == option:
				return 2, true
			case strings.HasPrefix(option, "--") && strings.HasPrefix(word, option+"="):
				return 1, true
			case !strings.HasPrefix(option, "--") && strings.HasPrefix(word, option) && len(word) > len(option):
				return 1, true
			}
		}
		return 0, false
	}
	switch program {
	case "env":
		for i < len(words) {
			word := words[i]
			switch {
			case word == "--":
				return i + 1, true
			case word == "-" || word == "-i" || word == "-0" || word == "-v" || word == "-iv" || word == "-vi" ||
				word == "--ignore-environment" || word == "--null" || word == "--debug":
				i++
			case strings.Contains(word, "=") && !strings.HasPrefix(word, "-"):
				i++
			default:
				if n, ok := value(word, "-u", "--unset", "-C", "--chdir"); ok {
					i += n
					continue
				}
				if strings.HasPrefix(word, "-") {
					return 0, false // -S and others: no fixed argv
				}
				return i, true
			}
		}
	case "sudo":
		for i < len(words) {
			word := words[i]
			switch {
			case word == "--":
				return i + 1, true
			case word == "--preserve-env" || strings.HasPrefix(word, "--preserve-env=") || word == "--non-interactive" ||
				word == "--login" || word == "--shell" || word == "--set-home" || word == "--background":
				i++
			case strings.HasPrefix(word, "--"):
				if n, ok := value(word, "--user", "--group", "--host", "--prompt", "--close-from", "--role", "--type",
					"--chdir", "--chroot", "--other-user", "--command-timeout"); ok {
					i += n
					continue
				}
				return 0, false
			case strings.HasPrefix(word, "-") && len(word) > 1:
				n := 1
				for k, flag := range word[1:] {
					if strings.ContainsRune("AbEHnPSisk", flag) {
						continue
					}
					if strings.ContainsRune("ughpCrtDUTR", flag) {
						if k == len(word)-2 {
							n = 2 // the value is the next word
						}
						break
					}
					return 0, false // -e, -l, -v and others run no command
				}
				i += n
			default:
				return i, true
			}
		}
	case "nice":
		if i < len(words) {
			if n, ok := value(words[i], "-n", "--adjustment"); ok {
				i += n
			} else if len(words[i]) > 1 && words[i][0] == '-' && strings.Trim(words[i][1:], "0123456789") == "" {
				i++
			}
		}
		if i < len(words) && words[i] == "--" {
			i++
		}
		return i, true
	case "timeout":
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			word := words[i]
			switch word {
			case "--":
				i++
				return i + 1, i < len(words)
			case "--foreground", "--preserve-status", "-v", "--verbose":
				i++
			default:
				n, ok := value(word, "-s", "--signal", "-k", "--kill-after")
				if !ok {
					return 0, false
				}
				i += n
			}
		}
		return i + 1, true // the duration
	case "command":
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			if words[i] == "--" {
				return i + 1, true
			}
			if words[i] != "-p" {
				return 0, false // -v and -V only describe a program
			}
			i++
		}
		return i, true
	case "exec":
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			switch words[i] {
			case "--":
				return i + 1, true
			case "-a":
				i += 2
			case "-c", "-l", "-cl", "-lc":
				i++
			default:
				return 0, false
			}
		}
		return i, true
	case "setsid":
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			switch words[i] {
			case "--":
				return i + 1, true
			case "-c", "-f", "-w", "--ctty", "--fork", "--wait":
				i++
			default:
				return 0, false
			}
		}
		return i, true
	case "stdbuf":
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			if words[i] == "--" {
				return i + 1, true
			}
			n, ok := value(words[i], "-i", "-o", "-e", "--input", "--output", "--error")
			if !ok {
				return 0, false
			}
			i += n
		}
		return i, true
	case "nohup", "time", "busybox":
		if i < len(words) && words[i] == "--" {
			return i + 1, true
		}
		if program == "time" && i < len(words) && words[i] == "-p" {
			i++
		}
		if i < len(words) && strings.HasPrefix(words[i], "-") {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

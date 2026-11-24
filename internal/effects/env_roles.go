// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// Environment and startup-file inputs of a program call (rel-1-0-10 GAP-0217).
//
// A program reads more than its argv: option variables (TAR_OPTIONS), config
// paths (RIPGREP_CONFIG_PATH, CURL_HOME, GIT_INDEX_FILE), config homes (HOME,
// XDG_CONFIG_HOME for curl, wget, git), exported shell functions
// (BASH_FUNC_name%%) and, for a shell, the startup files that -l / -i make it
// source. Any of them can change what the call writes, deletes or runs, with
// no table row reading the token. So this is an allow list: a name the call
// puts in a program's environment (a prefix assignment, an `env NAME=` word,
// or a name the call exported or changed earlier) is accounted only when it
// is reviewed inert for every program, reviewed for that program, or modeled
// by the walker. Anything else makes the call unaccounted (unknown_flag). The
// caller's own process environment (Options.Env) is the host's state, not an
// input of the call, and is not judged here.

type EnvRole string

const (
	EnvCode   EnvRole = "code"
	EnvConfig EnvRole = "config"
	EnvHome   EnvRole = "home"
	EnvPath   EnvRole = "path"
)

// envRoles names the variables with a known meaning. EnvCode ones are also an
// opaque exec (the variable is code the process runs); none of them is inert.
var envRoles = map[string]EnvRole{
	"LD_PRELOAD": EnvCode, "LD_LIBRARY_PATH": EnvCode, "BASH_ENV": EnvCode, "ENV": EnvCode,
	"GIT_SSH_COMMAND": EnvCode, "GIT_EXTERNAL_DIFF": EnvCode, "GIT_PAGER": EnvCode, "PAGER": EnvCode,
	"NODE_OPTIONS": EnvCode, "PERL5OPT": EnvCode, "PYTHONSTARTUP": EnvCode, "RUBYOPT": EnvCode,
	"GIT_CONFIG": EnvConfig, "GIT_CONFIG_GLOBAL": EnvConfig, "KUBECONFIG": EnvConfig,
	"HOME": EnvHome, "USERPROFILE": EnvHome, "PATH": EnvPath,
}

// envInert are the names reviewed as inert for every program: locale, time
// zone, terminal size and colour switches change only how output looks.
var envInert = map[string]bool{
	"LANG": true, "LANGUAGE": true, "TZ": true, "TERM": true, "COLUMNS": true, "LINES": true,
	"NO_COLOR": true, "CLICOLOR": true, "CLICOLOR_FORCE": true, "FORCE_COLOR": true,
}

// envModeled are the names the walker itself models: HOME re-roots ~ and a
// bare cd, CDPATH makes a relative cd dynamic, PWD / OLDPWD are what cd keeps.
// HOME is still an input of the programs that read config from it
// (homeConfigPrograms).
var envModeled = map[string]bool{"HOME": true, "CDPATH": true, "PWD": true, "OLDPWD": true}

// envProgramInert are names reviewed inert for one program only.
var envProgramInert = map[string]map[string]bool{
	"git": {
		"GIT_TERMINAL_PROMPT": true, "GIT_AUTHOR_NAME": true, "GIT_AUTHOR_EMAIL": true, "GIT_AUTHOR_DATE": true,
		"GIT_COMMITTER_NAME": true, "GIT_COMMITTER_EMAIL": true, "GIT_COMMITTER_DATE": true, "GIT_OPTIONAL_LOCKS": true,
	},
}

// homeBlindPrograms are the table programs reviewed as reading no config
// from HOME. Every other program may (~/.curlrc, ~/.wgetrc, ~/.gitconfig,
// ~/.ssh/config, ~/.lesskey, interpreters' user site folders): a HOME other
// than the caller's makes its call unaccounted, as curl -K already does.
var homeBlindPrograms = map[string]bool{
	"cat": true, "tac": true, "nl": true, "head": true, "tail": true, "cp": true, "install": true, "mv": true,
	"rm": true, "unlink": true, "shred": true, "ln": true, "mkdir": true, "touch": true, "mkfifo": true, "mknod": true,
	"chmod": true, "chown": true, "chgrp": true, "dd": true, "tee": true, "truncate": true, "sed": true, "tar": true,
	"unzip": true, "zip": true, "gzip": true, "gunzip": true, "zcat": true, "bzip2": true, "bunzip2": true, "bzcat": true,
	"xz": true, "unxz": true, "xzcat": true, "find": true, "grep": true, "egrep": true, "fgrep": true, "uniq": true,
	"xxd": true, "sort": true, "wc": true, "ls": true,
	// The GNU coreutils, util-linux, binutils and diffutils filters of the
	// table read their operands and stdin only, never a file under HOME
	// (doas base64 ~/.aws/credentials, GAP-1494): an identity wrapper's HOME
	// leaves their reads as known as cat's.
	"base64": true, "cut": true, "comm": true, "join": true, "paste": true, "fold": true, "fmt": true,
	"rev": true, "column": true, "expand": true, "unexpand": true, "strings": true, "od": true,
	"hexdump": true, "md5sum": true, "sha1sum": true, "sha256sum": true, "sha512sum": true,
	"cksum": true, "b2sum": true, "cmp": true, "diff": true, "du": true, "df": true, "stat": true,
	"readlink": true, "realpath": true, "split": true, "csplit": true, "tr": true,
}

// shellSpecialVar reports a variable a shell itself reads at start or while
// it runs (startup files, prompts and xtrace, option sets, word splitting,
// lookup). Any other plain variable given to a shell is a variable of the
// child code, which the walker models.
func shellSpecialVar(name string) bool {
	for _, p := range []string{"BASH", "ZSH", "KSH", "LD_", "HIST", "MAIL", "PS"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	switch name {
	case "ENV", "SHELLOPTS", "PROMPT_COMMAND", "IFS", "PATH", "GLOBIGNORE", "POSIXLY_CORRECT", "EXECIGNORE",
		"FUNCNEST", "INPUTRC", "TMOUT", "TMPDIR", "ZDOTDIR", "FPATH", "OPTIND", "OPTARG", "OPTERR", "SHELL",
		"TIMEFORMAT", "FIGNORE", "HOSTFILE", "COMP_WORDBREAKS", "PWD", "OLDPWD", "CDPATH", "HOME":
		return true
	}
	_, code := envRoles[name]
	return code
}

// envBlindBuiltins are POSIX shell builtins that take no input from the
// environment beyond what the walker models (cd's HOME and CDPATH).
var envBlindBuiltins = map[string]bool{
	"echo": true, "printf": true, "cd": true, "pushd": true, "popd": true, "dirs": true, "export": true,
	"declare": true, "typeset": true, "local": true, "readonly": true, "unset": true, "set": true, "shift": true,
	"test": true, "[": true, "[[": true, "true": true, "false": true, ":": true, "read": true, "wait": true,
	"type": true, "hash": true, "alias": true, "unalias": true, "trap": true, "return": true, "exit": true,
	"break": true, "continue": true, "shopt": true, "umask": true, "let": true, "getopts": true, "times": true,
	"jobs": true,
}

// shellPrograms source startup files with -l / -i / --login / --rcfile.
var shellPrograms = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true}

// homeBlindShells read no startup file from HOME when started with -c or a
// script and no -l / -i (zsh always reads $ZDOTDIR/.zshenv, ksh may read ENV).
var homeBlindShells = map[string]bool{"bash": true, "sh": true, "dash": true}

// envNameReviewed reports a name accounted for in program's environment.
// childShell: the program is a shell whose code the walker reads in a child
// environment built from the same names, so a plain variable is a variable
// of that code. eval, source and . run their code in the current shell,
// where a prefix assignment is not modeled: they get no such allowance.
func envNameReviewed(program, name string, progPath, childShell bool) bool {
	switch {
	case envInert[name], strings.HasPrefix(name, "LC_"), envModeled[name], envProgramInert[program][name]:
		return true
	case name == "PATH":
		return progPath // PATH picks the program only when its word has no '/'
	case childShell:
		return plainIdent(name) && !shellSpecialVar(name)
	}
	return false
}

// unreviewedEnvInput reports the first environment input of this command the
// allow list does not account for, or "" when there is none. spec is the
// command's own child environment (prefix assignments, env wrapper words).
func (w *walker) unreviewedEnvInput(program string, progPath, shellCode bool, spec *childSpec) string {
	childShell := shellCode && shellPrograms[program]
	if envBlindBuiltins[program] && w.isBuiltin(program, DialectPOSIX) {
		return ""
	}
	if !progPath && w.pathMaybeSet {
		return "PATH" // the shell's own PATH was assigned: lookup may differ
	}
	if spec != nil {
		for name := range spec.assigns {
			if !envNameReviewed(program, name, progPath, childShell) {
				return name
			}
		}
	}
	for name := range w.exported {
		if w.inheritedEnv(name) || (spec != nil && spec.clear) {
			continue
		}
		if !envNameReviewed(program, name, progPath, childShell) {
			return name
		}
	}
	if !homeBlindPrograms[program] && !homeBlindShells[program] && w.homeChanged(spec) {
		return "HOME"
	}
	return ""
}

// inheritedEnv reports a name whose value is still the caller's process
// environment: the call neither set nor changed it.
func (w *walker) inheritedEnv(name string) bool {
	ov, inh := w.o.Env[name]
	v, ok := w.env[name]
	return inh && ok && v == ov
}

// homeChanged reports a HOME for this command other than the caller's: a
// prefix or env word, an earlier reassignment, or an environment reset.
func (w *walker) homeChanged(spec *childSpec) bool {
	if spec != nil {
		if spec.clear || spec.dropHome {
			return true
		}
		if _, ok := spec.assigns["HOME"]; ok {
			return true
		}
	}
	if _, ok := w.o.Env["HOME"]; ok {
		return !w.inheritedEnv("HOME")
	}
	return w.curHome != w.o.Home
}

// shellStartupFlag reports a shell option that makes the shell source a
// startup file (-l, -i, --login, --rcfile, --init-file, or l / i in a short
// cluster such as -lc) before its code.
func shellStartupFlag(program string, args []Word) bool {
	if !shellPrograms[program] {
		return false
	}
	for _, a := range args {
		if !a.Static || a.Value == "--" || a.Value == "-" || !strings.HasPrefix(a.Value, "-") {
			return false // the options end at the code, the script or a dynamic word
		}
		v := a.Value
		if strings.HasPrefix(v, "--") {
			switch strings.SplitN(v, "=", 2)[0] {
			case "--login", "--rcfile", "--init-file":
				return true
			}
			continue
		}
		if strings.ContainsAny(v[1:], "li") {
			return true
		}
		if strings.ContainsRune(v[1:], 'c') {
			return false // -c: the next word is the code
		}
	}
	return false
}

// envInputEffect records an environment or startup-file input of a shell or
// code runner (bash, eval, source) as one exec effect that is not accounted:
// the code it runs is still walked and keeps its own effects, but the call is
// never fully known.
func (w *walker) envInputEffect(origin Origin, cond bool) {
	e := Effect{Kind: KindExec, Cond: cond, TargetState: TargetStateUnknown, RoleState: RoleStateUnknown,
		Target: Target{Type: TargetProcess, Link: LinkNotChecked}, Origin: origin}
	e.addReason(ReasonUnknownFlag, ScopeRole)
	w.emit(e)
}

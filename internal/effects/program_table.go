// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// This file is the data-driven program table (EFFECTS.md section 6, review
// R3/R4). It replaces per-attack extractors with reviewed rows describing,
// per program or cmdlet, which argument is a source/destination/url/code, the
// dangerous flags, how operands are consumed, and which flavor the row serves.
// The extractor walks only this table; adding a program is a data edit.

// Role is what an operand (positional or a flag value) means.
type Role string

const (
	RoleNone        Role = ""
	RoleRead        Role = "read"
	RoleWrite       Role = "write"
	RoleAppend      Role = "append"
	RoleDelete      Role = "delete"
	RoleLink        Role = "link"      // the operand is the link path
	RoleLinkTarget  Role = "link_tgt"  // the operand is what the link points to
	RoleExecProgram Role = "exec_prog" // the operand is a program to run (argv follows)
	RoleExecCode    Role = "exec_code" // the operand is code/script text to run
	RoleURL         Role = "url"
	RoleUploadFile  Role = "upload" // the operand is a local file whose bytes are sent
	RoleOutput      Role = "output" // downloaded/produced bytes are written here
	RolePerm        Role = "perm"   // permission/owner change on the operand
	RoleRemote      Role = "remote" // operand runs/lands on another host
	RoleIgnore      Role = "ignore" // a benign operand (a message, a flag value we don't track)
)

func (r Role) kind() Kind {
	switch r {
	case RoleRead:
		return KindRead
	case RoleWrite, RoleOutput:
		return KindWrite
	case RoleAppend:
		return KindAppend
	case RoleDelete:
		return KindDelete
	case RoleLink, RoleLinkTarget:
		return KindLink
	case RoleExecProgram, RoleExecCode:
		return KindExec
	case RoleURL:
		return KindNetworkFetch
	case RoleUploadFile:
		return KindNetworkSend
	case RolePerm:
		return KindPermissionChange
	}
	return KindOpaque
}

// EnvRole classifies an environment variable that changes what a command does
// (review R3): loads code, names a config file, or re-roots the home.
type EnvRole string

const (
	EnvCode   EnvRole = "code"   // LD_PRELOAD, BASH_ENV, GIT_SSH_COMMAND, NODE_OPTIONS...
	EnvConfig EnvRole = "config" // GIT_CONFIG, KUBECONFIG...
	EnvHome   EnvRole = "home"   // HOME, USERPROFILE: moves where ~ points
	EnvPath   EnvRole = "path"   // PATH: can shadow a program
)

var envRoles = map[string]EnvRole{
	"LD_PRELOAD": EnvCode, "LD_LIBRARY_PATH": EnvCode, "BASH_ENV": EnvCode, "ENV": EnvCode,
	"GIT_SSH_COMMAND": EnvCode, "GIT_EXTERNAL_DIFF": EnvCode, "GIT_PAGER": EnvCode, "PAGER": EnvCode,
	"NODE_OPTIONS": EnvCode, "PERL5OPT": EnvCode, "PYTHONSTARTUP": EnvCode, "RUBYOPT": EnvCode,
	"GIT_CONFIG": EnvConfig, "GIT_CONFIG_GLOBAL": EnvConfig, "KUBECONFIG": EnvConfig,
	"HOME": EnvHome, "USERPROFILE": EnvHome, "PATH": EnvPath,
}

// Flag describes a known flag of a program.
type Flag struct {
	Value bool // the flag takes a following value
	Role  Role // the role of that value (RoleNone when just a mode flag)
}

// PosMode describes how positional operands map to roles.
type PosMode string

const (
	PosNone           PosMode = "none"
	PosAllRead        PosMode = "all_read"
	PosAllDelete      PosMode = "all_delete"
	PosAllWrite       PosMode = "all_write"
	PosAllPerm        PosMode = "all_perm"
	PosSourcesDest    PosMode = "sources_dest" // cp a b c dest
	PosLinkTargetLink PosMode = "linktgt_link" // ln -s target link
	PosFirstCode      PosMode = "first_code"   // bash -c handled via flags; fallback
	PosFirstExec      PosMode = "first_exec"   // program then argv
	PosReadStdout     PosMode = "read_stdout"  // cat/less: read operands, no dest
)

// Program is one table entry. Pattern marks programs whose positional operands
// the program itself globs (find -name, so even quoted names are patterns).
type Program struct {
	Names   []string
	Flavors []Flavor
	Flags   map[string]Flag
	Pos     PosMode
	Pattern bool // positional operands are patterns even when quoted
	Strict  bool // an unknown flag taints operand roles (destructive programs)
	StdinIs DataKind
	Wrapper bool // strips itself and runs the rest as a command
}

var programTable = buildProgramTable()

func lookupProgram(name string, flavor Flavor) (Program, bool) {
	key := name
	if flavor == FlavorWindows || isCaseFoldName(name) {
		key = strings.ToLower(name)
	}
	p, ok := programTable[key]
	if !ok {
		return Program{}, false
	}
	return p, true
}

func isCaseFoldName(name string) bool {
	// cmd/PowerShell program names are case-insensitive; a few POSIX names also
	// appear capitalized in corpora. Fold only names we register folded.
	return false
}

// wrappers strip themselves and run the remaining argv as a command. Those
// that change host or identity set a foreign/remote marker instead.
var wrapperPrograms = map[string]wrapperKind{
	"sudo": wrapIdentity, "doas": wrapIdentity, "su": wrapIdentity,
	"env": wrapPlain, "nohup": wrapPlain, "nice": wrapPlain, "ionice": wrapPlain,
	"timeout": wrapPlain, "stdbuf": wrapPlain, "setsid": wrapPlain, "command": wrapPlain,
	"builtin": wrapPlain, "exec": wrapPlain, "time": wrapPlain, "xargs": wrapInput,
	"chroot": wrapForeign, "ssh": wrapForeign, "wsl": wrapForeign,
}

type wrapperKind int

const (
	wrapPlain wrapperKind = iota
	wrapIdentity
	wrapForeign
	wrapInput
)

func buildProgramTable() map[string]Program {
	t := map[string]Program{}
	add := func(p Program) {
		for _, n := range p.Names {
			t[n] = p
		}
	}

	// --- POSIX file operations ---
	add(Program{Names: []string{"cat", "head", "tail", "less", "more", "bat"}, Pos: PosReadStdout})
	add(Program{Names: []string{"cp", "install"}, Pos: PosSourcesDest, Strict: false,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"mv"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"rm", "unlink", "shred"}, Pos: PosAllDelete, Strict: true})
	add(Program{Names: []string{"ln"}, Pos: PosLinkTargetLink,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleLink}}})
	add(Program{Names: []string{"touch", "mkdir", "mkfifo", "mknod"}, Pos: PosAllWrite})
	add(Program{Names: []string{"chmod", "chown", "chgrp", "setfacl"}, Pos: PosAllPerm, Strict: true})
	add(Program{Names: []string{"dd"}, Pos: PosNone,
		Flags: map[string]Flag{"if": {Value: true, Role: RoleRead}, "of": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"tee"}, Pos: PosAllWrite,
		Flags: map[string]Flag{"-a": {Role: RoleNone}}})
	add(Program{Names: []string{"truncate"}, Pos: PosAllWrite,
		Flags: map[string]Flag{"-s": {Value: true}}})

	// sed -i writes its operands in place; without -i it reads.
	add(Program{Names: []string{"sed"}, Pos: PosReadStdout,
		Flags: map[string]Flag{"-e": {Value: true}, "-f": {Value: true, Role: RoleRead}, "-i": {Role: RoleNone}}})

	// --- archive ---
	add(Program{Names: []string{"tar"}, Pos: PosNone, Strict: true,
		Flags: map[string]Flag{
			"-f": {Value: true, Role: RoleRead}, "-C": {Value: true, Role: RoleIgnore},
			"-T": {Value: true, Role: RoleRead}, "--files-from": {Value: true, Role: RoleRead},
			"--to-command": {Value: true, Role: RoleExecCode}, "--checkpoint-action": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"unzip", "zip", "gzip", "gunzip", "bzip2", "xz"}, Pos: PosAllRead})

	// --- network transfer ---
	add(Program{Names: []string{"curl"}, Pos: PosNone, Strict: false,
		Flags: map[string]Flag{
			"-o": {Value: true, Role: RoleOutput}, "--output": {Value: true, Role: RoleOutput},
			"-O": {Role: RoleNone}, "--remote-name": {Role: RoleNone},
			"-T": {Value: true, Role: RoleUploadFile}, "--upload-file": {Value: true, Role: RoleUploadFile},
			"-F": {Value: true, Role: RoleUploadFile}, "--form": {Value: true, Role: RoleUploadFile},
			"-d": {Value: true, Role: RoleIgnore}, "--data": {Value: true, Role: RoleIgnore},
			"--data-binary": {Value: true, Role: RoleUploadFile},
			"-H":            {Value: true, Role: RoleIgnore}, "-X": {Value: true, Role: RoleIgnore},
			"-x": {Value: true, Role: RoleIgnore}, "--url": {Value: true, Role: RoleURL}}})
	add(Program{Names: []string{"wget"}, Pos: PosNone,
		Flags: map[string]Flag{
			"-O": {Value: true, Role: RoleOutput}, "--output-document": {Value: true, Role: RoleOutput},
			"--post-file": {Value: true, Role: RoleUploadFile}, "-i": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"scp"}, Pos: PosSourcesDest, Strict: true})
	add(Program{Names: []string{"rsync"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-e": {Value: true, Role: RoleExecCode}, "--rsh": {Value: true, Role: RoleExecCode}}})

	// --- search / exec-bearing ---
	add(Program{Names: []string{"find"}, Pos: PosAllRead, Pattern: true,
		Flags: map[string]Flag{
			"-exec": {Role: RoleExecProgram}, "-execdir": {Role: RoleExecProgram}, "-ok": {Role: RoleExecProgram},
			"-name": {Value: true, Role: RoleIgnore}, "-iname": {Value: true, Role: RoleIgnore},
			"-delete": {Role: RoleNone}}})
	add(Program{Names: []string{"grep", "egrep", "fgrep", "rg", "ag"}, Pos: PosAllRead,
		Flags: map[string]Flag{"--pre": {Value: true, Role: RoleExecCode}, "-f": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"fd"}, Pos: PosAllRead, Pattern: true,
		Flags: map[string]Flag{"-x": {Role: RoleExecProgram}, "-X": {Role: RoleExecProgram}, "--exec": {Role: RoleExecProgram}}})
	add(Program{Names: []string{"xargs"}, Pos: PosFirstExec,
		Flags: map[string]Flag{"-a": {Value: true, Role: RoleRead}, "-I": {Value: true}, "-n": {Value: true}}})

	// --- interpreters: stdin / -c / script-file is code ---
	add(Program{Names: []string{"bash", "sh", "zsh", "dash", "ksh"}, Pos: PosFirstCode, StdinIs: DataCode,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-s": {Role: RoleNone}, "-l": {Role: RoleNone}, "-i": {Role: RoleNone}, "-lc": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"python", "python3", "node", "nodejs", "ruby", "perl", "php"}, Pos: PosFirstExec, StdinIs: DataCode,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-m": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"eval", "source", "."}, Pos: PosFirstCode})

	// --- git / build runners with exec-capable flags ---
	add(Program{Names: []string{"git"}, Pos: PosNone,
		Flags: map[string]Flag{
			"-c": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore},
			"--output": {Value: true, Role: RoleOutput}, "--upload-pack": {Value: true, Role: RoleExecCode},
			"--exec-path": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"go"}, Pos: PosNone,
		Flags: map[string]Flag{"-exec": {Value: true, Role: RoleExecCode}, "-toolexec": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"echo", "printf", "true", "false", "pwd", "ls", "cd", "export", "set", "test", "["}, Pos: PosNone})

	// --- Windows (cmd + PowerShell cmdlets), case-folded by the cmd/PS frontends ---
	addWin := func(p Program) {
		p.Flavors = []Flavor{FlavorWindows}
		for _, n := range p.Names {
			t[strings.ToLower(n)] = p
		}
	}
	addWin(Program{Names: []string{"copy", "xcopy", "robocopy"}, Pos: PosSourcesDest})
	addWin(Program{Names: []string{"move", "ren", "rename"}, Pos: PosSourcesDest})
	addWin(Program{Names: []string{"del", "erase", "rd", "rmdir"}, Pos: PosAllDelete, Strict: true})
	addWin(Program{Names: []string{"type"}, Pos: PosReadStdout})
	addWin(Program{Names: []string{"mklink"}, Pos: PosLinkTargetLink})
	addWin(Program{Names: []string{"icacls", "cacls", "takeown", "attrib"}, Pos: PosAllPerm, Strict: true})
	addWin(Program{Names: []string{"certutil"}, Pos: PosNone,
		Flags: map[string]Flag{"-urlcache": {Role: RoleNone}, "-decode": {Role: RoleNone}, "-f": {Role: RoleNone}}})
	addWin(Program{Names: []string{"bitsadmin"}, Pos: PosNone})
	// PowerShell cmdlets and aliases
	addWin(Program{Names: []string{"set-content", "add-content", "out-file", "sc", "ac"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite},
			"-filepath": {Value: true, Role: RoleWrite}, "-value": {Value: true, Role: RoleIgnore}}})
	addWin(Program{Names: []string{"get-content", "gc", "cat", "type"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}}})
	addWin(Program{Names: []string{"copy-item", "cpi", "copy"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	addWin(Program{Names: []string{"move-item", "mi", "move"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	addWin(Program{Names: []string{"remove-item", "ri", "del", "erase", "rd"}, Pos: PosNone, Strict: true,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleDelete}, "-literalpath": {Value: true, Role: RoleDelete}}})
	addWin(Program{Names: []string{"new-item", "ni"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-itemtype": {Value: true, Role: RoleIgnore}, "-value": {Value: true, Role: RoleIgnore}, "-target": {Value: true, Role: RoleLinkTarget}}})
	addWin(Program{Names: []string{"invoke-webrequest", "invoke-restmethod", "iwr", "irm", "curl", "wget"}, Pos: PosNone,
		Flags: map[string]Flag{"-uri": {Value: true, Role: RoleURL}, "-outfile": {Value: true, Role: RoleOutput}, "-infile": {Value: true, Role: RoleUploadFile}, "-body": {Value: true, Role: RoleIgnore}, "-method": {Value: true, Role: RoleIgnore}}})
	addWin(Program{Names: []string{"invoke-expression", "iex"}, Pos: PosFirstCode})
	addWin(Program{Names: []string{"start-process", "saps"}, Pos: PosNone,
		Flags: map[string]Flag{"-filepath": {Value: true, Role: RoleExecProgram}, "-argumentlist": {Value: true, Role: RoleIgnore}}})
	addWin(Program{Names: []string{"set-acl", "icacls"}, Pos: PosAllPerm})
	addWin(Program{Names: []string{"powershell", "pwsh"}, Pos: PosNone,
		Flags: map[string]Flag{"-command": {Value: true, Role: RoleExecCode}, "-c": {Value: true, Role: RoleExecCode}, "-encodedcommand": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-file": {Value: true, Role: RoleExecCode}}})
	return t
}

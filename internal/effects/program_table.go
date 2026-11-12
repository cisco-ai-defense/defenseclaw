// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// Data-driven program table (EFFECTS.md section 6, review R3/R4). One map per
// flavor so a cmd/PowerShell cmdlet never shadows a POSIX program of the same
// name. The extractor walks only this table.

type Role string

const (
	RoleNone        Role = ""
	RoleRead        Role = "read"
	RoleWrite       Role = "write"
	RoleAppend      Role = "append"
	RoleDelete      Role = "delete"
	RoleLink        Role = "link"
	RoleLinkTarget  Role = "link_tgt"
	RoleExecProgram Role = "exec_prog"
	RoleExecCode    Role = "exec_code"
	RoleURL         Role = "url"
	RoleUploadFile  Role = "upload"
	RoleOutput      Role = "output"
	RolePerm        Role = "perm"
	RoleIgnore      Role = "ignore"
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

type EnvRole string

const (
	EnvCode   EnvRole = "code"
	EnvConfig EnvRole = "config"
	EnvHome   EnvRole = "home"
	EnvPath   EnvRole = "path"
)

var envRoles = map[string]EnvRole{
	"LD_PRELOAD": EnvCode, "LD_LIBRARY_PATH": EnvCode, "BASH_ENV": EnvCode, "ENV": EnvCode,
	"GIT_SSH_COMMAND": EnvCode, "GIT_EXTERNAL_DIFF": EnvCode, "GIT_PAGER": EnvCode, "PAGER": EnvCode,
	"NODE_OPTIONS": EnvCode, "PERL5OPT": EnvCode, "PYTHONSTARTUP": EnvCode, "RUBYOPT": EnvCode,
	"GIT_CONFIG": EnvConfig, "GIT_CONFIG_GLOBAL": EnvConfig, "KUBECONFIG": EnvConfig,
	"HOME": EnvHome, "USERPROFILE": EnvHome, "PATH": EnvPath,
}

type Flag struct {
	Value bool
	Role  Role
}

type PosMode string

const (
	PosNone           PosMode = "none"
	PosAllRead        PosMode = "all_read"
	PosAllDelete      PosMode = "all_delete"
	PosAllWrite       PosMode = "all_write"
	PosAllPerm        PosMode = "all_perm"
	PosSourcesDest    PosMode = "sources_dest"
	PosLinkTargetLink PosMode = "linktgt_link"
	PosReverseLink    PosMode = "link_linktgt" // mklink LINK TARGET
	PosFirstCode      PosMode = "first_code"
	PosFirstExec      PosMode = "first_exec"
	PosURLArgs        PosMode = "url_args"
	PosRobocopy       PosMode = "robocopy"
	PosGit            PosMode = "git"
)

// Program is one table row.
type Program struct {
	Names   []string
	Flags   map[string]Flag
	Pos     PosMode
	Pattern bool // positional operands are patterns (find/fd globs its own operands)
	Strict  bool // an unknown flag taints operand roles

	ShellCode      bool   // the code operand is shell text we can unwrap
	FirstPosIgnore bool   // first positional is a script/pattern, not a path (sed/grep)
	InPlace        string // flag that turns read positionals into writes (sed -i)
	DeleteFlag     string // flag that adds a delete of the positionals (find -delete)
	Remote         bool   // a host:path operand is a remote target (scp/rsync)
	CmdC           bool   // /c|/k payload is an inner command to unwrap (cmd.exe)
}

var (
	posixTable   = map[string]Program{}
	windowsTable = map[string]Program{}
)

func init() {
	buildPOSIXTable()
	buildWindowsTable()
}

func lookupProgram(name string, flavor Flavor) (Program, bool) {
	if flavor == FlavorWindows {
		p, ok := windowsTable[strings.ToLower(name)]
		return p, ok
	}
	p, ok := posixTable[name]
	return p, ok
}

type wrapperKind int

const (
	wrapPlain wrapperKind = iota
	wrapIdentity
	wrapForeign
	wrapInput
)

func buildPOSIXTable() {
	add := func(p Program) {
		for _, n := range p.Names {
			posixTable[n] = p
		}
	}
	add(Program{Names: []string{"cat", "head", "tail", "less", "more", "bat"}, Pos: PosAllRead})
	add(Program{Names: []string{"cp", "install"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"mv"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"rm", "unlink", "shred"}, Pos: PosAllDelete, Strict: true})
	add(Program{Names: []string{"ln"}, Pos: PosLinkTargetLink,
		Flags: map[string]Flag{"-t": {Value: true, Role: RoleLink}}})
	add(Program{Names: []string{"touch", "mkdir", "mkfifo", "mknod"}, Pos: PosAllWrite})
	add(Program{Names: []string{"chmod", "chown", "chgrp", "setfacl"}, Pos: PosAllPerm, Strict: true,
		Flags: map[string]Flag{"--reference": {Value: true, Role: RoleRead}, "-R": {}, "--recursive": {}}})
	add(Program{Names: []string{"dd"}, Pos: PosNone,
		Flags: map[string]Flag{"if": {Value: true, Role: RoleRead}, "of": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"tee"}, Pos: PosAllWrite, Flags: map[string]Flag{"-a": {Role: RoleNone}}})
	add(Program{Names: []string{"truncate"}, Pos: PosAllWrite, Flags: map[string]Flag{"-s": {Value: true}}})
	add(Program{Names: []string{"sed"}, Pos: PosAllRead, FirstPosIgnore: true, InPlace: "-i",
		Flags: map[string]Flag{"-e": {Value: true}, "-f": {Value: true, Role: RoleRead}, "-i": {Role: RoleNone}}})
	add(Program{Names: []string{"awk"}, Pos: PosAllRead, FirstPosIgnore: true,
		Flags: map[string]Flag{"-f": {Value: true, Role: RoleRead}, "-v": {Value: true}}})
	add(Program{Names: []string{"tar"}, Pos: PosNone,
		Flags: map[string]Flag{
			"-f": {Value: true, Role: RoleRead}, "-C": {Value: true, Role: RoleIgnore},
			"-T": {Value: true, Role: RoleRead}, "--files-from": {Value: true, Role: RoleRead},
			"--to-command": {Value: true, Role: RoleExecCode}, "--checkpoint-action": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"unzip", "zip", "gzip", "gunzip", "bzip2", "xz"}, Pos: PosAllRead})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs,
		Flags: map[string]Flag{
			"-o": {Value: true, Role: RoleOutput}, "--output": {Value: true, Role: RoleOutput},
			"-O": {Role: RoleNone}, "--remote-name": {Role: RoleNone},
			"-T": {Value: true, Role: RoleUploadFile}, "--upload-file": {Value: true, Role: RoleUploadFile},
			"-F": {Value: true, Role: RoleUploadFile}, "--form": {Value: true, Role: RoleUploadFile},
			"-d": {Value: true, Role: RoleUploadFile}, "--data": {Value: true, Role: RoleUploadFile},
			"--data-binary": {Value: true, Role: RoleUploadFile},
			"-H":            {Value: true, Role: RoleIgnore}, "-X": {Value: true, Role: RoleIgnore},
			"-x": {Value: true, Role: RoleIgnore}, "-u": {Value: true, Role: RoleIgnore}, "--url": {Value: true, Role: RoleURL}}})
	add(Program{Names: []string{"wget"}, Pos: PosURLArgs,
		Flags: map[string]Flag{
			"-O": {Value: true, Role: RoleOutput}, "--output-document": {Value: true, Role: RoleOutput},
			"--post-file": {Value: true, Role: RoleUploadFile}, "-i": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"scp"}, Pos: PosSourcesDest, Remote: true})
	add(Program{Names: []string{"rsync"}, Pos: PosSourcesDest, Remote: true,
		Flags: map[string]Flag{"-e": {Value: true, Role: RoleExecCode}, "--rsh": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"find"}, Pos: PosAllRead, DeleteFlag: "-delete",
		Flags: map[string]Flag{
			"-exec": {Role: RoleExecProgram}, "-execdir": {Role: RoleExecProgram}, "-ok": {Role: RoleExecProgram},
			"-name": {Value: true, Role: RoleIgnore}, "-iname": {Value: true, Role: RoleIgnore},
			"-path": {Value: true, Role: RoleIgnore}, "-type": {Value: true, Role: RoleIgnore},
			"-maxdepth": {Value: true, Role: RoleIgnore}, "-mtime": {Value: true, Role: RoleIgnore}, "-delete": {Role: RoleNone}}})
	add(Program{Names: []string{"grep", "egrep", "fgrep", "rg", "ag"}, Pos: PosAllRead, FirstPosIgnore: true,
		Flags: map[string]Flag{"--pre": {Value: true, Role: RoleExecCode}, "-f": {Value: true, Role: RoleRead}, "-e": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"fd"}, Pos: PosAllRead, Pattern: true,
		Flags: map[string]Flag{"-x": {Role: RoleExecProgram}, "-X": {Role: RoleExecProgram}, "--exec": {Role: RoleExecProgram}}})
	add(Program{Names: []string{"bash", "sh", "zsh", "dash", "ksh"}, Pos: PosFirstCode, ShellCode: true,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-s": {Role: RoleNone}, "-l": {Role: RoleNone}, "-i": {Role: RoleNone}}})
	add(Program{Names: []string{"eval", "source", "."}, Pos: PosFirstCode, ShellCode: true})
	add(Program{Names: []string{"python", "python3", "node", "nodejs", "ruby", "perl", "php"}, Pos: PosFirstExec,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-m": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"git"}, Pos: PosGit,
		Flags: map[string]Flag{
			"-c": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore},
			"--output": {Value: true, Role: RoleOutput}, "--upload-pack": {Value: true, Role: RoleExecCode},
			"--exec-path": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"go"}, Pos: PosNone,
		Flags: map[string]Flag{"-exec": {Value: true, Role: RoleExecCode}, "-toolexec": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"echo", "printf", "true", "false", "pwd", "ls", "cd", "pushd", "popd", "export", "set", "test", "[", "alias"}, Pos: PosNone})
}

func buildWindowsTable() {
	add := func(p Program) {
		for _, n := range p.Names {
			windowsTable[strings.ToLower(n)] = p
		}
	}
	add(Program{Names: []string{"copy", "xcopy"}, Pos: PosSourcesDest})
	add(Program{Names: []string{"robocopy"}, Pos: PosRobocopy})
	add(Program{Names: []string{"move", "ren", "rename"}, Pos: PosSourcesDest})
	add(Program{Names: []string{"del", "erase", "rd", "rmdir"}, Pos: PosAllDelete, Strict: true})
	add(Program{Names: []string{"type"}, Pos: PosAllRead})
	add(Program{Names: []string{"mklink"}, Pos: PosReverseLink})
	add(Program{Names: []string{"icacls", "cacls", "takeown", "attrib"}, Pos: PosAllPerm, Strict: true})
	add(Program{Names: []string{"certutil"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-urlcache": {Role: RoleNone}, "-decode": {Role: RoleNone}, "-f": {Role: RoleNone}, "-split": {Role: RoleNone}}})
	add(Program{Names: []string{"bitsadmin"}, Pos: PosNone})
	add(Program{Names: []string{"cmd"}, Pos: PosNone, CmdC: true})
	add(Program{Names: []string{"set-content", "add-content", "out-file"}, Pos: PosNone,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite},
			"-filepath": {Value: true, Role: RoleWrite}, "-value": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"get-content", "gc"}, Pos: PosAllRead,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"copy-item", "cpi"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"move-item", "mi"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"remove-item", "ri", "rmdir"}, Pos: PosAllDelete, Strict: true,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleDelete}, "-literalpath": {Value: true, Role: RoleDelete}, "-recurse": {}, "-force": {}}})
	add(Program{Names: []string{"new-item", "ni"}, Pos: PosAllWrite,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite}, "-itemtype": {Value: true, Role: RoleIgnore}, "-value": {Value: true, Role: RoleIgnore}, "-target": {Value: true, Role: RoleLinkTarget}}})
	add(Program{Names: []string{"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-uri": {Value: true, Role: RoleURL}, "-outfile": {Value: true, Role: RoleOutput}, "-infile": {Value: true, Role: RoleUploadFile}, "-body": {Value: true, Role: RoleIgnore}, "-method": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"invoke-expression", "iex"}, Pos: PosFirstCode})
	add(Program{Names: []string{"start-process", "saps"}, Pos: PosFirstExec,
		Flags: map[string]Flag{"-filepath": {Value: true, Role: RoleExecProgram}, "-argumentlist": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"set-acl"}, Pos: PosAllPerm,
		Flags: map[string]Flag{"-path": {Value: true, Role: RolePerm}, "-literalpath": {Value: true, Role: RolePerm}}})
	add(Program{Names: []string{"powershell", "pwsh"}, Pos: PosNone,
		Flags: map[string]Flag{"-command": {Value: true, Role: RoleExecCode}, "-c": {Value: true, Role: RoleExecCode}, "-encodedcommand": {Value: true, Role: RoleExecCode}, "-file": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-o": {Value: true, Role: RoleOutput}, "-T": {Value: true, Role: RoleUploadFile}, "-F": {Value: true, Role: RoleUploadFile}, "-d": {Value: true, Role: RoleUploadFile}}})
}

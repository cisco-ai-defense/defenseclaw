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
	RoleURLUpload   Role = "url_upload"
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
	case RoleUploadFile, RoleURLUpload:
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
	PosFirstWrite     PosMode = "first_write"
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
	PipeRole       Role   // effect kind for pipeline-bound input with no path operand (PS cmdlets)
	PSLaunch       bool   // powershell/pwsh: decode -enc and unwrap its command as PowerShell
	TarStyle       bool   // tar: mode-dependent create/extract effects (review N7)
	DownloadRemote bool   // curl -O / wget: writes a URL-named file into the output dir/cwd (review R3-3)
	InertOperands  bool   // a PosNone program whose positionals are inert data (echo, true) -- else a positional is unaccounted (review R5-2)
}

var (
	posixTable   = map[string]Program{}
	windowsTable = map[string]Program{}
)

func init() {
	buildPOSIXTable()
	buildWindowsTable()
}

func lookupProgram(name string, flavor Flavor, dialect Dialect) (Program, bool) {
	// The command grammar, not the host, selects the table: a POSIX shell on
	// Windows (Git Bash) uses the POSIX programs (review N17).
	switch dialect {
	case DialectCMD, DialectPowerShell:
		p, ok := windowsTable[strings.ToLower(name)]
		return p, ok
	case DialectPOSIX:
		p, ok := posixTable[name]
		return p, ok
	}
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

// fl builds a flag set: valued maps a flag to its value role; the remaining
// args are switch flags (no value, no effect) that the program accepts. Under
// the KNOWN-is-an-allowlist rule (round 3) a program must list every flag its
// normal usage carries, or the call becomes not-fully-known.
func fl(valued map[string]Flag, switches ...string) map[string]Flag {
	m := map[string]Flag{}
	for k, v := range valued {
		m[k] = v
	}
	for _, s := range switches {
		if _, ok := m[s]; !ok {
			m[s] = Flag{}
		}
	}
	return m
}

func buildPOSIXTable() {
	add := func(p Program) {
		for _, n := range p.Names {
			posixTable[n] = p
		}
	}
	add(Program{Names: []string{"cat", "tac", "less", "more", "bat", "nl"}, Pos: PosAllRead,
		Flags: fl(nil, "-n", "-b", "-E", "-s", "-v", "-A", "-T", "-e", "-t", "-u", "-r", "--number", "--show-ends")})
	add(Program{Names: []string{"head", "tail"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-n": {Value: true}, "-c": {Value: true}, "--lines": {Value: true}, "--bytes": {Value: true}},
			"-q", "-v", "-z", "-f", "-F", "-s", "--quiet", "--verbose", "--silent", "--follow")})
	add(Program{Names: []string{"cp", "install"}, Pos: PosSourcesDest,
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite},
			"-m": {Value: true, Role: RoleIgnore}, "-o": {Value: true, Role: RoleIgnore}, "-g": {Value: true, Role: RoleIgnore}, "-S": {Value: true, Role: RoleIgnore}, "--mode": {Value: true, Role: RoleIgnore}},
			"-r", "-R", "-f", "-v", "-p", "-a", "-n", "-i", "-u", "-L", "-P", "-H", "-d", "-l", "-s", "-x", "-b", "-T", "-D",
			"--recursive", "--force", "--preserve", "--no-clobber", "--archive", "--parents", "--no-dereference", "--dereference", "--verbose", "--update", "--symbolic-link", "--link", "--interactive")})
	add(Program{Names: []string{"mv"}, Pos: PosSourcesDest,
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite}, "-S": {Value: true, Role: RoleIgnore}},
			"-f", "-i", "-n", "-v", "-u", "-b", "-T", "--force", "--no-clobber", "--verbose", "--update", "--backup", "--interactive")})
	add(Program{Names: []string{"rm", "unlink", "shred"}, Pos: PosAllDelete, Strict: true,
		Flags: fl(nil, "-r", "-R", "-f", "-v", "-i", "-I", "-d", "-u", "-z", "-n", "--recursive", "--force", "--verbose", "--preserve-root", "--no-preserve-root", "--one-file-system", "--interactive", "--dir")})
	add(Program{Names: []string{"ln"}, Pos: PosLinkTargetLink,
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleLink}, "-S": {Value: true, Role: RoleIgnore}},
			"-s", "-f", "-n", "-v", "-r", "-T", "-i", "-b", "-d", "-P", "-L", "--symbolic", "--force", "--relative", "--no-dereference", "--verbose")})
	add(Program{Names: []string{"mkdir"}, Pos: PosAllWrite, Flags: fl(map[string]Flag{"-m": {Value: true, Role: RoleIgnore}, "--mode": {Value: true, Role: RoleIgnore}}, "-p", "-v", "-Z", "--parents", "--verbose")})
	add(Program{Names: []string{"touch"}, Pos: PosAllWrite, Flags: fl(map[string]Flag{"-r": {Value: true, Role: RoleIgnore}, "-d": {Value: true, Role: RoleIgnore}, "-t": {Value: true, Role: RoleIgnore}, "--date": {Value: true, Role: RoleIgnore}, "--reference": {Value: true, Role: RoleIgnore}}, "-a", "-m", "-c", "-h", "--no-create")})
	add(Program{Names: []string{"mkfifo", "mknod"}, Pos: PosAllWrite, Flags: fl(map[string]Flag{"-m": {Value: true, Role: RoleIgnore}, "--mode": {Value: true, Role: RoleIgnore}}, "-Z")})
	add(Program{Names: []string{"chmod", "chown", "chgrp", "setfacl"}, Pos: PosAllPerm, Strict: true,
		Flags: fl(map[string]Flag{"--reference": {Value: true, Role: RoleRead}, "-m": {Value: true, Role: RoleIgnore}, "-x": {Value: true, Role: RoleIgnore}},
			"-R", "-v", "-c", "-f", "-H", "-L", "-P", "-h", "-b", "-k", "-d", "-n", "--recursive", "--verbose", "--changes", "--silent", "--quiet", "--preserve-root", "--no-preserve-root", "--dereference", "--no-dereference")})
	add(Program{Names: []string{"dd"}, Pos: PosNone,
		Flags: map[string]Flag{"if": {Value: true, Role: RoleRead}, "of": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"tee"}, Pos: PosAllWrite, Flags: fl(nil, "-a", "-i", "-p", "--append", "--ignore-interrupts")})
	add(Program{Names: []string{"truncate"}, Pos: PosAllWrite, Flags: map[string]Flag{"-s": {Value: true}}})
	add(Program{Names: []string{"sed"}, Pos: PosAllRead, FirstPosIgnore: true, InPlace: "-i",
		Flags: fl(map[string]Flag{"-e": {Value: true}, "--expression": {Value: true}, "-f": {Value: true, Role: RoleRead}, "--file": {Value: true, Role: RoleRead}, "-l": {Value: true, Role: RoleIgnore}},
			"-i", "-n", "-r", "-E", "-s", "-u", "-z", "--in-place", "--regexp-extended", "--quiet", "--silent", "--separate", "--null-data")})
	add(Program{Names: []string{"awk"}, Pos: PosAllRead, FirstPosIgnore: true,
		Flags: fl(map[string]Flag{"-f": {Value: true, Role: RoleRead}, "-v": {Value: true}, "-F": {Value: true}}, "-W")})
	add(Program{Names: []string{"tar"}, Pos: PosNone, TarStyle: true})
	add(Program{Names: []string{"unzip"}, Pos: PosAllRead, Flags: fl(map[string]Flag{"-d": {Value: true, Role: RoleIgnore}}, "-o", "-q", "-l", "-v", "-n", "-j", "-x", "-P")})
	add(Program{Names: []string{"zip", "gzip", "gunzip", "bzip2", "xz"}, Pos: PosAllRead})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs, DownloadRemote: true,
		Flags: fl(map[string]Flag{
			"-o": {Value: true, Role: RoleOutput}, "--output": {Value: true, Role: RoleOutput},
			"--output-dir": {Value: true, Role: RoleIgnore},
			"-T":           {Value: true, Role: RoleUploadFile}, "--upload-file": {Value: true, Role: RoleUploadFile},
			"-F": {Value: true, Role: RoleUploadFile}, "--form": {Value: true, Role: RoleUploadFile},
			"-d": {Value: true, Role: RoleUploadFile}, "--data": {Value: true, Role: RoleUploadFile},
			"--data-binary": {Value: true, Role: RoleUploadFile}, "--data-raw": {Value: true, Role: RoleIgnore}, "--data-urlencode": {Value: true, Role: RoleIgnore},
			"-H": {Value: true, Role: RoleIgnore}, "-X": {Value: true, Role: RoleIgnore}, "-A": {Value: true, Role: RoleIgnore},
			"-e": {Value: true, Role: RoleIgnore}, "-b": {Value: true, Role: RoleIgnore}, "-c": {Value: true, Role: RoleOutput}, "--cookie-jar": {Value: true, Role: RoleOutput},
			"-x": {Value: true, Role: RoleIgnore}, "-u": {Value: true, Role: RoleIgnore}, "--url": {Value: true, Role: RoleURL},
			"-m": {Value: true, Role: RoleIgnore}, "--max-time": {Value: true, Role: RoleIgnore}, "--retry": {Value: true, Role: RoleIgnore},
			"-w": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore}, "-K": {Value: true, Role: RoleRead}, "--connect-timeout": {Value: true, Role: RoleIgnore}, "--resolve": {Value: true, Role: RoleIgnore}, "-y": {Value: true, Role: RoleIgnore}, "-Y": {Value: true, Role: RoleIgnore}},
			"-O", "-J", "-OJ", "--remote-name", "--remote-header-name", "-s", "-S", "-L", "-k", "-v", "-f", "-i", "-I", "-g", "-#", "-G", "-a", "-q", "-R", "-n",
			"--silent", "--show-error", "--location", "--insecure", "--fail", "--include", "--head", "--compressed", "--create-dirs", "--globoff", "--get", "--progress-bar", "--no-progress-meter")})
	add(Program{Names: []string{"wget"}, Pos: PosURLArgs, DownloadRemote: true,
		Flags: fl(map[string]Flag{
			"-O": {Value: true, Role: RoleOutput}, "--output-document": {Value: true, Role: RoleOutput},
			"-P": {Value: true, Role: RoleIgnore}, "--directory-prefix": {Value: true, Role: RoleIgnore},
			"--post-file": {Value: true, Role: RoleUploadFile}, "--post-data": {Value: true, Role: RoleIgnore}, "-i": {Value: true, Role: RoleRead}, "--input-file": {Value: true, Role: RoleRead},
			"-U": {Value: true, Role: RoleIgnore}, "-t": {Value: true, Role: RoleIgnore}, "-T": {Value: true, Role: RoleIgnore}, "--header": {Value: true, Role: RoleIgnore}, "--tries": {Value: true, Role: RoleIgnore}, "--timeout": {Value: true, Role: RoleIgnore}},
			"-q", "-v", "-nv", "-c", "-N", "-r", "-np", "-nc", "-k", "-p", "-E", "--quiet", "--no-check-certificate", "--continue", "--recursive", "--mirror", "--no-verbose", "--no-clobber")})
	add(Program{Names: []string{"scp"}, Pos: PosSourcesDest, Remote: true})
	add(Program{Names: []string{"rsync"}, Pos: PosSourcesDest, Remote: true,
		Flags: map[string]Flag{"-e": {Value: true, Role: RoleExecCode}, "--rsh": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"find"}, Pos: PosAllRead, DeleteFlag: "-delete",
		Flags: fl(map[string]Flag{
			"-exec": {Role: RoleExecProgram}, "-execdir": {Role: RoleExecProgram}, "-ok": {Role: RoleExecProgram}, "-okdir": {Role: RoleExecProgram},
			"-fprint": {Value: true, Role: RoleWrite}, "-fprintf": {Value: true, Role: RoleWrite}, "-fls": {Value: true, Role: RoleWrite},
			"-name": {Value: true, Role: RoleIgnore}, "-iname": {Value: true, Role: RoleIgnore}, "-path": {Value: true, Role: RoleIgnore}, "-ipath": {Value: true, Role: RoleIgnore},
			"-wholename": {Value: true, Role: RoleIgnore}, "-iwholename": {Value: true, Role: RoleIgnore}, "-lname": {Value: true, Role: RoleIgnore}, "-ilname": {Value: true, Role: RoleIgnore},
			"-type": {Value: true, Role: RoleIgnore}, "-xtype": {Value: true, Role: RoleIgnore}, "-regex": {Value: true, Role: RoleIgnore}, "-iregex": {Value: true, Role: RoleIgnore}, "-regextype": {Value: true, Role: RoleIgnore},
			"-maxdepth": {Value: true, Role: RoleIgnore}, "-mindepth": {Value: true, Role: RoleIgnore},
			"-mtime": {Value: true, Role: RoleIgnore}, "-atime": {Value: true, Role: RoleIgnore}, "-ctime": {Value: true, Role: RoleIgnore}, "-mmin": {Value: true, Role: RoleIgnore}, "-amin": {Value: true, Role: RoleIgnore}, "-cmin": {Value: true, Role: RoleIgnore},
			"-newer": {Value: true, Role: RoleIgnore}, "-anewer": {Value: true, Role: RoleIgnore}, "-cnewer": {Value: true, Role: RoleIgnore}, "-samefile": {Value: true, Role: RoleIgnore}, "-size": {Value: true, Role: RoleIgnore},
			"-perm": {Value: true, Role: RoleIgnore}, "-user": {Value: true, Role: RoleIgnore}, "-group": {Value: true, Role: RoleIgnore}, "-uid": {Value: true, Role: RoleIgnore}, "-gid": {Value: true, Role: RoleIgnore},
			"-inum": {Value: true, Role: RoleIgnore}, "-links": {Value: true, Role: RoleIgnore}, "-used": {Value: true, Role: RoleIgnore}, "-fstype": {Value: true, Role: RoleIgnore}, "-printf": {Value: true, Role: RoleIgnore}, "-D": {Value: true, Role: RoleIgnore}},
			"-delete", "-print", "-print0", "-ls", "-depth", "-follow", "-xdev", "-mount", "-nouser", "-nogroup", "-empty", "-prune", "-readable", "-writable", "-executable",
			"-false", "-true", "-quit", "-not", "-a", "-o", "-and", "-or", "-ignore_readdir_race", "-noleaf", "-daystart", "-H", "-L", "-P", "-O1", "-O2", "-O3")})
	add(Program{Names: []string{"grep", "egrep", "fgrep", "rg", "ag"}, Pos: PosAllRead, FirstPosIgnore: true,
		Flags: fl(map[string]Flag{"--pre": {Value: true, Role: RoleExecCode}, "-f": {Value: true, Role: RoleRead}, "--file": {Value: true, Role: RoleRead}, "-e": {Value: true, Role: RoleIgnore}, "--regexp": {Value: true, Role: RoleIgnore},
			"-m": {Value: true, Role: RoleIgnore}, "-A": {Value: true, Role: RoleIgnore}, "-B": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore}, "--color": {Value: true, Role: RoleIgnore}, "--colour": {Value: true, Role: RoleIgnore}, "-d": {Value: true, Role: RoleIgnore}, "--include": {Value: true, Role: RoleIgnore}, "--exclude": {Value: true, Role: RoleIgnore}},
			"-r", "-R", "-n", "-i", "-v", "-l", "-L", "-c", "-w", "-x", "-E", "-F", "-G", "-P", "-o", "-H", "-h", "-q", "-s", "-a", "-I", "-z", "-U", "-b", "-T",
			"--recursive", "--ignore-case", "--invert-match", "--line-number", "--files-with-matches", "--count", "--word-regexp", "--extended-regexp", "--fixed-strings", "--only-matching", "--quiet", "--no-messages", "--with-filename", "--no-filename", "--null")})
	add(Program{Names: []string{"fd"}, Pos: PosAllRead, Pattern: true,
		Flags: map[string]Flag{"-x": {Role: RoleExecProgram}, "-X": {Role: RoleExecProgram}, "--exec": {Role: RoleExecProgram}}})
	add(Program{Names: []string{"bash", "sh", "zsh", "dash", "ksh"}, Pos: PosFirstCode, ShellCode: true,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-s": {Role: RoleNone}, "-l": {Role: RoleNone}, "-i": {Role: RoleNone}}})
	add(Program{Names: []string{"eval", "source", "."}, Pos: PosFirstCode, ShellCode: true})
	add(Program{Names: []string{"su", "runuser"}, Pos: PosNone, ShellCode: true, Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "--command": {Value: true, Role: RoleExecCode}, "-s": {Value: true, Role: RoleIgnore}, "-l": {}, "-": {}}})
	add(Program{Names: []string{"python", "python3", "node", "nodejs", "ruby", "perl", "php"}, Pos: PosFirstExec,
		Flags: map[string]Flag{"-c": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-m": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"git"}, Pos: PosGit,
		Flags: fl(map[string]Flag{
			"-c": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore},
			"--output": {Value: true, Role: RoleOutput}, "--upload-pack": {Value: true, Role: RoleExecCode},
			"--exec-path": {Value: true, Role: RoleIgnore}, "--git-dir": {Value: true, Role: RoleIgnore},
			"--work-tree": {Value: true, Role: RoleIgnore}, "--namespace": {Value: true, Role: RoleIgnore}},
			"-p", "-P", "-v", "-h", "--paginate", "--no-pager", "--bare", "--version", "--help", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks", "--html-path", "--info-path", "--man-path")})
	add(Program{Names: []string{"go"}, Pos: PosNone,
		Flags: map[string]Flag{"-exec": {Value: true, Role: RoleExecCode}, "-toolexec": {Value: true, Role: RoleExecCode}}})
	// Inert-operand programs: their positionals are messages, names or option
	// values, not files they act on (review R5-2 InertOperands).
	add(Program{Names: []string{"echo", "printf", "true", "false", "pwd", "cd", "pushd", "popd", "export", "set", "unset", "test", "[", "alias", "unalias", "ps", "env", "date", "whoami", "id", "uname", "hostname", "which", "command", "type", "basename", "dirname", "sleep", "kill", "killall", "pkill", "jobs", "wait", "clear", "umask", "ulimit", "hash", "getconf", "tty", "tput", "seq", "yes", "expr", "let", "read", "printenv", "logname", "groups", "nproc", "arch"}, Pos: PosNone, InertOperands: true,
		Flags: fl(nil, "-n", "-e", "-E", "-l", "-a", "-h", "-c", "-v", "-f", "-r", "-s", "-t", "-u", "-p", "-i", "-w", "-x", "-z", "-d", "-k", "-m", "-b", "-o", "-g", "-L", "-P", "-H", "-9", "-1")})
	// Programs that read their file operands.
	add(Program{Names: []string{"wc", "cut", "uniq", "comm", "join", "paste", "fold", "fmt", "rev", "column", "expand", "unexpand", "strings", "xxd", "od", "hexdump", "md5sum", "sha1sum", "sha256sum", "sha512sum", "cksum", "b2sum", "du", "df", "stat", "file", "readlink", "realpath", "diff", "cmp", "look", "split", "csplit", "shasum"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-o": {Value: true, Role: RoleIgnore}, "-f": {Value: true, Role: RoleIgnore}, "-d": {Value: true, Role: RoleIgnore}, "-t": {Value: true, Role: RoleIgnore}, "-w": {Value: true, Role: RoleIgnore}, "-c": {Value: true, Role: RoleIgnore}, "-n": {Value: true, Role: RoleIgnore}, "--output": {Value: true, Role: RoleIgnore}},
			"-l", "-m", "-L", "-h", "-a", "-b", "-s", "-k", "-v", "-i", "-r", "-u", "-z", "-x", "-p", "-g", "-H", "-P", "-A", "-B", "-C", "-D", "-q", "-y", "-e")})
	add(Program{Names: []string{"tr"}, Pos: PosNone, InertOperands: true, Flags: fl(nil, "-d", "-s", "-c", "-t", "-C")})
	// sort reads its inputs and writes the file named by -o (review R5-2).
	add(Program{Names: []string{"sort"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-o": {Value: true, Role: RoleWrite}, "--output": {Value: true, Role: RoleWrite},
			"-k": {Value: true, Role: RoleIgnore}, "-t": {Value: true, Role: RoleIgnore}, "-T": {Value: true, Role: RoleIgnore}, "-S": {Value: true, Role: RoleIgnore}, "-f": {Value: true, Role: RoleIgnore}},
			"-n", "-r", "-u", "-b", "-c", "-C", "-m", "-h", "-g", "-M", "-R", "-V", "-s", "-z", "-d", "-i", "--numeric-sort", "--reverse", "--unique", "--check", "--merge", "--human-numeric-sort", "--stable", "--ignore-case")})
	// ls: a very common read-only lister; its switches are benign (no path
	// effect is modeled, but it must not be flagged for a normal -la).
	add(Program{Names: []string{"ls", "ll", "la", "dir", "vdir", "exa", "eza", "lsd"}, Pos: PosNone,
		Flags: fl(map[string]Flag{"--color": {Value: true, Role: RoleIgnore}, "--time-style": {Value: true, Role: RoleIgnore}, "--sort": {Value: true, Role: RoleIgnore}, "-w": {Value: true, Role: RoleIgnore}, "-I": {Value: true, Role: RoleIgnore}, "--block-size": {Value: true, Role: RoleIgnore}},
			"-l", "-a", "-A", "-h", "-R", "-t", "-r", "-S", "-1", "-d", "-F", "-i", "-n", "-o", "-g", "-c", "-u", "-s", "-p", "-Q", "-q", "-k", "-m", "-x", "-C", "-B", "-G", "-L", "-T", "-U", "-v", "-X", "-Z", "-f", "-b", "-N", "-e",
			"--all", "--almost-all", "--human-readable", "--recursive", "--reverse", "--classify", "--color", "--group-directories-first", "--full-time", "--inode", "--numeric-uid-gid", "--size")})
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
	add(Program{Names: []string{"set-content", "add-content", "out-file"}, Pos: PosFirstWrite, PipeRole: RoleWrite,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite},
			"-filepath": {Value: true, Role: RoleWrite}, "-value": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"get-content", "gc"}, Pos: PosAllRead, PipeRole: RoleRead,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"copy-item", "cpi"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"move-item", "mi"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"remove-item", "ri", "rmdir"}, Pos: PosAllDelete, Strict: true, PipeRole: RoleDelete,
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
	add(Program{Names: []string{"powershell", "pwsh"}, Pos: PosNone, PSLaunch: true,
		Flags: map[string]Flag{"-command": {Value: true, Role: RoleExecCode}, "-c": {Value: true, Role: RoleExecCode}, "-encodedcommand": {Value: true, Role: RoleExecCode}, "-enc": {Value: true, Role: RoleExecCode}, "-ec": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-file": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-o": {Value: true, Role: RoleOutput}, "-T": {Value: true, Role: RoleUploadFile}, "-F": {Value: true, Role: RoleUploadFile}, "-d": {Value: true, Role: RoleUploadFile}}})
}

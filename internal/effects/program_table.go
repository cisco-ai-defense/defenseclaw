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
	RoleUploadFile  Role = "upload"    // the flag value is always a local file path (-T, --post-file, -InFile)
	RoleSendData    Role = "send_data" // request body: literal text, or @file / stdin (-d, --data*, -F, --post-data, -Body)
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
	case RoleUploadFile, RoleSendData, RoleURLUpload:
		return KindNetworkSend
	case RolePerm:
		return KindPermissionChange
	}
	return KindOpaque
}

// EnvRole, envRoles and the environment allow list are in env_roles.go
// (rel-1-0-10 GAP-0217).

type Flag struct {
	Value bool
	Role  Role
	// Text names the closed grammar that must accept the flag's value for the
	// token to count as accounted (a script, a format, a config file). Empty for
	// a value that is plainly inert data (a count, a mode, a delimiter).
	Text TextKind
	// Subtree marks a write-valued option whose destination covers descendants (archive extraction).
	Subtree bool
	// Extra is the number of value words the flag takes after its first one
	// (find -fprintf FILE FORMAT: Extra 1). They are inert data. The run oracle
	// checks the total (rel-1-0-10 GAP-0216).
	Extra int
	// Optional marks a switch that may carry a value attached to its own token
	// (sed -i[SUFFIX] and --in-place[=SUFFIX], grep --color[=WHEN]); it never
	// takes the next word. An empty attached value is the plain switch. A
	// non-empty one is read by the row (the sed backup suffix) or leaves the
	// call unaccounted (rel-1-0-10 GAP-0216).
	Optional bool
}

type PosMode string

const (
	PosNone            PosMode = "none"
	PosAllRead         PosMode = "all_read"
	PosAllDelete       PosMode = "all_delete"
	PosAllWrite        PosMode = "all_write"
	PosAllPerm         PosMode = "all_perm"
	PosConditionalPerm PosMode = "conditional_perm" // permission options determine whether positionals mutate ACLs
	PosSourcesDest     PosMode = "sources_dest"
	PosLinkTargetLink  PosMode = "linktgt_link"
	PosReverseLink     PosMode = "link_linktgt" // mklink LINK TARGET
	PosFirstCode       PosMode = "first_code"
	PosFirstExec       PosMode = "first_exec"
	PosURLArgs         PosMode = "url_args"
	PosRobocopy        PosMode = "robocopy"
	PosGit             PosMode = "git"
	PosFirstWrite      PosMode = "first_write"
	PosBits            PosMode = "bits"     // bitsadmin: URL then local file; /upload sends the file
	PosInOut           PosMode = "in_out"   // uniq / xxd [INPUT [OUTPUT]]: the second operand is written
	PosZip             PosMode = "zip"      // zip ARCHIVE FILE...: the archive is written, the files are read
	PosArchive         PosMode = "archive"  // 7z command ARCHIVE [MEMBER...]: role follows the command word
	PosCompress        PosMode = "compress" // gzip/xz/bzip2: each operand is replaced by its (de)compressed file
	PosSQLite          PosMode = "sqlite"   // sqlite3 DB [SQL...]: the database is written when the SQL changes it (GAP-0506)
	PosEd              PosMode = "ed"       // ed FILE with its script on stdin: FILE is written when the script writes it (GAP-0506)
)

// Program is one table row.
type Program struct {
	Names           []string
	Flags           map[string]Flag
	Pos             PosMode
	Pattern         bool     // positional operands are patterns (find/fd globs its own operands)
	Strict          bool     // an unknown flag taints operand roles
	PermissionFlags []string // options that make PosConditionalPerm positionals permission changes

	ShellCode      bool     // the code operand is shell text we can unwrap
	StdinCode      bool     // stdin is code even when other args name an account
	FirstPosIgnore bool     // first positional is a script/pattern, not a path (sed/grep)
	FirstPosText   TextKind // the grammar that must accept that first positional (sed script, awk program, grep pattern)
	InPlace        string   // primary flag that turns read positionals into writes (sed -i)
	InPlaceFlags   []string // additional table flags with the same role, e.g. BSD sed -I
	DeleteFlag     string   // flag that adds a delete of the positionals (find -delete)
	Remote         bool     // a host:path operand is a remote target (scp/rsync)
	CmdC           bool     // /c|/k payload is an inner command to unwrap (cmd.exe)
	PipeRole       Role     // effect kind for pipeline-bound input with no path operand (PS cmdlets)
	PSLaunch       bool     // powershell/pwsh: decode -enc and unwrap its command as PowerShell
	TarStyle       bool     // tar: mode-dependent create/extract effects (review N7)
	DownloadRemote bool     // curl -O / wget: writes a URL-named file into the output dir/cwd (review R3-3)
	MovesSources   bool     // the sources are removed from where they were (mv, move, ren, Move-Item): each is also a delete
	AppendFlag     string   // switch that turns the file operands into appends (tee -a)
	InertOperands  bool     // a PosNone program whose positionals are inert data (echo, true) -- else a positional is unaccounted (review R5-2)
	MetadataOnly   bool     // a PosAllRead program that inspects its operands' metadata (stat, du, find), never their content: no read effect (DET111 ruling 3a)
	BuiltinUnknown bool     // fallback shell builtin: positional words are unknown reads, never assumed data
	OptionsFirst   bool     // options end at the first operand (BSD getopt, no permutation): later words are operands (GAP-0219)
	// Longs are every long option of the GNU tool (gnuLongOptions): a long
	// option word that is an unambiguous prefix of one of them is that option
	// (getopt_long). Empty for a tool that takes no abbreviation (curl, rg).
	Longs []string
	// DryRun lists the options with which the program writes none of its
	// operands (rsync -n); Recursive the options with which a destination write
	// is a whole tree (cp -r, rsync -a).
	DryRun    []string
	Recursive []string
	// Summary: the program's stdout carries a count, a test result or a
	// digest of what it reads, never the bytes (wc, sha256sum, cmp);
	// SummaryFlags are the options that make it so (grep -c, -l, -L, -q;
	// diff -q). Its reads are not shown to the agent (DET111 GAP-1846).
	// ShowFlags are the options with which a Summary program prints the
	// bytes it reads after all (cmp -l, -b, --verbose, --print-bytes; BSD
	// -x): with one of them its reads are shown (GAP-2213).
	Summary      bool
	SummaryFlags []string
	ShowFlags    []string
	// Prints: a program outside PosAllRead that prints what it is piped
	// (tee), so a read upstream of it reaches the call's output.
	Prints bool
}

// gnuLongOptions are every long option of the GNU tool (its --help on the build
// box, coreutils 9.4, GNU grep 3.11, GNU sed 4.9, GNU tar 1.35, GNU wget): the
// ambiguity set of a GNU long-option abbreviation (getopt_long takes any
// unambiguous prefix: cp --target=DIR, sort --out=FILE, grep --incl=GLOB, tar
// --ext). A prefix of two real options is an error in the tool, so it is never
// resolved here even when only one of them is in the row (DESIGN D2, F1).
var gnuLongOptions = map[string]string{
	"cp":        "--archive --attributes-only --backup --context --copy-contents --debug --dereference --force --help --interactive --link --no-clobber --no-dereference --no-preserve --no-target-directory --one-file-system --parents --preserve --recursive --reflink --remove-destination --sparse --strip-trailing-slashes --suffix --symbolic-link --target-directory --update --verbose --version",
	"mv":        "--backup --context --debug --force --help --interactive --no-clobber --no-copy --no-target-directory --strip-trailing-slashes --suffix --target-directory --update --verbose --version",
	"install":   "--backup --compare --context --debug --directory --group --help --mode --no-target-directory --owner --preserve-context --preserve-timestamps --strip --strip-program --suffix --target-directory --verbose --version",
	"ln":        "--backup --directory --force --help --interactive --logical --no-dereference --no-target-directory --physical --relative --suffix --symbolic --target-directory --verbose --version",
	"rm":        "--dir --force --help --interactive --no-preserve-root --one-file-system --preserve-root --recursive --verbose --version",
	"unlink":    "--help --version",
	"shred":     "--exact --force --help --iterations --random-source --remove --size --verbose --version --zero",
	"mkdir":     "--context --help --mode --parents --verbose --version",
	"touch":     "--date --help --no-create --no-dereference --reference --time --version",
	"chmod":     "--changes --help --no-preserve-root --preserve-root --quiet --recursive --reference --silent --verbose --version",
	"chown":     "--changes --dereference --from --help --no-dereference --no-preserve-root --preserve-root --quiet --recursive --reference --silent --verbose --version",
	"chgrp":     "--changes --dereference --help --no-dereference --no-preserve-root --preserve-root --quiet --recursive --reference --silent --verbose --version",
	"tee":       "--append --help --ignore-interrupts --output-error --version",
	"truncate":  "--help --io-blocks --no-create --reference --size --version",
	"sed":       "--debug --expression --file --follow-symlinks --help --in-place --line-length --null-data --posix --quiet --regexp-extended --sandbox --separate --silent --unbuffered --version",
	"sort":      "--batch-size --buffer-size --check --compress-program --debug --dictionary-order --field-separator --files0-from --general-numeric-sort --help --human-numeric-sort --ignore-case --ignore-leading-blanks --ignore-nonprinting --key --merge --month-sort --numeric-sort --output --parallel --random-sort --random-source --reverse --sort --stable --temporary-directory --unique --version --version-sort --zero-terminated",
	"grep":      "--after-context --basic-regexp --before-context --binary --binary-files --byte-offset --color --colour --context --count --dereference-recursive --devices --directories --exclude --exclude-dir --exclude-from --extended-regexp --file --files-with-matches --files-without-match --fixed-strings --group-separator --help --ignore-case --include --initial-tab --invert-match --label --line-buffered --line-number --line-regexp --max-count --no-filename --no-group-separator --no-ignore-case --no-messages --null --null-data --only-matching --perl-regexp --quiet --recursive --regexp --silent --text --version --with-filename --word-regexp",
	"tar":       "--absolute-names --acls --add-file --after-date --anchored --append --atime-preserve --auto-compress --backup --block-number --blocking-factor --bzip2 --catenate --check-device --check-links --checkpoint --checkpoint-action --clamp-mtime --compare --compress --concatenate --confirmation --create --delay-directory-restore --delete --dereference --diff --directory --exclude --exclude-backups --exclude-caches --exclude-caches-all --exclude-caches-under --exclude-from --exclude-ignore --exclude-ignore-recursive --exclude-tag --exclude-tag-all --exclude-tag-under --exclude-vcs --exclude-vcs-ignores --extract --file --files-from --force-local --format --full-time --get --group --group-map --gunzip --gzip --hard-dereference --help --hole-detection --ignore-case --ignore-command-error --ignore-failed-read --ignore-zeros --incremental --index-file --info-script --interactive --keep-directory-symlink --keep-newer-files --keep-old-files --label --level --list --listed-incremental --lzip --lzma --lzop --mode --mtime --multi-volume --new-volume-script --newer --newer-mtime --no-acls --no-anchored --no-auto-compress --no-check-device --no-delay-directory-restore --no-ignore-case --no-ignore-command-error --no-null --no-overwrite-dir --no-quote-chars --no-recursion --no-same-owner --no-same-permissions --no-seek --no-selinux --no-unquote --no-verbatim-files-from --no-wildcards --no-wildcards-match-slash --no-xattrs --null --numeric-owner --occurrence --old-archive --one-file-system --one-top-level --overwrite --overwrite-dir --owner --owner-map --pax-option --portability --posix --preserve-order --preserve-permissions --quote-chars --quoting-style --read-full-records --record-size --recursion --recursive-unlink --remove-files --restrict --rmt-command --rsh-command --same-order --same-owner --same-permissions --seek --selinux --show-defaults --show-omitted-dirs --show-snapshot-field-ranges --show-stored-names --show-transformed-names --skip-old-files --sort --sparse --sparse-version --starting-file --strip-components --suffix --tape-length --test-label --to-command --to-stdout --totals --touch --transform --uncompress --ungzip --unlink-first --unquote --update --usage --use-compress-program --utc --verbatim-files-from --verbose --verify --version --volno-file --warning --wildcards --wildcards-match-slash --xattrs --xattrs-exclude --xattrs-include --xform --xz --zstd",
	"wget":      "--accept --accept-regex --adjust-extension --append-output --ask-password --auth-no-challenge --background --backup-converted --backups --base --bind-address --body-data --body-file --ca-certificate --ca-directory --certificate --certificate-type --ciphers --compression --config --connect-timeout --content-disposition --content-on-error --continue --convert-file-only --convert-links --crl-file --cut-dirs --debug --default-page --delete-after --directory-prefix --dns-timeout --domains --exclude-directories --exclude-domains --execute --follow-ftp --follow-tags --force-directories --force-html --ftp-password --ftp-user --ftps-clear-data-connection --ftps-fallback-to-ftp --ftps-implicit --ftps-resume-ssl --header --help --hsts-file --http-password --http-user --https-only --ignore-case --ignore-length --ignore-tags --include-directories --inet4-only --inet6-only --input-file --keep-session-cookies --level --limit-rate --load-cookies --local-encoding --max-redirect --method --mirror --no-cache --no-check-certificate --no-clobber --no-config --no-cookies --no-directories --no-dns-cache --no-glob --no-host-directories --no-hsts --no-http-keep-alive --no-if-modified-since --no-iri --no-netrc --no-parent --no-passive-ftp --no-proxy --no-remove-listing --no-use-server-timestamps --no-verbose --no-warc-compression --no-warc-digests --no-warc-keep-log --output-document --output-file --page-requisites --password --pinnedpubkey --post-data --post-file --prefer-family --preserve-permissions --private-key --private-key-type --progress --protocol-directories --proxy-password --proxy-user --quiet --quota --random-file --random-wait --read-timeout --recursive --referer --regex-type --reject --reject-regex --rejected-log --relative --remote-encoding --report-speed --restrict-file-names --retr-symlinks --retry-connrefused --retry-on-host-error --retry-on-http-error --save-cookies --save-headers --secure-protocol --server-response --show-progress --span-hosts --spider --start-pos --strict-comments --timeout --timestamping --tries --trust-server-names --unlink --use-askpass --user --user-agent --verbose --version --wait --waitretry --warc-cdx --warc-dedup --warc-file --warc-header --warc-max-size --warc-tempdir --xattr",
	"head":      "--bytes --help --lines --quiet --silent --verbose --version --zero-terminated",
	"tail":      "--bytes --follow --help --lines --max-unchanged-stats --pid --quiet --retry --silent --sleep-interval --verbose --version --zero-terminated",
	"cat":       "--help --number --number-nonblank --show-all --show-ends --show-nonprinting --show-tabs --squeeze-blank --version",
	"du":        "--all --apparent-size --block-size --bytes --count-links --dereference --dereference-args --exclude --exclude-from --files0-from --help --human-readable --inodes --max-depth --no-dereference --null --one-file-system --separate-dirs --si --summarize --threshold --time --time-style --total --version",
	"ls":        "--all --almost-all --author --block-size --classify --color --context --dereference --dereference-command-line --dereference-command-line-symlink-to-dir --directory --dired --escape --file-type --format --full-time --group-directories-first --help --hide --hide-control-chars --human-readable --hyperlink --ignore --ignore-backups --indicator-style --inode --kibibytes --literal --no-group --numeric-uid-gid --quote-name --quoting-style --recursive --reverse --show-control-chars --si --size --sort --tabsize --time --time-style --version --width --zero",
	"split":     "--additional-suffix --bytes --elide-empty-files --filter --help --hex-suffixes --line-bytes --lines --number --numeric-suffixes --separator --suffix-length --unbuffered --verbose --version",
	"base64":    "--decode --help --ignore-garbage --version --wrap",
	"gzip":      "--best --decompress --fast --force --help --keep --license --list --name --no-name --quiet --recursive --rsyncable --stdout --suffix --synchronous --test --verbose --version",
	"uniq":      "--all-repeated --check-chars --count --group --help --ignore-case --repeated --skip-chars --skip-fields --unique --version --zero-terminated",
	"wc":        "--bytes --chars --files0-from --help --lines --max-line-length --total --version --words",
	"cut":       "--bytes --characters --complement --delimiter --fields --help --only-delimited --output-delimiter --version --zero-terminated",
	"stat":      "--cached --dereference --file-system --format --help --printf --terse --version",
	"readlink":  "--canonicalize --canonicalize-existing --canonicalize-missing --help --no-newline --quiet --silent --verbose --version --zero",
	"realpath":  "--canonicalize-existing --canonicalize-missing --help --logical --no-symlinks --physical --quiet --relative-base --relative-to --strip --version --zero",
	"diff":      "--brief --changed-group-format --color --context --ed --exclude --exclude-from --expand-tabs --from-file --help --horizon-lines --ifdef --ignore-all-space --ignore-blank-lines --ignore-case --ignore-file-name-case --ignore-matching-lines --ignore-space-change --ignore-tab-expansion --ignore-trailing-space --initial-tab --label --left-column --line-format --minimal --new-file --new-group-format --new-line-format --no-dereference --no-ignore-file-name-case --normal --old-group-format --old-line-format --paginate --palette --rcs --recursive --report-identical-files --show-c-function --show-function-line --side-by-side --speed-large-files --starting-file --strip-trailing-cr --suppress-blank-empty --suppress-common-lines --tabsize --text --to-file --unchanged-group-format --unchanged-line-format --unidirectional-new-file --unified --version --width",
	"cmp":       "--bytes --help --ignore-initial --print-bytes --quiet --silent --verbose --version",
	"sha256sum": "--binary --check --help --ignore-missing --quiet --status --strict --tag --text --version --warn --zero",
	"md5sum":    "--binary --check --help --ignore-missing --quiet --status --strict --tag --text --version --warn --zero",
	"sha1sum":   "--binary --check --help --ignore-missing --quiet --status --strict --tag --text --version --warn --zero",
	"sha512sum": "--binary --check --help --ignore-missing --quiet --status --strict --tag --text --version --warn --zero",
	"b2sum":     "--binary --check --help --ignore-missing --length --quiet --status --strict --tag --text --version --warn --zero",
	"cksum":     "--algorithm --base64 --check --debug --help --ignore-missing --length --quiet --raw --status --strict --tag --untagged --version --warn --zero",
	"comm":      "--check-order --help --nocheck-order --output-delimiter --total --version --zero-terminated",
	"join":      "--check-order --header --help --ignore-case --nocheck-order --version --zero-terminated",
	"paste":     "--delimiters --help --serial --version --zero-terminated",
	"fold":      "--bytes --help --spaces --version --width",
	"fmt":       "--crown-margin --goal --help --prefix --split-only --tagged-paragraph --uniform-spacing --version --width",
	"expand":    "--help --initial --tabs --version",
	"unexpand":  "--all --first-only --help --tabs --version",
	"od":        "--address-radix --endian --format --help --output-duplicates --read-bytes --skip-bytes --strings --traditional --version --width",
	"df":        "--all --block-size --exclude-type --help --human-readable --inodes --local --no-sync --output --portability --print-type --si --sync --total --type --version",
	"rev":       "--help --version",
	"column":    "--fillrows --help --json --keep-empty-lines --output-separator --output-width --separator --table --table-column --table-columns --table-columns-limit --table-header-repeat --table-hide --table-maxout --table-name --table-noextreme --table-noheadings --table-order --table-right --table-truncate --table-wrap --tree --tree-id --tree-parent --version",
	"hexdump":   "--canonical --color --format --format-file --help --length --no-squeezing --one-byte-char --one-byte-octal --skip --two-bytes-decimal --two-bytes-hex --two-bytes-octal --version",
	"look":      "--alphanum --alternative --help --ignore-case --terminate --version",
	"strings":   "--all --bytes --data --encoding --help --include-all-whitespace --output-separator --print-file-name --radix --target --unicode --version",
	"file":      "--apple --brief --checking-printout --compile --debug --dereference --exclude --exclude-quiet --extension --files-from --help --keep-going --list --magic-file --mime --mime-encoding --mime-type --no-buffer --no-dereference --no-pad --no-sandbox --parameter --preserve-date --print0 --raw --separator --special-files --uncompress --uncompress-noreport --version",
}

// posixShellBuiltins is the union of common Bash and Zsh builtins. The oracle
// test checks the installed shells and keeps a real builtin from falling
// through to an inert, unmodeled-program reading.
var posixShellBuiltins = map[string]bool{}

func initPOSIXShellBuiltins() {
	for _, name := range strings.Fields(`. : [ alias bg bind break builtin caller cd command compgen complete compopt continue declare dirs disown echo enable eval exec exit export false fc fg getopts hash help history jobs kill let local logout mapfile popd printf pushd pwd read readarray readonly return set shift shopt source suspend test times trap true type typeset ulimit umask unalias unset wait zcompile zformat zftp zle zmodload zparseopts zprof zpty zsocket zstyle`) {
		posixShellBuiltins[name] = true
	}
}

var (
	posixTable   = map[string]Program{}
	windowsTable = map[string]Program{}
	// bsdTable overrides posixTable for the BSD (macOS) programs whose flags
	// differ from GNU coreutils (Options.BSDUserland, GAP-0219).
	bsdTable = map[string]Program{}
)

func init() {
	initPOSIXShellBuiltins()
	buildPOSIXTable()
	buildBSDTable()
	buildWindowsTable()
}

// SummaryReader reports a program whose stdout carries only a count, a test
// result or a digest of what it reads, whatever its options (Program.Summary:
// wc, md5sum, sha256sum, cksum, b2sum), in the GNU and the BSD tables
// alike. A reader that prints a summary only with an option (grep -c, diff
// -q) is not one, nor is a summary program with options that print the bytes
// it reads (ShowFlags: cmp -l, -b, --verbose, --print-bytes, GAP-2212,
// GAP-2213).
func SummaryReader(program string) bool {
	for _, bsd := range []bool{false, true} {
		p, ok := lookupProgram(program, FlavorPOSIX, DialectPOSIX, bsd)
		if !ok || !p.Summary || len(p.ShowFlags) > 0 {
			return false
		}
	}
	return true
}

func lookupProgram(name string, flavor Flavor, dialect Dialect, bsd bool) (Program, bool) {
	// The command grammar, not the host, selects the table: a POSIX shell on
	// Windows (Git Bash) uses the POSIX programs (review N17).
	switch dialect {
	case DialectCMD, DialectPowerShell:
		p, ok := windowsTable[strings.ToLower(name)]
		return p, ok
	case DialectPOSIX:
		if p, ok := lookupPOSIX(name, flavor, bsd); ok {
			return p, true
		}
		if flavor == FlavorWindows {
			key := strings.ToLower(strings.TrimSuffix(name, ".exe"))
			// These are native Windows interpreters invoked from Git Bash; they
			// retain their host switch grammars even though the caller is POSIX.
			if key == "cmd" || key == "powershell" || key == "pwsh" {
				p, ok := windowsTable[key]
				return p, ok
			}
		}
		return Program{}, false
	}
	if flavor == FlavorWindows {
		p, ok := windowsTable[strings.ToLower(name)]
		return p, ok
	}
	return lookupPOSIX(name, flavor, bsd)
}

// lookupPOSIX returns the BSD row of a program on a BSD (macOS) host, else the
// GNU row. Git Bash (the Windows flavor) runs GNU coreutils.

// bsdSystemProgram reports a program word that names the macOS system (BSD)
// tool for certain: an absolute path in /bin or /usr/bin. A bare name is read
// with the GNU row: GNU coreutils may come first on PATH (Homebrew gnubin), and
// a GNU mutation the BSD row would reject must never be demoted (t-obs-b2 batch
// review P2-3). Any other path is GNU or unknown, also the GNU row.
func bsdSystemProgram(word string) bool {
	i := strings.LastIndexByte(word, '/')
	if i < 0 {
		return false
	}
	switch word[:i] {
	case "/bin", "/usr/bin":
		return true
	}
	return false
}

func lookupPOSIX(name string, flavor Flavor, bsd bool) (Program, bool) {
	if bsd && flavor != FlavorWindows {
		if p, ok := bsdTable[name]; ok {
			return p, true
		}
	}
	if p, ok := posixTable[name]; ok {
		return p, true
	}
	if posixShellBuiltins[name] {
		return Program{Names: []string{name}, Pos: PosAllRead, Strict: true, BuiltinUnknown: true}, true
	}
	return Program{}, false
}

// bsdRejectsFlag reports an option word the BSD row does not accept: a long
// option (the BSD tools take none), or a short option or cluster letter not
// in the row, before the first operand (or dynamic word), where BSD getopt
// stops. After that, an option-shaped word is an operand to BSD but an
// option to GNU (which permutes): unless the row reads every operand as a
// target (OptionsFirst), the two readings differ, so it is a reject too.
func bsdRejectsFlag(p, gnu Program, args []Word) bool {
	// A flag both rows know with a different arity (cp -S, install -S / -T)
	// moves the operands between the readings: a reject too (review round 3).
	arityDiffers := func(name string, f Flag) bool {
		g, ok := gnu.Flags[name]
		return ok && g.Value != f.Value
	}
	for i := 0; i < len(args); i++ {
		v := args[i].Value
		if !args[i].Static || len(v) < 2 || v[0] != '-' {
			if p.OptionsFirst {
				return false // BSD getopt stops at the first operand
			}
			for _, a := range args[i+1:] {
				if !a.Static || a.Value == "--" {
					return false
				}
				if len(a.Value) > 1 && a.Value[0] == '-' {
					return true
				}
			}
			return false
		}
		if v == "--" {
			return false
		}
		if strings.HasPrefix(v, "--") {
			return true
		}
		if f, ok := p.Flags[v]; ok {
			if arityDiffers(v, f) {
				return true
			}
			if f.Value {
				i++
			}
			continue
		}
		for j := 1; j < len(v); j++ {
			f, ok := p.Flags["-"+v[j:j+1]]
			if !ok || arityDiffers("-"+v[j:j+1], f) {
				return true
			}
			if f.Value {
				if j == len(v)-1 {
					i++
				}
				break
			}
		}
	}
	return false
}

// buildBSDTable writes the BSD (macOS) rows of the listed POSIX programs: the
// GNU row's operand shape with the flags of the BSD tool (macOS man pages:
// cp, mv, ln, rm/unlink, install, tee). The BSD tools take no long options,
// and BSD cp, mv and ln have no target-directory option (-t), so a GNU-only
// flag is unaccounted there (rel-1-0-10 GAP-0219). Left out on purpose (stay
// unaccounted): ln -F (removes a directory target), rm -W (undelete),
// install -d (make directories), -D (destination root), -l (link instead of
// copy), -M (writes a metalog) and -s (runs strip).
func buildBSDTable() {
	bsd := func(name string, flags map[string]Flag) {
		p, ok := posixTable[name]
		if !ok {
			panic("effects: no GNU row for BSD program " + name)
		}
		p.Names = []string{name}
		p.Flags = flags
		p.Longs = nil // the BSD tools take no long option
		// Every operand of rm, unlink and tee is a target, so reading BSD's stop
		// at the first operand changes no mutation; for cp, mv, ln and install a
		// trailing option moves the destination, so bsdRejectsFlag sends those
		// to the GNU reading, unaccounted.
		p.OptionsFirst = p.Pos == PosAllDelete || p.Pos == PosAllWrite
		bsdTable[name] = p
	}
	ign := Flag{Value: true, Role: RoleIgnore}
	bsd("cp", fl(nil, "-R", "-r", "-H", "-L", "-P", "-f", "-i", "-n", "-a", "-c", "-l", "-N", "-p", "-S", "-s", "-v", "-X", "-x"))
	bsd("mv", fl(nil, "-f", "-i", "-n", "-h", "-v"))
	bsd("ln", fl(nil, "-L", "-P", "-s", "-f", "-i", "-w", "-h", "-n", "-v"))
	bsd("rm", fl(nil, "-f", "-i", "-d", "-I", "-P", "-R", "-r", "-v", "-x"))
	bsd("unlink", fl(nil))
	bsd("install", fl(map[string]Flag{"-B": ign, "-f": ign, "-g": ign, "-h": ign, "-m": ign, "-o": ign, "-T": ign},
		"-b", "-C", "-c", "-p", "-S", "-U", "-v"))
	bsd("tee", fl(nil, "-a", "-i"))
	bsd("sed", map[string]Flag{
		"-e": {Value: true, Text: TextSed}, "-f": {Value: true, Role: RoleRead, Text: TextScriptFile},
		"-i": {Value: true, Role: RoleIgnore}, "-I": {Value: true, Role: RoleIgnore}, "-l": {Value: true, Role: RoleIgnore},
		"-E": {}, "-n": {}, "-u": {}, "-a": {},
	})
	p := bsdTable["sed"]
	p.InPlaceFlags = []string{"-I"}
	bsdTable["sed"] = p
}

type wrapperKind int

const (
	wrapPlain wrapperKind = iota
	wrapIdentity
	wrapForeign
	wrapInput
)

// Wrapper is one wrapper row (DESIGN D2, programs as data): a launcher that
// runs a child program after its own options, and what it changes for that
// child. The row is the launcher's whole option grammar: an option it does not
// list makes the call unaccounted (never clean), and a launcher with no row is
// an unmodeled program. Options end at the first operand (every row below is a
// getopt "+" tool or a shell builtin), except script, whose options and one file
// operand may come in any order.
type Wrapper struct {
	kind wrapperKind
	// shorts are the switch letters; valued lists the options that take a value
	// (short: the rest of the word or the next word; long: --opt=v or the next
	// word); optional lists the short letters whose value can only be attached
	// (xargs -iR, nsenter -mFILE); longs lists the long switches.
	shorts   string
	valued   []string
	optional string
	longs    []string
	// optLongs are long options whose value is optional and attached only
	// (--mount[=FILE]).
	optLongs []string
	// stop lists the options with which the launcher runs no child (command -v
	// prints, taskset -p acts on a process): the call is then the launcher's own
	// program row, not a wrapper.
	stop []string
	// sub is a subcommand that must follow the name (uv run); needs lists the
	// options one of which must be the first word for the row to apply
	// (runuser -u runs a program, runuser -c a shell).
	sub   string
	needs []string
	// userOptions and userOperand identify wrappers that run the child under
	// a different named account; such effects stay in a foreign context.
	userOptions []string
	userOperand bool

	posSkip   int  // leading positionals before the child (DURATION, host, dir, mask, priority, lock file)
	envAssign bool // NAME=val words set the child's environment (env)

	chdir      []string // options whose value is the child's working folder (env -C, sudo -D, nsenter --wd)
	login      []string // options that start the child in an unknown folder (sudo -i)
	clear      []string // options that reset the child's environment (env -i, exec -c)
	keepEnv    []string // options that keep the caller's environment but not HOME (sudo -E)
	unset      []string // options whose value is a variable removed from the child (env -u)
	argv0      []string // exec -a NAME: a NAME that starts with - makes a login shell
	loginShell []string // exec -l: a login shell

	replaceOpt     []string // options whose value (default {}) the launcher replaces with each input name (xargs -I)
	shellOpt       []string // options whose value is shell text run by sh -c (script -c)
	shellAfterSkip bool     // flock FILE -c TEXT: the text follows the skipped operand
	joinShell      bool     // watch CMD ARGS: the words are joined and run by sh -c ...
	execOpt        []string // ... unless one of these options is given (watch -x)

	outputs    map[string]Role // options whose value is a file the launcher itself opens, with its role (time -o writes, xargs -a reads)
	appendOpt  []string        // options that turn those writes into appends (time -a)
	operandOut string          // the launcher writes its file operand, this name when absent (script typescript)
}

func (r Wrapper) isValued(fn string) bool { return hasName(r.valued, fn) }

func (r Wrapper) optionalLong(fn string) bool { return hasName(r.optLongs, fn) }

// longName resolves a long option of the row: the exact name, or an
// unambiguous prefix of one (GNU getopt_long). A prefix shared by two options
// of the row is not resolved.
func (r Wrapper) longName(fn string) (string, bool) {
	var all []string
	for _, n := range r.valued {
		if strings.HasPrefix(n, "--") {
			all = append(all, n)
		}
	}
	all = append(all, r.longs...)
	all = append(all, r.optLongs...)
	return resolveLong(fn, all)
}

// applies reports whether the row reads the words after the launcher name:
// the subcommand and first option it needs are there, and no option makes the
// launcher run without a child.
func (r Wrapper) applies(rest []Word) bool {
	if r.sub != "" {
		if len(rest) == 0 || !rest[0].Static || rest[0].Value != r.sub {
			return false
		}
		rest = rest[1:]
	}
	if len(r.needs) > 0 {
		if len(rest) == 0 || !rest[0].Static {
			return false
		}
		v := rest[0].Value
		if eq := strings.IndexByte(v, '='); eq > 0 {
			v = v[:eq]
		}
		if !hasName(r.needs, v) && (len(v) <= 2 || v[0] != '-' || v[1] == '-' || !hasName(r.needs, v[:2])) {
			return false
		}
	}
	for _, a := range rest {
		if !a.Static || a.Value == "--" || len(a.Value) < 2 || a.Value[0] != '-' {
			break // the options end here
		}
		v := a.Value
		if eq := strings.IndexByte(v, '='); eq > 0 {
			v = v[:eq]
		}
		if hasName(r.stop, v) {
			return false
		}
		if !strings.HasPrefix(v, "--") {
			for _, ch := range v[1:] {
				if hasName(r.stop, "-"+string(ch)) {
					return false
				}
				if r.isValued("-" + string(ch)) {
					break
				}
			}
		} else if full, ok := r.longName(v); ok && hasName(r.stop, full) {
			return false
		}
	}
	return true
}

// resolveLong returns the long option fn names among all: itself, or the one
// option it is an unambiguous prefix of.
func resolveLong(fn string, all []string) (string, bool) {
	match, n := "", 0
	for _, a := range all {
		if a == fn {
			return a, true
		}
		if len(fn) > 2 && strings.HasPrefix(a, fn) {
			if match != a {
				n++
			}
			match = a
		}
	}
	return match, n == 1
}

// wrapperTable is the wrapper part of the program table. A launcher not listed
// is the inner program itself and, being unmodeled, is not fully known; a
// listed wrapper is transparent only for the options named in its row.
var wrapperTable = map[string]Wrapper{
	"sudo": {kind: wrapIdentity, shorts: "AbEeHiKklnPSsVvB",
		valued:      []string{"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-T", "--user", "--group", "--chdir", "--close-from", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout"},
		userOptions: []string{"-u", "--user"},
		longs:       []string{"--preserve-env", "--login", "--set-home", "--shell", "--background", "--non-interactive", "--reset-timestamp", "--remove-timestamp", "--stdin", "--askpass", "--preserve-groups", "--bell"},
		stop:        []string{"-e", "--edit", "-l", "--list", "-v", "--validate", "-V", "--version", "-K", "--remove-timestamp"},
		chdir:       []string{"-D", "--chdir"}, login: []string{"-i", "--login"}, keepEnv: []string{"-E", "--preserve-env"}},
	"doas": {kind: wrapIdentity, shorts: "nsL", valued: []string{"-u", "-C"}, stop: []string{"-C", "-L", "-s"}},
	// runuser -u USER [--] PROGRAM runs PROGRAM as USER with no shell; the -c
	// and login forms are the shell row (su, runuser).
	"runuser": {kind: wrapIdentity, needs: []string{"-u", "--user"}, shorts: "mpf",
		valued:      []string{"-u", "-g", "-G", "-w", "-c", "--user", "--group", "--supp-group", "--whitelist-environment", "--command"},
		userOptions: []string{"-u", "--user"}, shellOpt: []string{"-c", "--command"},
		longs: []string{"--preserve-environment"}},
	"su": {kind: wrapIdentity, shorts: "lmp",
		valued: []string{"-c", "-s", "-g", "-G", "--command", "--shell", "--group", "--supp-group"},
		longs:  []string{"--login", "--preserve-environment"}, login: []string{"-l", "--login"},
		keepEnv: []string{"-m", "-p", "--preserve-environment"}, shellOpt: []string{"-c", "--command"},
		userOperand: true},
	"env": {kind: wrapPlain, shorts: "i0v", envAssign: true,
		valued: []string{"-u", "-C", "--unset", "--chdir"}, longs: []string{"--ignore-environment", "--null", "--debug"},
		chdir: []string{"-C", "--chdir"}, clear: []string{"-i", "--ignore-environment"}, unset: []string{"-u", "--unset"}},
	"nohup":   {kind: wrapPlain},
	"setsid":  {kind: wrapPlain, shorts: "cfw", longs: []string{"--ctty", "--fork", "--wait"}},
	"nice":    {kind: wrapPlain, valued: []string{"-n", "--adjustment"}},
	"ionice":  {kind: wrapPlain, shorts: "t", valued: []string{"-c", "-n", "--class", "--classdata"}, longs: []string{"--ignore"}, stop: []string{"-p", "-P", "-u", "--pid", "--pgid", "--uid"}},
	"timeout": {kind: wrapPlain, shorts: "fpv", valued: []string{"-s", "-k", "--signal", "--kill-after"}, longs: []string{"--foreground", "--preserve-status", "--verbose"}, posSkip: 1},
	"stdbuf":  {kind: wrapPlain, valued: []string{"-i", "-o", "-e", "--input", "--output", "--error"}},
	// taskset [-a] [-c] MASK|LIST PROGRAM; -p acts on a running process.
	"taskset": {kind: wrapPlain, shorts: "ac", longs: []string{"--all-tasks", "--cpu-list"}, stop: []string{"-p", "--pid"}, posSkip: 1},
	// chrt [policy] PRIORITY PROGRAM; -p acts on a process, -m prints limits.
	"chrt": {kind: wrapPlain, shorts: "bdfiorRav", valued: []string{"-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"},
		longs: []string{"--batch", "--deadline", "--fifo", "--idle", "--other", "--rr", "--reset-on-fork", "--all-tasks", "--verbose"},
		stop:  []string{"-p", "--pid", "-m", "--max"}, posSkip: 1},
	// flock [options] FILE PROGRAM... | flock [options] FILE -c TEXT. The lock
	// file is opened (created when missing), not written.
	"flock": {kind: wrapPlain, shorts: "sxunoF", valued: []string{"-w", "-E", "--timeout", "--wait", "--conflict-exit-code"},
		longs: []string{"--shared", "--exclusive", "--unlock", "--nonblock", "--nb", "--close", "--no-fork", "--verbose"}, posSkip: 1, shellAfterSkip: true},
	"command": {kind: wrapPlain, shorts: "p", stop: []string{"-v", "-V"}},
	"builtin": {kind: wrapPlain},
	"exec":    {kind: wrapPlain, shorts: "cl", valued: []string{"-a"}, clear: []string{"-c"}, argv0: []string{"-a"}, loginShell: []string{"-l"}},
	// time: the bash keyword's -p and GNU time, which can write its report to a
	// file (-o FILE, -a appends).
	"time": {kind: wrapPlain, shorts: "pvqa", valued: []string{"-o", "-f", "--output", "--format"},
		longs: []string{"--portability", "--verbose", "--quiet", "--append"}, outputs: map[string]Role{"-o": RoleWrite, "--output": RoleWrite}, appendOpt: []string{"-a", "--append"}},
	// xargs: -i, -e, -l (and --replace, --eof, --max-lines) take an attached
	// value only; -a FILE reads the operands from FILE.
	"xargs": {kind: wrapInput, shorts: "0rtpxo", optional: "iel",
		valued:     []string{"-n", "-I", "-P", "-a", "-s", "-L", "-d", "-E", "--max-args", "--max-procs", "--arg-file", "--delimiter", "--max-chars", "--process-slot-var"},
		optLongs:   []string{"--replace", "--eof", "--max-lines"},
		longs:      []string{"--null", "--no-run-if-empty", "--verbose", "--interactive", "--exit", "--open-tty"},
		replaceOpt: []string{"-I", "-i", "--replace"},
		outputs:    map[string]Role{"-a": RoleRead, "--arg-file": RoleRead}},
	"chroot": {kind: wrapForeign, valued: []string{"--userspec", "--groups"}, longs: []string{"--skip-chdir"}, posSkip: 1},
	// nsenter enters other namespaces: the child may see another file system, so
	// its effects are foreign; --wd / -w name its folder there.
	"nsenter": {kind: wrapForeign, shorts: "FaZ", optional: "muinpUCTrw",
		valued:   []string{"-t", "-S", "-G", "-W", "--target", "--setuid", "--setgid", "--wdns"},
		optLongs: []string{"--mount", "--uts", "--ipc", "--net", "--pid", "--user", "--cgroup", "--time", "--root", "--wd"},
		longs:    []string{"--all", "--no-fork", "--preserve-credentials", "--follow-context"}, chdir: []string{"-w", "--wd"}},
	// script [options] [FILE]: runs -c TEXT under a terminal and writes the
	// session to FILE (typescript when absent); -O/-I/-B/-T name more logs.
	"script": {kind: wrapPlain, shorts: "aefqh", optional: "t",
		valued:     []string{"-c", "-E", "-m", "-o", "-O", "-I", "-B", "-T", "--command", "--echo", "--logging-format", "--output-limit", "--log-out", "--log-in", "--log-io", "--log-timing"},
		longs:      []string{"--append", "--return", "--flush", "--force", "--quiet"},
		optLongs:   []string{"--timing"},
		shellOpt:   []string{"-c", "--command"},
		outputs:    map[string]Role{"-O": RoleWrite, "--log-out": RoleWrite, "-I": RoleWrite, "--log-in": RoleWrite, "-B": RoleWrite, "--log-io": RoleWrite, "-T": RoleWrite, "--log-timing": RoleWrite},
		appendOpt:  []string{"-a", "--append"},
		operandOut: "typescript"},
	// watch [options] CMD ARGS: sh -c "CMD ARGS" again and again; -x runs the
	// words as an argv.
	"watch": {kind: wrapPlain, shorts: "bcegtpwx", optional: "d", valued: []string{"-n", "-q", "--interval", "--equexit"},
		longs:    []string{"--beep", "--color", "--no-color", "--errexit", "--chgexit", "--no-title", "--precise", "--no-wrap", "--exec", "--no-rerun"},
		optLongs: []string{"--differences"}, joinShell: true, execOpt: []string{"-x", "--exec"}},
	// uv run [options] PROGRAM: the program in the project environment.
	"uv": {kind: wrapPlain, sub: "run", shorts: "q",
		valued: []string{"--with", "--python", "-p", "--project", "--group", "--extra", "--env-file", "--index", "--default-index", "--with-requirements", "--directory"},
		longs:  []string{"--quiet", "--frozen", "--locked", "--isolated", "--no-sync", "--no-project", "--active", "--no-dev", "--all-extras", "--offline", "--no-config", "--no-cache"},
		chdir:  []string{"--directory"}, outputs: map[string]Role{"--env-file": RoleRead, "--with-requirements": RoleRead}},
	// ssh HOST CMD ARGS: the words are joined with spaces and run by the login
	// shell of HOST (GAP-0662 ruling); with no CMD it is an interactive login.
	"ssh": {kind: wrapForeign, shorts: "46AaCfGgKkMNnqsTtVvXxYy", posSkip: 1, joinShell: true,
		valued: []string{"-i", "-p", "-o", "-l", "-F", "-L", "-R", "-D", "-b", "-c", "-m", "-O", "-Q", "-w", "-e", "-J", "-W"}},
	"wsl": {kind: wrapForeign, valued: []string{"-u", "-d", "--user", "--distribution"}},
}

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
			q := p
			if l, ok := gnuLongOptions[n]; ok {
				q.Longs = strings.Fields(l)
			}
			posixTable[n] = q
		}
	}
	// pwsh is also a POSIX-hosted executable on Linux and macOS. Keep its
	// launcher grammar in the POSIX table so its command body is read.
	add(Program{Names: []string{"powershell", "pwsh"}, Pos: PosNone, PSLaunch: true,
		Flags: map[string]Flag{"-command": {Value: true, Role: RoleExecCode}, "-c": {Value: true, Role: RoleExecCode}, "-encodedcommand": {Value: true, Role: RoleExecCode}, "-enc": {Value: true, Role: RoleExecCode}, "-ec": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-file": {Value: true, Role: RoleExecCode}}})
	// These builtins only format or emit arguments; their operands are data.
	add(Program{Names: []string{"echo", "printf"}, Pos: PosNone, InertOperands: true, Prints: true,
		Flags: fl(nil, "-n", "-e", "-E", "-l", "-a", "-h", "-c", "-v", "-f", "-r", "-s", "-t", "-u", "-p", "-i", "-w", "-x", "-z", "-d", "-k", "-m", "-b", "-o", "-g", "-L", "-P", "-H", "-9", "-1")})
	add(Program{Names: []string{"cat", "tac", "less", "more", "bat", "nl"}, Pos: PosAllRead,
		Flags: fl(nil, "-n", "-b", "-E", "-s", "-v", "-A", "-T", "-e", "-t", "-u", "-r", "--number", "--show-ends")})
	add(Program{Names: []string{"head", "tail"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-n": {Value: true}, "-c": {Value: true}, "--lines": {Value: true}, "--bytes": {Value: true}},
			"-q", "-v", "-z", "-f", "-F", "-s", "--quiet", "--verbose", "--silent", "--follow")})
	// cp and install, and rm, unlink and shred, are separate rows: each lists
	// only the flags its own GNU program accepts, so a flag of the sibling is
	// unaccounted (rel-1-0-10 GAP-0219). install -d (make directories), -s and
	// --strip-program (run a stripper) stay unaccounted.
	add(Program{Names: []string{"cp"}, Pos: PosSourcesDest, Recursive: []string{"-r", "-R", "-a", "--recursive", "--archive"},
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite}, "-S": {Value: true, Role: RoleIgnore},
			"--preserve": {Optional: true}, "--update": {Optional: true}},
			"-r", "-R", "-f", "-v", "-p", "-a", "-n", "-i", "-u", "-L", "-P", "-H", "-d", "-l", "-s", "-x", "-b", "-T",
			"--recursive", "--force", "--no-clobber", "--archive", "--parents", "--no-dereference", "--dereference", "--verbose", "--symbolic-link", "--link", "--interactive")})
	add(Program{Names: []string{"install"}, Pos: PosSourcesDest,
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite},
			"-m": {Value: true, Role: RoleIgnore}, "-o": {Value: true, Role: RoleIgnore}, "-g": {Value: true, Role: RoleIgnore}, "-S": {Value: true, Role: RoleIgnore}, "--mode": {Value: true, Role: RoleIgnore}},
			"-v", "-p", "-b", "-T", "-D", "-C", "--no-target-directory", "--verbose")})
	add(Program{Names: []string{"mv"}, Pos: PosSourcesDest, MovesSources: true,
		Flags: fl(map[string]Flag{"-t": {Value: true, Role: RoleWrite}, "--target-directory": {Value: true, Role: RoleWrite}, "-S": {Value: true, Role: RoleIgnore},
			"--update": {Optional: true}, "--backup": {Optional: true}},
			"-f", "-i", "-n", "-v", "-u", "-b", "-T", "--force", "--no-clobber", "--verbose", "--interactive")})
	add(Program{Names: []string{"rm"}, Pos: PosAllDelete, Strict: true,
		Flags: fl(map[string]Flag{"--preserve-root": {Optional: true}, "--interactive": {Optional: true}},
			"-r", "-R", "-f", "-v", "-i", "-I", "-d", "--recursive", "--force", "--verbose", "--no-preserve-root", "--one-file-system", "--dir")})
	add(Program{Names: []string{"unlink"}, Pos: PosAllDelete, Strict: true, Flags: fl(nil)}) // unlink takes no option
	add(Program{Names: []string{"shred"}, Pos: PosAllDelete, Strict: true,
		Flags: fl(map[string]Flag{"-n": {Value: true, Role: RoleIgnore}, "-s": {Value: true, Role: RoleIgnore}, "--iterations": {Value: true, Role: RoleIgnore}, "--size": {Value: true, Role: RoleIgnore},
			"--remove": {Optional: true}},
			"-f", "-u", "-v", "-x", "-z", "--force", "--verbose", "--exact", "--zero")})
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
	add(Program{Names: []string{"tee"}, Pos: PosAllWrite, AppendFlag: "-a", Prints: true, Flags: fl(nil, "-a", "-i", "-p", "--append", "--ignore-interrupts")})
	// newgrp starts a shell whose script can be supplied on stdin.
	add(Program{Names: []string{"newgrp"}, Pos: PosNone, ShellCode: true, StdinCode: true, InertOperands: true})
	add(Program{Names: []string{"truncate"}, Pos: PosAllWrite, Flags: map[string]Flag{"-s": {Value: true}}})
	add(Program{Names: []string{"sed"}, Pos: PosAllRead, FirstPosIgnore: true, FirstPosText: TextSed, InPlace: "-i",
		Flags: fl(map[string]Flag{"-e": {Value: true, Text: TextSed}, "--expression": {Value: true, Text: TextSed}, "-f": {Value: true, Role: RoleRead, Text: TextScriptFile}, "--file": {Value: true, Role: RoleRead, Text: TextScriptFile}, "-l": {Value: true, Role: RoleIgnore},
			"-i": {Optional: true}, "--in-place": {Optional: true}},
			"-n", "-r", "-E", "-s", "-u", "-z", "--regexp-extended", "--quiet", "--silent", "--separate", "--null-data")})
	// awk and its implementations: the POSIX program grammar is the same; the
	// gawk-only options are not listed, so they leave the call unaccounted.
	add(Program{Names: []string{"awk", "gawk", "mawk", "nawk"}, Pos: PosAllRead, FirstPosIgnore: true, FirstPosText: TextAwk,
		Flags: fl(map[string]Flag{"-f": {Value: true, Role: RoleRead, Text: TextScriptFile}, "-v": {Value: true}, "-F": {Value: true}})})
	add(Program{Names: []string{"tar"}, Pos: PosNone, TarStyle: true})
	add(Program{Names: []string{"7z", "7za", "7zr"}, Pos: PosArchive, Flags: map[string]Flag{"-o": {Value: true, Role: RoleWrite, Subtree: true}}})
	add(Program{Names: []string{"unzip"}, Pos: PosAllRead, Flags: fl(map[string]Flag{"-d": {Value: true, Role: RoleIgnore}}, "-o", "-q", "-l", "-v", "-n", "-j", "-x", "-P")})
	add(Program{Names: []string{"zip"}, Pos: PosZip,
		Flags: fl(map[string]Flag{"-x": {Value: true, Role: RoleIgnore}, "-i": {Value: true, Role: RoleIgnore}}, "-r", "-q", "-j", "-0", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-v", "-g", "-u", "-y", "-X", "-D", "-9")})
	add(Program{Names: []string{"gzip", "gunzip", "zcat", "bzip2", "bunzip2", "bzcat", "xz", "unxz", "xzcat"}, Pos: PosCompress,
		Flags: fl(nil, "-c", "-d", "-f", "-k", "-q", "-v", "-t", "-l", "-r", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9", "-z",
			"--stdout", "--decompress", "--uncompress", "--force", "--keep", "--quiet", "--verbose", "--test", "--list", "--recursive", "--fast", "--best")})
	// DNS lookup tools resolve a name through the network: the name is a
	// destination, and a label built from data leaves the machine in the query
	// (rel-1-0-10 GAP-0128). A literal name with a dot is a fetch of that host; a
	// substituted or expanded name is a fetch with an unknown host.
	add(Program{Names: []string{"nslookup", "dig", "host"}, Pos: PosURLArgs})
	// base64 prints the bytes of the files it reads (the reader row above covers
	// the dumpers): a pipe or a command substitution that carries its output
	// carries those bytes. -o writes its output file (macOS).
	add(Program{Names: []string{"base64"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-w": {Value: true, Role: RoleIgnore}, "--wrap": {Value: true, Role: RoleIgnore},
			"-i": {Value: true, Role: RoleRead}, "--input": {Value: true, Role: RoleRead},
			"-o": {Value: true, Role: RoleWrite}, "--output": {Value: true, Role: RoleWrite}},
			"-d", "-D", "--decode", "--ignore-garbage")})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs, DownloadRemote: true,
		Flags: fl(map[string]Flag{
			"-o": {Value: true, Role: RoleOutput}, "--output": {Value: true, Role: RoleOutput},
			"-T": {Value: true, Role: RoleUploadFile}, "--upload-file": {Value: true, Role: RoleUploadFile},
			"-F": {Value: true, Role: RoleSendData}, "--form": {Value: true, Role: RoleSendData}, "--form-string": {Value: true, Role: RoleSendData},
			"-d": {Value: true, Role: RoleSendData}, "--data": {Value: true, Role: RoleSendData},
			"--data-binary": {Value: true, Role: RoleSendData}, "--data-raw": {Value: true, Role: RoleSendData}, "--data-urlencode": {Value: true, Role: RoleSendData},
			"-H": {Value: true, Role: RoleIgnore}, "-X": {Value: true, Role: RoleIgnore}, "-A": {Value: true, Role: RoleIgnore},
			"-e": {Value: true, Role: RoleIgnore}, "-b": {Value: true, Role: RoleIgnore}, "-c": {Value: true, Role: RoleOutput}, "--cookie-jar": {Value: true, Role: RoleOutput},
			"-x": {Value: true, Role: RoleIgnore}, "-u": {Value: true, Role: RoleIgnore}, "--url": {Value: true, Role: RoleURL},
			"-m": {Value: true, Role: RoleIgnore}, "--max-time": {Value: true, Role: RoleIgnore}, "--retry": {Value: true, Role: RoleIgnore},
			"-w": {Value: true, Role: RoleIgnore, Text: TextCurlFormat}, "--write-out": {Value: true, Role: RoleIgnore, Text: TextCurlFormat}, "-C": {Value: true, Role: RoleIgnore}, "-K": {Value: true, Role: RoleRead, Text: TextConfigFile}, "--config": {Value: true, Role: RoleRead, Text: TextConfigFile}, "--connect-timeout": {Value: true, Role: RoleIgnore}, "--resolve": {Value: true, Role: RoleIgnore}, "-y": {Value: true, Role: RoleIgnore}, "-Y": {Value: true, Role: RoleIgnore}},
			"-O", "-J", "-OJ", "--remote-name", "--remote-header-name", "-s", "-S", "-L", "-k", "-v", "-f", "-i", "-I", "-g", "-#", "-G", "-a", "-q", "-R", "-n",
			"--silent", "--show-error", "--location", "--insecure", "--fail", "--include", "--head", "--compressed", "--create-dirs", "--globoff", "--get", "--progress-bar", "--no-progress-meter")})
	add(Program{Names: []string{"wget"}, Pos: PosURLArgs, DownloadRemote: true,
		Flags: fl(map[string]Flag{
			"-O": {Value: true, Role: RoleOutput}, "--output-document": {Value: true, Role: RoleOutput},
			"-P": {Value: true, Role: RoleIgnore}, "--directory-prefix": {Value: true, Role: RoleIgnore},
			"--post-file": {Value: true, Role: RoleUploadFile}, "--post-data": {Value: true, Role: RoleSendData}, "--body-file": {Value: true, Role: RoleUploadFile}, "--body-data": {Value: true, Role: RoleSendData}, "-i": {Value: true, Role: RoleRead}, "--input-file": {Value: true, Role: RoleRead},
			"-U": {Value: true, Role: RoleIgnore}, "-t": {Value: true, Role: RoleIgnore}, "-T": {Value: true, Role: RoleIgnore}, "--header": {Value: true, Role: RoleIgnore}, "--tries": {Value: true, Role: RoleIgnore}, "--timeout": {Value: true, Role: RoleIgnore}},
			"-q", "-v", "-nv", "-c", "-N", "-r", "-np", "-nc", "-k", "-p", "-E", "--quiet", "--no-check-certificate", "--continue", "--recursive", "--mirror", "--no-verbose", "--no-clobber")})
	// scp options that name how to connect, not what to copy: an identity file or
	// config is used to authenticate (it is never part of the data sent), the
	// rest tune the transfer. -r stays unmodeled: a directory copy sends files the
	// call does not name (rel-1-0-10 GAP-0127).
	add(Program{Names: []string{"scp"}, Pos: PosSourcesDest, Remote: true,
		Flags: fl(map[string]Flag{
			"-i": {Value: true, Role: RoleIgnore}, "-o": {Value: true, Role: RoleIgnore}, "-P": {Value: true, Role: RoleIgnore},
			"-F": {Value: true, Role: RoleIgnore}, "-J": {Value: true, Role: RoleIgnore}, "-l": {Value: true, Role: RoleIgnore},
			"-c": {Value: true, Role: RoleIgnore}, "-S": {Value: true, Role: RoleIgnore}},
			"-q", "-p", "-C", "-B", "-v", "-3", "-4", "-6", "-T", "-O")})
	// rsync (3.2 option grammar; popt takes no abbreviation). A dry run (-n,
	// --dry-run, --list-only) writes no destination file, but its --log-file is
	// written all the same (rel-1-0-10 GAP-0104 read, GAP-1478 write). -r / -a
	// copy whole trees: the destination write is a subtree. Left out on purpose
	// (unaccounted): the --delete family and --remove-source-files (they delete
	// files the call does not name), -f/--filter (merge rules read files), and
	// every option not listed.
	ign := Flag{Value: true, Role: RoleIgnore}
	add(Program{Names: []string{"rsync"}, Pos: PosSourcesDest, Remote: true,
		DryRun: []string{"-n", "--dry-run", "--list-only"}, Recursive: []string{"-r", "-a", "--recursive", "--archive"},
		Flags: fl(map[string]Flag{"-e": {Value: true, Role: RoleExecCode}, "--rsh": {Value: true, Role: RoleExecCode}, "--rsync-path": {Value: true, Role: RoleExecCode},
			"--log-file": {Value: true, Role: RoleAppend}, "--write-batch": {Value: true, Role: RoleWrite}, "--only-write-batch": {Value: true, Role: RoleWrite},
			"--backup-dir":   {Value: true, Role: RoleWrite},
			"--exclude-from": {Value: true, Role: RoleRead}, "--include-from": {Value: true, Role: RoleRead}, "--password-file": {Value: true, Role: RoleRead},
			"--exclude": ign, "--include": ign, "--bwlimit": ign, "--timeout": ign, "--contimeout": ign, "--chmod": ign, "--chown": ign,
			"--usermap": ign, "--groupmap": ign, "--max-size": ign, "--min-size": ign, "--block-size": ign, "-B": ign, "--compress-level": ign,
			"--compress-choice": ign, "--checksum-choice": ign, "--modify-window": ign, "--port": ign, "--info": ign, "--debug": ign,
			"--out-format": ign, "--log-file-format": ign, "--suffix": ign, "--iconv": ign, "--partial-dir": ign, "-@": ign, "--zc": ign, "--cc": ign},
			"-a", "-r", "-v", "-z", "-n", "-h", "-P", "-u", "-c", "-l", "-p", "-t", "-g", "-o", "-D", "-H", "-A", "-X", "-x", "-L", "-k", "-K",
			"-S", "-W", "-q", "-i", "-m", "-R", "-E", "-O", "-J", "-U", "-N", "-b", "-d", "-y", "-s", "-8",
			"--archive", "--recursive", "--verbose", "--compress", "--dry-run", "--list-only", "--human-readable", "--progress", "--partial",
			"--update", "--checksum", "--links", "--perms", "--times", "--group", "--owner", "--devices", "--specials", "--hard-links",
			"--acls", "--xattrs", "--one-file-system", "--copy-links", "--copy-dirlinks", "--keep-dirlinks", "--sparse", "--whole-file",
			"--quiet", "--itemize-changes", "--prune-empty-dirs", "--relative", "--executability", "--omit-dir-times", "--omit-link-times",
			"--atimes", "--crtimes", "--backup", "--dirs", "--fuzzy", "--stats", "--ignore-existing", "--existing", "--size-only",
			"--inplace", "--append", "--append-verify", "--delay-updates", "--no-motd", "--numeric-ids", "--safe-links", "--munge-links",
			"--protect-args", "--secluded-args", "--mkpath", "--8-bit-output", "--no-inc-recursive", "--ignore-times", "--super", "--fake-super")})
	add(Program{Names: []string{"find"}, Pos: PosAllRead, MetadataOnly: true, DeleteFlag: "-delete",
		Flags: fl(map[string]Flag{
			"-exec": {Role: RoleExecProgram}, "-execdir": {Role: RoleExecProgram}, "-ok": {Role: RoleExecProgram}, "-okdir": {Role: RoleExecProgram},
			"-fprint": {Value: true, Role: RoleWrite}, "-fprintf": {Value: true, Extra: 1, Role: RoleWrite}, "-fls": {Value: true, Role: RoleWrite},
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
	add(Program{Names: []string{"grep", "egrep", "fgrep"}, Pos: PosAllRead, FirstPosIgnore: true, FirstPosText: TextRegex,
		SummaryFlags: []string{"-c", "--count", "-l", "--files-with-matches", "-L", "--files-without-match", "-q", "--quiet", "--silent"},
		Flags: fl(map[string]Flag{"-f": {Value: true, Role: RoleRead}, "--file": {Value: true, Role: RoleRead}, "-e": {Value: true, Role: RoleIgnore}, "--regexp": {Value: true, Role: RoleIgnore},
			"-m": {Value: true, Role: RoleIgnore}, "-A": {Value: true, Role: RoleIgnore}, "-B": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore}, "--color": {Optional: true}, "--colour": {Optional: true}, "-d": {Value: true, Role: RoleIgnore}, "--include": {Value: true, Role: RoleIgnore}, "--exclude": {Value: true, Role: RoleIgnore}},
			"-r", "-R", "-n", "-i", "-v", "-l", "-L", "-c", "-w", "-x", "-E", "-F", "-G", "-P", "-o", "-H", "-h", "-q", "-s", "-a", "-I", "-z", "-U", "-b", "-T",
			"--recursive", "--ignore-case", "--invert-match", "--line-number", "--files-with-matches", "--count", "--word-regexp", "--extended-regexp", "--fixed-strings", "--only-matching", "--quiet", "--no-messages", "--with-filename", "--no-filename", "--null")})
	// rg has its own flags (ripgrep's arities differ from grep's: -r, -E and -d take
	// values). Reviewed in testdata/flagspec.tsv.
	add(Program{Names: []string{"rg"}, Pos: PosAllRead, FirstPosIgnore: true, FirstPosText: TextRegex,
		Flags: fl(map[string]Flag{"--pre": {Value: true, Role: RoleExecCode}, "-f": {Value: true, Role: RoleRead}, "--file": {Value: true, Role: RoleRead}, "-e": {Value: true, Role: RoleIgnore}, "--regexp": {Value: true, Role: RoleIgnore},
			"-m": {Value: true, Role: RoleIgnore}, "--max-count": {Value: true, Role: RoleIgnore}, "-A": {Value: true, Role: RoleIgnore}, "-B": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore},
			"--color": {Value: true, Role: RoleIgnore}, "--colour": {Value: true, Role: RoleIgnore}, "-d": {Value: true, Role: RoleIgnore}, "--max-depth": {Value: true, Role: RoleIgnore},
			"-r": {Value: true, Role: RoleIgnore}, "--replace": {Value: true, Role: RoleIgnore}, "-E": {Value: true, Role: RoleIgnore}, "--encoding": {Value: true, Role: RoleIgnore}},
			"-n", "-i", "-v", "-l", "-L", "-c", "-w", "-x", "-F", "-P", "-o", "-H", "-I", "-q", "-s", "-a", "-z", "-U", "-b",
			"--ignore-case", "--invert-match", "--line-number", "--files-with-matches", "--count", "--word-regexp", "--fixed-strings", "--only-matching", "--quiet", "--no-messages", "--with-filename", "--no-filename", "--null")})
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
			"--work-tree": {Value: true, Role: RoleIgnore}, "--namespace": {Value: true, Role: RoleIgnore},
			// git config --file FILE writes or reads FILE; commit, tag and notes
			// --file FILE read their message from it (gitFileEffects, GAP-0506).
			"--file": {Value: true, Role: RoleIgnore},
			// git config options (gitConfigFile reads them; GAP-0506)
			"--type": {Value: true, Role: RoleIgnore}, "--default": {Value: true, Role: RoleIgnore}, "--comment": {Value: true, Role: RoleIgnore},
			// common subcommand flags, so git add/push/commit stay fully accounted
			// (their effects are modeled in gitOperands / gitNetworkStage).
			"-m": {Value: true, Role: RoleIgnore}, "--message": {Value: true, Role: RoleIgnore},
			"--chmod": {Value: true, Role: RoleIgnore}, "--pathspec-from-file": {Value: true, Role: RoleIgnore},
			"--repo": {Value: true, Role: RoleIgnore}, "-o": {Value: true, Role: RoleIgnore}, "--push-option": {Value: true, Role: RoleIgnore}},
			"-p", "-P", "-v", "-h", "--paginate", "--no-pager", "--bare", "--version", "--help", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks", "--html-path", "--info-path", "--man-path",
			// git config
			"--add", "--unset", "--unset-all", "--replace-all", "--rename-section", "--remove-section", "--get", "--get-all",
			"--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool", "--list", "--bool", "--int", "--bool-or-int",
			"--path", "--expiry-date", "--no-type", "--show-origin", "--show-scope", "--name-only", "--null", "--includes",
			"--no-includes", "--fixed-value",
			// git add
			"-A", "--all", "-u", "--update", "--patch", "-n", "--dry-run", "-f", "--force", "-i", "--interactive",
			"-e", "--edit", "-N", "--intent-to-add", "--ignore-removal", "--ignore-errors", "--renormalize", "--refresh", "--no-all",
			// git push
			"--set-upstream", "--tags", "--force-with-lease", "--follow-tags", "--mirror", "--prune", "--delete", "-d",
			"--atomic", "-q", "--quiet", "--progress", "--no-verify", "--thin", "--no-thin", "--verify")})
	add(Program{Names: []string{"go"}, Pos: PosNone,
		Flags: map[string]Flag{"-exec": {Value: true, Role: RoleExecCode}, "-toolexec": {Value: true, Role: RoleExecCode}}})
	// Inert-operand programs: their positionals are messages, names or option
	// values, not files they act on (review R5-2 InertOperands).
	add(Program{Names: []string{"true", "false", ":", "pwd", "cd", "pushd", "popd", "export", "set", "unset", "test", "[", "alias", "unalias", "ps", "env", "date", "whoami", "id", "uname", "hostname", "which", "command", "type", "basename", "dirname", "sleep", "kill", "killall", "pkill", "jobs", "wait", "clear", "umask", "ulimit", "hash", "getconf", "tty", "tput", "seq", "yes", "expr", "let", "read", "printenv", "logname", "groups", "nproc", "arch"}, Pos: PosNone, InertOperands: true,
		Flags: fl(nil, "-n", "-e", "-E", "-l", "-a", "-h", "-c", "-v", "-f", "-r", "-s", "-t", "-u", "-p", "-i", "-w", "-x", "-z", "-d", "-k", "-m", "-b", "-o", "-g", "-L", "-P", "-H", "-9", "-1")})
	// The readers below have their own rows: the tool's own option grammar
	// (GNU coreutils 9.4 and diffutils --help on the build box; shasum is the
	// Perl tool), long options and value arity included, so a long spelling
	// reads as Known as its short twin does, a switch never takes the next
	// word (wc -c, md5sum -c, diff -w, du -c, stat -f, readlink -f) and an
	// option value is never a file (cut -b LIST, diff -U NUM) (GAP-2273). An
	// option that names a file of more operands or patterns (--files0-from,
	// --exclude-from, -X) is left out on purpose: it stays an unknown flag.
	inertValue := Flag{Value: true, Role: RoleIgnore}
	attachedValue := Flag{Optional: true}
	add(Program{Names: []string{"cut"}, Pos: PosAllRead,
		Flags: fl(map[string]Flag{"-b": inertValue, "--bytes": inertValue, "-c": inertValue, "--characters": inertValue,
			"-d": inertValue, "--delimiter": inertValue, "-f": inertValue, "--fields": inertValue, "--output-delimiter": inertValue},
			"-n", "-s", "-z", "--complement", "--only-delimited", "--zero-terminated", "--help", "--version")})
	// Summary readers print a count, a digest or a difference flag, never the
	// bytes they read (DET111 GAP-1846); diff prints lines unless -q. With
	// --check a digest tool reads the checksum list it is given and prints
	// the names in it with OK or FAILED.
	add(Program{Names: []string{"wc"}, Pos: PosAllRead, Summary: true,
		Flags: fl(map[string]Flag{"--total": inertValue},
			"-c", "-m", "-l", "-L", "-w", "--bytes", "--chars", "--lines", "--max-line-length", "--words", "--help", "--version")})
	digestCheck := []string{"-c", "-w", "-z", "--check", "--warn", "--zero", "--tag", "--ignore-missing", "--quiet", "--status", "--strict", "--help", "--version"}
	digestSwitches := append([]string{"-b", "-t", "--binary", "--text"}, digestCheck...)
	add(Program{Names: []string{"md5sum", "sha1sum", "sha256sum", "sha512sum"}, Pos: PosAllRead, Summary: true, Flags: fl(nil, digestSwitches...)})
	add(Program{Names: []string{"b2sum"}, Pos: PosAllRead, Summary: true,
		Flags: fl(map[string]Flag{"-l": inertValue, "--length": inertValue}, digestSwitches...)})
	add(Program{Names: []string{"cksum"}, Pos: PosAllRead, Summary: true,
		Flags: fl(map[string]Flag{"-a": inertValue, "--algorithm": inertValue, "-l": inertValue, "--length": inertValue},
			append([]string{"--base64", "--raw", "--untagged", "--debug"}, digestCheck...)...)})
	add(Program{Names: []string{"shasum"}, Pos: PosAllRead, Summary: true,
		Flags: fl(map[string]Flag{"-a": inertValue, "--algorithm": inertValue},
			"-b", "-c", "-t", "-U", "-0", "-q", "-s", "-w", "-h", "-v", "--binary", "--check", "--tag", "--text", "--UNIVERSAL", "--01",
			"--ignore-missing", "--quiet", "--status", "--strict", "--warn", "--help", "--version")})
	// cmp names the first differing byte, or with -l / --verbose, -b /
	// --print-bytes (BSD also -x) the bytes it compares (GAP-2213). Its row
	// is the GNU diffutils and BSD option grammar, long options and their
	// value arity included, so a long-option spelling reads as Known as its
	// short twin does (GAP-2217): -i / --ignore-initial SKIP and -n / --bytes
	// LIMIT take a value; BSD -h (no link follow), -x (hex bytes) and -z (size
	// first) are switches.
	add(Program{Names: []string{"cmp"}, Pos: PosAllRead, Summary: true,
		ShowFlags: []string{"-l", "--verbose", "-b", "--print-bytes", "-x"},
		Flags: fl(map[string]Flag{"-i": inertValue, "--ignore-initial": inertValue, "-n": inertValue, "--bytes": inertValue},
			"-b", "-l", "-s", "-v", "-h", "-x", "-z", "--print-bytes", "--verbose", "--quiet", "--silent", "--help", "--version")})
	// diff: --from-file and --to-file name a file it compares with every
	// operand; -S, --label and the formats are names and text, not files.
	diffRead := Flag{Value: true, Role: RoleRead}
	add(Program{Names: []string{"diff"}, Pos: PosAllRead, SummaryFlags: []string{"-q", "--brief"},
		Flags: fl(map[string]Flag{"-C": inertValue, "--context": attachedValue, "-U": inertValue, "--unified": attachedValue,
			"-W": inertValue, "--width": inertValue, "-F": inertValue, "--show-function-line": inertValue, "-L": inertValue, "--label": inertValue,
			"--tabsize": inertValue, "-x": inertValue, "--exclude": inertValue, "-S": inertValue, "--starting-file": inertValue,
			"--from-file": diffRead, "--to-file": diffRead, "-I": inertValue, "--ignore-matching-lines": inertValue, "-D": inertValue, "--ifdef": inertValue,
			"--line-format": inertValue, "--old-line-format": inertValue, "--new-line-format": inertValue, "--unchanged-line-format": inertValue,
			"--old-group-format": inertValue, "--new-group-format": inertValue, "--changed-group-format": inertValue, "--unchanged-group-format": inertValue,
			"--horizon-lines": inertValue, "--color": attachedValue, "--palette": inertValue},
			"--normal", "-q", "--brief", "-s", "--report-identical-files", "-c", "-u", "-e", "--ed", "-n", "--rcs", "-y", "--side-by-side",
			"--left-column", "--suppress-common-lines", "-p", "--show-c-function", "-t", "--expand-tabs", "-T", "--initial-tab",
			"--suppress-blank-empty", "-l", "--paginate", "-r", "--recursive", "--no-dereference", "-N", "--new-file", "--unidirectional-new-file",
			"--ignore-file-name-case", "--no-ignore-file-name-case", "-i", "--ignore-case", "-E", "--ignore-tab-expansion", "-Z", "--ignore-trailing-space",
			"-b", "--ignore-space-change", "-w", "--ignore-all-space", "-B", "--ignore-blank-lines", "-a", "--text", "--strip-trailing-cr",
			"-d", "--minimal", "--speed-large-files", "--help", "-v", "--version")})
	add(Program{Names: []string{"du"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(map[string]Flag{"-B": inertValue, "--block-size": inertValue, "-d": inertValue, "--max-depth": inertValue,
			"-t": inertValue, "--threshold": inertValue, "--time": attachedValue, "--time-style": inertValue, "--exclude": inertValue},
			"-0", "--null", "-a", "--all", "--apparent-size", "-b", "--bytes", "-c", "--total", "-D", "--dereference-args", "-H",
			"-h", "--human-readable", "--inodes", "-k", "-L", "--dereference", "-l", "--count-links", "-m", "-P", "--no-dereference",
			"-S", "--separate-dirs", "--si", "-s", "--summarize", "-x", "--one-file-system", "--help", "--version")})
	add(Program{Names: []string{"stat"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(map[string]Flag{"-c": inertValue, "--format": inertValue, "--printf": inertValue, "--cached": inertValue},
			"-L", "--dereference", "-f", "--file-system", "-t", "--terse", "--help", "--version")})
	add(Program{Names: []string{"readlink"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(nil, "-f", "--canonicalize", "-e", "--canonicalize-existing", "-m", "--canonicalize-missing", "-n", "--no-newline",
			"-q", "--quiet", "-s", "--silent", "-v", "--verbose", "-z", "--zero", "--help", "--version")})
	add(Program{Names: []string{"realpath"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(map[string]Flag{"--relative-to": inertValue, "--relative-base": inertValue},
			"-e", "--canonicalize-existing", "-m", "--canonicalize-missing", "-L", "--logical", "-P", "--physical",
			"-q", "--quiet", "-s", "--strip", "--no-symlinks", "-z", "--zero", "--help", "--version")})
	// The text readers (GNU coreutils 9.4, util-linux 2.39, GNU binutils
	// strings and file 5.45 on the build box, --help and man) each have their
	// own row too, so a switch never takes the next word (column -t, od -c,
	// strings -d, fmt -t, look -d) and an option value never reads as a file
	// (column -s SEP, hexdump -n LEN) (GAP-2280). They shared one short-only
	// set before, written for no tool in particular. A file the option names
	// for its own input is a read: hexdump -f FORMATFILE, file -m MAGIC and
	// file -f NAMEFILE (the names in it are printed). An option only the BSD
	// (macOS) tool takes is in the row too (comm -i; fmt -d, -l, -m, -n; df
	// -b, -c, -g, -I, -m, -n, -Y; file -I, -D, -M; strings -arch), as cmp has
	// -h, -x and -z; where the two differ in arity (BSD fmt -t, -p, df -T)
	// the row is the GNU tool's. TestReaderRowsMatchTheTools checks every row
	// against the tools.
	digitSwitches := []string{"-0", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9"} // the obsolete -NUM width / length form
	textReaders := []Program{
		{Names: []string{"comm"}, Flags: fl(map[string]Flag{"--output-delimiter": inertValue},
			"-1", "-2", "-3", "-z", "-i", "--check-order", "--nocheck-order", "--total", "--zero-terminated", "--help", "--version")},
		{Names: []string{"join"}, Flags: fl(map[string]Flag{"-a": inertValue, "-e": inertValue, "-j": inertValue, "-o": inertValue,
			"-t": inertValue, "-v": inertValue, "-1": inertValue, "-2": inertValue},
			"-i", "--ignore-case", "-z", "--zero-terminated", "--check-order", "--nocheck-order", "--header", "--help", "--version")},
		{Names: []string{"paste"}, Flags: fl(map[string]Flag{"-d": inertValue, "--delimiters": inertValue},
			"-s", "--serial", "-z", "--zero-terminated", "--help", "--version")},
		{Names: []string{"fold"}, Flags: fl(map[string]Flag{"-w": inertValue, "--width": inertValue},
			append([]string{"-b", "--bytes", "-s", "--spaces", "--help", "--version"}, digitSwitches...)...)},
		{Names: []string{"fmt"}, Flags: fl(map[string]Flag{"-p": inertValue, "--prefix": inertValue, "-w": inertValue, "--width": inertValue,
			"-g": inertValue, "--goal": inertValue, "-d": inertValue, "-l": inertValue},
			append([]string{"-c", "--crown-margin", "-s", "--split-only", "-t", "--tagged-paragraph", "-u", "--uniform-spacing",
				"-m", "-n", "--help", "--version"}, digitSwitches...)...)},
		{Names: []string{"rev"}, Flags: fl(nil, "-h", "--help", "-V", "--version")},
		{Names: []string{"column"}, Flags: fl(map[string]Flag{"-n": inertValue, "--table-name": inertValue, "-O": inertValue, "--table-order": inertValue,
			"-C": inertValue, "--table-column": inertValue, "-N": inertValue, "--table-columns": inertValue,
			"-l": inertValue, "--table-columns-limit": inertValue, "-E": inertValue, "--table-noextreme": inertValue,
			"-H": inertValue, "--table-hide": inertValue, "-R": inertValue, "--table-right": inertValue,
			"-T": inertValue, "--table-truncate": inertValue, "-W": inertValue, "--table-wrap": inertValue,
			"-r": inertValue, "--tree": inertValue, "-i": inertValue, "--tree-id": inertValue, "-p": inertValue, "--tree-parent": inertValue,
			"-c": inertValue, "--output-width": inertValue, "-o": inertValue, "--output-separator": inertValue, "-s": inertValue, "--separator": inertValue},
			"-t", "--table", "-d", "--table-noheadings", "-m", "--table-maxout", "-e", "--table-header-repeat",
			"-L", "--keep-empty-lines", "-J", "--json", "-x", "--fillrows", "-h", "--help", "-V", "--version")},
		{Names: []string{"expand"}, Flags: fl(map[string]Flag{"-t": inertValue, "--tabs": inertValue},
			append([]string{"-i", "--initial", "--help", "--version"}, digitSwitches...)...)},
		{Names: []string{"unexpand"}, Flags: fl(map[string]Flag{"-t": inertValue, "--tabs": inertValue},
			append([]string{"-a", "--all", "--first-only", "--help", "--version"}, digitSwitches...)...)},
		{Names: []string{"strings"}, Flags: fl(map[string]Flag{"-n": inertValue, "--bytes": inertValue, "-t": inertValue, "--radix": inertValue,
			"-e": inertValue, "--encoding": inertValue, "-T": inertValue, "--target": inertValue, "-U": inertValue, "--unicode": inertValue,
			"-s": inertValue, "--output-separator": inertValue, "-arch": inertValue},
			append([]string{"-a", "--all", "-d", "--data", "-f", "--print-file-name", "-w", "--include-all-whitespace", "-o",
				"-h", "--help", "-v", "-V", "--version"}, digitSwitches...)...)},
		// od: -w[BYTES] and --strings[=BYTES] take an attached value only; the
		// one-letter formats (-a -b -c -d -f -i -l -o -s -x and the legacy -B
		// -D -e -F -H -h -I -L -O -X, also BSD od's) are switches.
		{Names: []string{"od"}, Flags: fl(map[string]Flag{"-A": inertValue, "--address-radix": inertValue, "-j": inertValue, "--skip-bytes": inertValue,
			"-N": inertValue, "--read-bytes": inertValue, "-S": inertValue, "--strings": attachedValue, "-t": inertValue, "--format": inertValue,
			"-w": attachedValue, "--width": attachedValue, "--endian": inertValue},
			"-v", "--output-duplicates", "--traditional", "-a", "-b", "-c", "-d", "-f", "-i", "-l", "-o", "-s", "-x",
			"-B", "-D", "-e", "-F", "-H", "-h", "-I", "-L", "-O", "-X", "--help", "--version")},
		{Names: []string{"hexdump"}, Flags: fl(map[string]Flag{"-e": inertValue, "--format": inertValue,
			"-f": {Value: true, Role: RoleRead}, "--format-file": {Value: true, Role: RoleRead},
			"-n": inertValue, "--length": inertValue, "-s": inertValue, "--skip": inertValue, "-L": attachedValue, "--color": attachedValue},
			"-b", "--one-byte-octal", "-c", "--one-byte-char", "-C", "--canonical", "-d", "--two-bytes-decimal",
			"-o", "--two-bytes-octal", "-x", "--two-bytes-hex", "-v", "--no-squeezing", "-h", "--help", "-V", "--version")},
		{Names: []string{"look"}, Flags: fl(map[string]Flag{"-t": inertValue, "--terminate": inertValue},
			"-a", "--alternative", "-d", "--alphanum", "-f", "--ignore-case", "-h", "--help", "-V", "--version")},
	}
	for _, p := range textReaders {
		p.Pos = PosAllRead
		add(p)
	}
	// Metadata-only programs: they report a file's size, type, inode data or
	// resolved name, never its bytes, so an operand is accounted but carries no
	// content-read effect (DET111 ruling 3a: stat of a credential file is not a
	// credential read). file reads magic bytes but prints only a type label;
	// the magic file and the file of names it is given are reads.
	add(Program{Names: []string{"df"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(map[string]Flag{"-B": inertValue, "--block-size": inertValue, "-t": inertValue, "--type": inertValue,
			"-x": inertValue, "--exclude-type": inertValue, "--output": attachedValue},
			"-a", "--all", "-h", "--human-readable", "-H", "--si", "-i", "--inodes", "-k", "-l", "--local", "-P", "--portability",
			"-T", "--print-type", "-v", "--sync", "--no-sync", "--total", "--help", "--version",
			"-b", "-c", "-g", "-I", "-m", "-n", "-Y")})
	fileRead := Flag{Value: true, Role: RoleRead}
	add(Program{Names: []string{"file"}, Pos: PosAllRead, MetadataOnly: true,
		Flags: fl(map[string]Flag{"-m": fileRead, "--magic-file": fileRead, "-M": fileRead, "-f": fileRead, "--files-from": fileRead,
			"-e": inertValue, "--exclude": inertValue, "--exclude-quiet": inertValue, "-F": inertValue, "--separator": inertValue,
			"-P": inertValue, "--parameter": inertValue},
			"-b", "--brief", "-c", "--checking-printout", "-C", "--compile", "-d", "--debug", "-E", "-h", "--no-dereference",
			"-L", "--dereference", "-i", "--mime", "--mime-type", "--mime-encoding", "--apple", "--extension", "-k", "--keep-going",
			"-l", "--list", "-n", "--no-buffer", "-N", "--no-pad", "-0", "--print0", "-p", "--preserve-date", "-r", "--raw",
			"-s", "--special-files", "-S", "--no-sandbox", "-z", "--uncompress", "-Z", "--uncompress-noreport", "-I", "-D",
			"-v", "--version", "--help")})
	// uniq and xxd get their own exact flag sets: the union above makes -c a
	// valued flag, which for uniq (a count switch) would swallow the next operand.
	inert := func(names ...string) map[string]Flag {
		m := map[string]Flag{}
		for _, n := range names {
			m[n] = Flag{Value: true, Role: RoleIgnore}
		}
		return m
	}
	// sqlite3 DB [SQL...] (GAP-0506): the options that take a value are inert;
	// -cmd, -init, -A and the rest are unlisted, so the call is not fully known.
	// sqlite3 takes each option with one dash or two.
	dashes := func(names ...string) []string {
		out := make([]string, 0, 2*len(names))
		for _, n := range names {
			out = append(out, n, "-"+n)
		}
		return out
	}
	sqliteSwitches := dashes("-readonly", "-bail", "-batch", "-box", "-column", "-csv", "-echo", "-header", "-noheader",
		"-html", "-json", "-line", "-list", "-markdown", "-quote", "-table", "-tabs", "-ascii", "-safe", "-nofollow", "-stats",
		"-version", "-help")
	sqliteValued := dashes("-separator", "-newline", "-nullvalue", "-mmap", "-vfs", "-maxsize")
	add(Program{Names: []string{"sqlite3"}, Pos: PosSQLite, Strict: true, Flags: fl(inert(sqliteValued...), sqliteSwitches...)})
	add(Program{Names: []string{"ed"}, Pos: PosEd, Strict: true, Flags: fl(inert("-p", "--prompt"), "-s", "--quiet", "--silent", "-G", "--traditional", "-l", "--loose-exit-status", "-v", "--verbose", "-E", "--extended-regexp")})
	add(Program{Names: []string{"uniq"}, Pos: PosInOut, Prints: true,
		Flags: fl(inert("-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"),
			"-c", "-d", "-D", "-i", "-u", "-z", "--count", "--repeated", "--all-repeated", "--ignore-case", "--unique", "--zero-terminated", "--group")})
	add(Program{Names: []string{"xxd"}, Pos: PosInOut, Prints: true,
		Flags: fl(inert("-c", "-g", "-l", "-o", "-s", "-n", "-cols", "-groupsize", "-len", "-seek", "-name"),
			"-a", "-b", "-d", "-e", "-E", "-i", "-p", "-ps", "-postscript", "-plain", "-r", "-revert", "-u", "-v", "-C", "-autoskip", "-bits", "-include", "-uppercase", "-EBCDIC")})
	add(Program{Names: []string{"split", "csplit"}, Pos: PosSourcesDest,
		Flags: fl(map[string]Flag{"-b": {Value: true, Role: RoleIgnore}, "-n": {Value: true, Role: RoleIgnore}, "-C": {Value: true, Role: RoleIgnore}, "-l": {Value: true, Role: RoleIgnore}, "-a": {Value: true, Role: RoleIgnore}, "--additional-suffix": {Value: true, Role: RoleIgnore}, "-f": {Value: true, Role: RoleIgnore}, "--suffix-length": {Value: true, Role: RoleIgnore}, "-k": {Value: true, Role: RoleIgnore}},
			"-d", "-u", "-z", "-e", "-s", "-x", "--numeric-suffixes", "--elide-empty-files")})
	add(Program{Names: []string{"tr"}, Pos: PosNone, InertOperands: true, Prints: true, Flags: fl(nil, "-d", "-s", "-c", "-t", "-C")})
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
	add(Program{Names: []string{"7z", "7za", "7zr"}, Pos: PosArchive, Flags: map[string]Flag{"-o": {Value: true, Role: RoleWrite, Subtree: true}}})
	add(Program{Names: []string{"robocopy"}, Pos: PosRobocopy})
	add(Program{Names: []string{"move", "ren", "rename"}, Pos: PosSourcesDest, MovesSources: true})
	add(Program{Names: []string{"del", "erase", "rd", "rmdir"}, Pos: PosAllDelete, Strict: true})
	add(Program{Names: []string{"type"}, Pos: PosAllRead})
	add(Program{Names: []string{"mklink"}, Pos: PosReverseLink})
	add(Program{Names: []string{"icacls"}, Pos: PosConditionalPerm, Strict: true,
		PermissionFlags: []string{"/grant", "/deny", "/remove", "/setowner", "/reset", "/inheritance", "/substitute", "/restore"},
		Flags: map[string]Flag{
			"/verify": {Role: RoleIgnore}, "/c": {Role: RoleIgnore}, "/t": {Role: RoleIgnore},
			"/l": {Role: RoleIgnore}, "/q": {Role: RoleIgnore},
		}})
	add(Program{Names: []string{"cacls", "takeown", "attrib"}, Pos: PosAllPerm, Strict: true})
	add(Program{Names: []string{"certutil"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-urlcache": {Role: RoleNone}, "-decode": {Role: RoleNone}, "-f": {Role: RoleNone}, "-split": {Role: RoleNone}}})
	add(Program{Names: []string{"bitsadmin"}, Pos: PosBits,
		Flags: map[string]Flag{"/transfer": {Value: true, Role: RoleIgnore}, "/addfile": {Value: true, Role: RoleIgnore},
			"/priority": {Value: true, Role: RoleIgnore}, "/download": {}, "/upload": {}, "/dynamic": {}, "/acl": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"cmd"}, Pos: PosNone, CmdC: true})
	add(Program{Names: []string{"set-content", "add-content", "out-file"}, Pos: PosFirstWrite, PipeRole: RoleWrite,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite},
			"-filepath": {Value: true, Role: RoleWrite}, "-value": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"tee-object"}, Pos: PosFirstWrite, PipeRole: RoleWrite, AppendFlag: "-append",
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-filepath": {Value: true, Role: RoleWrite}, "-inputobject": {Value: true, Role: RoleIgnore}, "-append": {}}})
	add(Program{Names: []string{"get-content", "gc", "cat"}, Pos: PosAllRead, PipeRole: RoleRead,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}}})
	add(Program{Names: []string{"copy-item", "cpi"}, Pos: PosSourcesDest,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"move-item", "mi"}, Pos: PosSourcesDest, MovesSources: true,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleRead}, "-literalpath": {Value: true, Role: RoleRead}, "-destination": {Value: true, Role: RoleWrite}}})
	add(Program{Names: []string{"remove-item", "ri", "rmdir"}, Pos: PosAllDelete, Strict: true, PipeRole: RoleDelete,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleDelete}, "-literalpath": {Value: true, Role: RoleDelete}, "-recurse": {}, "-force": {}}})
	add(Program{Names: []string{"new-item", "ni"}, Pos: PosAllWrite,
		Flags: map[string]Flag{"-path": {Value: true, Role: RoleWrite}, "-literalpath": {Value: true, Role: RoleWrite}, "-itemtype": {Value: true, Role: RoleIgnore}, "-value": {Value: true, Role: RoleIgnore}, "-target": {Value: true, Role: RoleLinkTarget}}})
	add(Program{Names: []string{"invoke-webrequest", "invoke-restmethod", "iwr", "irm"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-uri": {Value: true, Role: RoleURL}, "-outfile": {Value: true, Role: RoleOutput}, "-infile": {Value: true, Role: RoleUploadFile}, "-body": {Value: true, Role: RoleSendData}, "-method": {Value: true, Role: RoleIgnore}, "-headers": {Value: true, Role: RoleIgnore}, "-contenttype": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"invoke-expression", "iex"}, Pos: PosFirstCode})
	add(Program{Names: []string{"start-process", "saps"}, Pos: PosFirstExec,
		Flags: map[string]Flag{"-filepath": {Value: true, Role: RoleExecProgram}, "-argumentlist": {Value: true, Role: RoleIgnore}}})
	add(Program{Names: []string{"set-acl"}, Pos: PosAllPerm,
		Flags: map[string]Flag{"-path": {Value: true, Role: RolePerm}, "-literalpath": {Value: true, Role: RolePerm}}})
	add(Program{Names: []string{"powershell", "pwsh"}, Pos: PosNone, PSLaunch: true,
		Flags: map[string]Flag{"-command": {Value: true, Role: RoleExecCode}, "-c": {Value: true, Role: RoleExecCode}, "-encodedcommand": {Value: true, Role: RoleExecCode}, "-enc": {Value: true, Role: RoleExecCode}, "-ec": {Value: true, Role: RoleExecCode}, "-e": {Value: true, Role: RoleExecCode}, "-file": {Value: true, Role: RoleExecCode}}})
	add(Program{Names: []string{"curl"}, Pos: PosURLArgs,
		Flags: map[string]Flag{"-o": {Value: true, Role: RoleOutput}, "--output": {Value: true, Role: RoleOutput},
			"-T": {Value: true, Role: RoleUploadFile}, "--upload-file": {Value: true, Role: RoleUploadFile},
			"-F": {Value: true, Role: RoleSendData}, "--form": {Value: true, Role: RoleSendData},
			"-d": {Value: true, Role: RoleSendData}, "--data": {Value: true, Role: RoleSendData},
			"--data-binary": {Value: true, Role: RoleSendData}, "--data-raw": {Value: true, Role: RoleSendData}, "--data-urlencode": {Value: true, Role: RoleSendData}}})
	addPSParameters()
}

// psCommonParameters are the parameters every PowerShell cmdlet accepts. None
// names a path; the valued ones consume the next word, so they must be listed or
// that word would be read as an operand (round 8, S13/S14).
var psCommonParameters = map[string]Flag{
	"-erroraction": {Value: true, Role: RoleIgnore}, "-warningaction": {Value: true, Role: RoleIgnore}, "-informationaction": {Value: true, Role: RoleIgnore},
	"-errorvariable": {Value: true, Role: RoleIgnore}, "-warningvariable": {Value: true, Role: RoleIgnore}, "-informationvariable": {Value: true, Role: RoleIgnore},
	"-outvariable": {Value: true, Role: RoleIgnore}, "-outbuffer": {Value: true, Role: RoleIgnore}, "-pipelinevariable": {Value: true, Role: RoleIgnore},
	"-ea": {Value: true, Role: RoleIgnore}, "-wa": {Value: true, Role: RoleIgnore}, "-ia": {Value: true, Role: RoleIgnore},
	"-ev": {Value: true, Role: RoleIgnore}, "-wv": {Value: true, Role: RoleIgnore}, "-iv": {Value: true, Role: RoleIgnore},
	"-ov": {Value: true, Role: RoleIgnore}, "-ob": {Value: true, Role: RoleIgnore}, "-pv": {Value: true, Role: RoleIgnore},
	"-verbose": {}, "-debug": {}, "-whatif": {}, "-confirm": {}, "-vb": {}, "-db": {}, "-wi": {}, "-cf": {},
}

// psCmdletParameters adds, per cmdlet, the parameters that do not change which
// path is read or written.
var psCmdletParameters = map[string]map[string]Flag{
	"set-content": psWriterParameters, "add-content": psWriterParameters, "out-file": psWriterParameters,
	"get-content": {"-encoding": {Value: true, Role: RoleIgnore}, "-totalcount": {Value: true, Role: RoleIgnore}, "-tail": {Value: true, Role: RoleIgnore},
		"-readcount": {Value: true, Role: RoleIgnore}, "-delimiter": {Value: true, Role: RoleIgnore}, "-stream": {Value: true, Role: RoleIgnore},
		"-filter": {Value: true, Role: RoleIgnore}, "-include": {Value: true, Role: RoleIgnore}, "-exclude": {Value: true, Role: RoleIgnore},
		"-credential": {Value: true, Role: RoleIgnore}, "-raw": {}, "-wait": {}, "-force": {}, "-asbytestream": {}},
	"copy-item": {"-filter": {Value: true, Role: RoleIgnore}, "-include": {Value: true, Role: RoleIgnore}, "-exclude": {Value: true, Role: RoleIgnore},
		"-credential": {Value: true, Role: RoleIgnore}, "-force": {}, "-recurse": {}, "-container": {}, "-passthru": {}, "-noclobber": {}},
	"move-item": {"-filter": {Value: true, Role: RoleIgnore}, "-include": {Value: true, Role: RoleIgnore}, "-exclude": {Value: true, Role: RoleIgnore},
		"-credential": {Value: true, Role: RoleIgnore}, "-force": {}, "-passthru": {}, "-noclobber": {}},
	"remove-item": {"-filter": {Value: true, Role: RoleIgnore}, "-include": {Value: true, Role: RoleIgnore}, "-exclude": {Value: true, Role: RoleIgnore},
		"-credential": {Value: true, Role: RoleIgnore}, "-stream": {Value: true, Role: RoleIgnore}},
	"new-item": {"-credential": {Value: true, Role: RoleIgnore}, "-type": {Value: true, Role: RoleIgnore}, "-force": {}},
}

var psWriterParameters = map[string]Flag{
	"-encoding": {Value: true, Role: RoleIgnore}, "-inputobject": {Value: true, Role: RoleIgnore}, "-stream": {Value: true, Role: RoleIgnore},
	"-width": {Value: true, Role: RoleIgnore}, "-credential": {Value: true, Role: RoleIgnore},
	"-include": {Value: true, Role: RoleIgnore}, "-exclude": {Value: true, Role: RoleIgnore}, "-filter": {Value: true, Role: RoleIgnore},
	"-nonewline": {}, "-force": {}, "-passthru": {}, "-append": {}, "-noclobber": {}, "-asbytestream": {}, "-usetransaction": {},
}

// addPSParameters merges the common and per-cmdlet parameters into every
// PowerShell cmdlet row of the Windows table.
func addPSParameters() {
	for name, p := range windowsTable {
		if len(p.Names) == 0 || !strings.Contains(p.Names[0], "-") {
			continue
		}
		merged := map[string]Flag{}
		for k, v := range p.Flags {
			merged[k] = v
		}
		for k, v := range psCommonParameters {
			if _, ok := merged[k]; !ok {
				merged[k] = v
			}
		}
		for k, v := range psCmdletParameters[strings.ToLower(p.Names[0])] {
			if _, ok := merged[k]; !ok {
				merged[k] = v
			}
		}
		p.Flags = merged
		windowsTable[name] = p
	}
}

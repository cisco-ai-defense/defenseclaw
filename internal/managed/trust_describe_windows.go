// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DescribeUntrustedSource explains, for the standalone profile, why an
// administrator input such as the config was refused: the account by name,
// the path, and a safe staging step. A standard user who owns the staging
// folder, or can write to it, can change what LocalSystem applies (GAP-0527,
// GAP-0528, GAP-0562). The source might be in an enrolled user's home, so
// never advise changing its ACL (GAP-1112). ok is false when err is not an
// ownership or write-access refusal.
func DescribeUntrustedSource(label, source string, err error) (string, bool) {
	var principal *UntrustedPrincipalError
	if !errors.As(err, &principal) {
		return "", false
	}
	account := principal.SID
	if name := windowsAccountName(principal.SID); name != "" {
		account = name + " (" + principal.SID + ")"
	}
	source = filepath.Clean(source)
	failed := filepath.Clean(principal.Path)
	what := "can write to"
	if principal.Owner {
		what = "owns"
	}
	text := fmt.Sprintf("the %s %s is not protected: %s %s %s, and only Administrators, SYSTEM and TrustedInstaller may own or write it and the folders above it",
		label, source, account, what, failed)
	return text + fmt.Sprintf(". Copy the %s into a dedicated administrator-only staging folder, such as C:\\ProgramData\\DefenseClaw-Staging, writable only by Administrators and SYSTEM; run the same command with that copy. Leave the original path's ACL unchanged (nothing was changed)", label), true
}

// DescribeUntrustedRulePack explains, for the standalone profile, why an
// administrator rule pack was refused: the account by name, the file or
// folder it can change, and the icacls commands that fix it. Setup refused
// such a pack only after it had stopped every service, with a SID and no fix
// (GAP-0668). The fix grants read to the gateway service account alone, not
// BUILTIN\Users: a pack is one profile's policy, and a standard user may see
// only their own (GAP-0386). ok is false when err is not an ownership or
// write-access refusal.
func DescribeUntrustedRulePack(label, pack, serviceAccount string, err error) (string, bool) {
	var principal *UntrustedPrincipalError
	if !errors.As(err, &principal) {
		return "", false
	}
	account := principal.SID
	if name := windowsAccountName(principal.SID); name != "" {
		account = name + " (" + principal.SID + ")"
	}
	pack = filepath.Clean(pack)
	failed := filepath.Clean(principal.Path)
	what := "can write to"
	if principal.Owner {
		what = "owns"
	}
	text := fmt.Sprintf("the rule pack %s (%s) is not protected: %s %s %s, and only Administrators, SYSTEM and TrustedInstaller may own or write a rule pack, the files and folders in it and the folders above it",
		pack, label, account, what, failed)
	inside := strings.EqualFold(failed, pack) ||
		strings.HasPrefix(strings.ToLower(failed), strings.ToLower(pack)+`\`)
	if !inside {
		return text + `. Copy the pack into a folder that only administrators can write, such as C:\ProgramData\DefenseClaw-RulePacks, set that path in the config, and run it again (nothing was changed)`, true
	}
	serviceGrant := RulePackServiceReadGrant(serviceAccount)
	fix := untrustedFolderFix(pack, principal, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", serviceGrant)
	return text + ". From an elevated prompt run " + strings.Join(fix, ", then ") + ", and run it again (nothing was changed)" +
		serviceGrantLeftOutHint(pack, serviceAccount, serviceGrant), true
}

// serviceGrantLeftOutHint is the sentence after a fix whose icacls commands
// carry the gateway service grant: icacls refuses the whole command with
// error 1332 until the service exists (a first install), so it says to leave
// that grant out and give it with the PowerShell form instead (GAP-0087). It is empty
// for an account that is not an NT SERVICE name.
func serviceGrantLeftOutHint(path, serviceAccount, serviceGrant string) string {
	command := ServiceReadGrantPowerShell(path, serviceAccount)
	if command == "" {
		return ""
	}
	return ". Before the gateway service exists (a first install) icacls fails with error 1332: leave \"" + serviceGrant +
		"\" out of the icacls commands and then run, from an elevated cmd or PowerShell prompt: " + command +
		" (" + serviceReadGrantEffect(path, serviceAccount, true) + ")"
}

// DefaultGatewayServiceAccount is the standalone gateway's virtual account.
const DefaultGatewayServiceAccount = `NT SERVICE\DefenseClawGateway`

// RulePackServiceReadGrant is the icacls grant that lets the gateway service
// account, and no standard user, read a rule pack folder: "*<service
// SID>:(OI)(CI)RX". The SID is derived from the service name, so the grant
// works before the service exists (a first install): looking the account up
// fails until the service is installed.
func RulePackServiceReadGrant(serviceAccount string) string {
	return serviceGrantPrincipal(serviceAccount) + ":(OI)(CI)RX"
}

// serviceGrantPrincipal is the icacls principal for the gateway service
// account: "*<service SID>", derived from the service name, so a printed
// grant also works before the service exists, when icacls refuses the
// account name and its looked-up SID (error 1332, #1251). An account that is
// not an NT SERVICE name is named as given.
func serviceGrantPrincipal(serviceAccount string) string {
	account := strings.TrimSpace(serviceAccount)
	if account == "" {
		account = DefaultGatewayServiceAccount
	}
	if name, err := ntServiceName(account); err == nil {
		return "*" + WindowsServiceSIDString(name)
	}
	return account
}

// ServiceReadGrantPowerShell is the command that gives the gateway service
// Read & execute on the rule-pack folder path and everything in it, by its
// service SID. icacls refuses every SID Windows cannot map yet, also in the
// *S-1-5-80-... form, with error 1332, and the service SID maps only once
// the service exists; an ACL rule with a SecurityIdentifier accepts it
// before (GAP-0087). It is empty for an account that is not an NT SERVICE
// name.
func ServiceReadGrantPowerShell(path, serviceAccount string) string {
	return serviceReadGrantPowerShell(path, serviceAccount, true)
}

// serviceReadGrantPowerShell prints the grant as one powershell.exe
// -EncodedCommand, which runs as printed from cmd, from Windows PowerShell
// and from PowerShell 7. The -Command "..." form it replaces ran only from
// cmd: a PowerShell prompt expanded the script's $ variables inside the
// double quotes before powershell.exe started, and the child could not parse
// what was left (GAP-0087). tree false is the grant on a parent folder of a
// rule pack: that folder only, as the icacls RX example beside it, because
// an inheritable rule there reached everything below it, such as the
// administrator's whole profile.
func serviceReadGrantPowerShell(path, serviceAccount string, tree bool) string {
	script := serviceReadGrantScript(path, serviceAccount, tree)
	if script == "" {
		return ""
	}
	return "powershell -NoProfile -NonInteractive -EncodedCommand " + powerShellEncodedCommand(script)
}

// serviceReadGrantEffect says in words what the encoded grant does, so an
// administrator can tell before running it.
func serviceReadGrantEffect(path, serviceAccount string, tree bool) string {
	scope := ", inherited by everything in it"
	if !tree {
		scope = ", on that folder only"
	}
	return "it adds one allow rule, Read & execute for " + strings.TrimPrefix(serviceGrantPrincipal(serviceAccount), "*") +
		" on " + filepath.Clean(path) + scope
}

// powerShellEncodedCommand is script as -EncodedCommand takes it: base64 of
// its UTF-16LE bytes.
func powerShellEncodedCommand(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], unit)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// serviceReadGrantScript is the script of serviceReadGrantPowerShell. .NET
// calls, not Get-Acl and Set-Acl: run from a PowerShell 7 prompt, Windows
// PowerShell inherits a module path whose Security module it cannot load,
// and the cmdlets are not found. A failure stops the script and exits 1.
func serviceReadGrantScript(path, serviceAccount string, tree bool) string {
	sid, ok := strings.CutPrefix(serviceGrantPrincipal(serviceAccount), "*")
	if !ok {
		return ""
	}
	inherit := "'ContainerInherit,ObjectInherit'"
	if !tree {
		inherit = "'None'"
	}
	return "$ErrorActionPreference = 'Stop'; $d = [IO.DirectoryInfo]::new(" + PowerShellLiteral(filepath.Clean(path)) + "); $a = $d.GetAccessControl(); " +
		"$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('" + sid + "'), " +
		"'ReadAndExecute', " + inherit + ", 'None', 'Allow')); $d.SetAccessControl($a)"
}

// StandardUserReadersOf returns the SIDs of the groups every standard user is in (Users,
// Authenticated Users, Everyone, INTERACTIVE, a domain's Domain Users) that
// an allow entry of path lets list or read it. A rule pack is one profile's
// policy, so a pack folder they can read shows every user the policy of
// other profiles (GAP-0386). It reads the folder's own DACL; an error means
// the DACL could not be read.
func StandardUserReadersOf(path string) ([]string, error) {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return []string{"S-1-1-0"}, nil // a NULL DACL grants everyone access
	}
	const read = windows.ACCESS_MASK(windows.FILE_LIST_DIRECTORY) | windows.GENERIC_READ | windows.GENERIC_ALL
	denied := map[string]bool{}
	var readers []string
	seen := map[string]bool{}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&read == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !standardUserGroupSID(sid) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			denied[sid] = true
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !denied[sid] && !seen[sid] {
				seen[sid] = true
				readers = append(readers, sid)
			}
		}
	}
	return readers, nil
}

// standardUserGroupSID reports a group every standard account is in.
func standardUserGroupSID(sid string) bool {
	switch sid {
	case "S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4":
		return true
	}
	return strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-513")
}

// untrustedFolderFix is the icacls commands that leave folder, and the files
// in it, with only the given grants and take the refused principal off them
// (GAP-0953):
//   - Each argument is quoted, so the commands also run in PowerShell, where
//     an unquoted (OI) is a command.
//   - The grants go on the folder alone and its files inherit them. With /T
//     icacls would also strip each file's inherited entries and give it the
//     container grants, which a file cannot use: its DACL would be empty.
//   - /inheritance:r keeps an entry that is the folder's own, and on a Windows
//     client edition a new folder under C:\ holds Authenticated Users that
//     way, so the principal is removed by name from the folder and its files.
//   - /remove:g takes every grant of the principal, so a grant for that same
//     principal (Users Read & execute on a rule pack, which the gateway
//     service reads through) is given again after it (GAP-1326).
func untrustedFolderFix(folder string, principal *UntrustedPrincipalError, grants ...string) []string {
	var fix []string
	if principal.Owner {
		fix = append(fix, fmt.Sprintf(`icacls "%s" /setowner "*S-1-5-32-544" /T /C`, folder))
	}
	grant := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r`, folder)
	regrant := ""
	for _, entry := range grants {
		grant += ` "` + entry + `"`
		if sid, _, _ := strings.Cut(strings.TrimPrefix(entry, "*"), ":"); strings.EqualFold(sid, principal.SID) {
			regrant += ` "` + entry + `"`
		}
	}
	fix = append(fix, grant, fmt.Sprintf(`icacls "%s" /remove:g "*%s" /T /C`, folder, principal.SID))
	if regrant != "" {
		fix = append(fix, fmt.Sprintf(`icacls "%s" /grant:r`, folder)+regrant)
	}
	return fix
}

// windowsAccountName is DOMAIN\name for a SID, or "" when it does not resolve.
func windowsAccountName(value string) string {
	sid, err := windows.StringToSid(value)
	if err != nil {
		return ""
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// StandaloneContentDriftError is the refusal of a drifted standalone policy
// or data file (StandaloneRefusesContentDrift). It wraps the strict verdict,
// so errors.As still finds the UntrustedPrincipalError that names the path
// and the account, and adds what to do: DefenseClaw does not repair the file
// in place, because an account that could write it may have changed it and
// may still hold a handle to it (GAP-0561). For config.yaml and the guardian
// manifest, Setup writes a fresh file from the administrator's source and
// replaces the old one; for a file Setup has no administrator source for,
// the administrator removes the entry and checks the file (GAP-0590).
type StandaloneContentDriftError struct {
	Err error
	// Recovery replaces the recovery chosen from the refused path when set.
	Recovery string
}

// Recovery texts of a StandaloneContentDriftError, by file. Setup is not
// installed on a managed computer, so each names the commands through the
// renderer and says where Setup comes from (cowork-1-0-8 GAP-0095).
func standaloneConfigDriftRecovery() string {
	return "from an elevated PowerShell prompt run `" + WindowsSetupCommand("/ensure", "CONFIG=<the approved administrator-only config>") +
		"` so Setup writes a new config.yaml from it, then `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") +
		"`. " + WindowsSetupSource
}

// standaloneMachinePolicyDriftRecovery is the way out of a drifted Claude
// Code, Codex or Cursor machine policy folder or DefenseClaw file in it,
// which the hook guardian does not re-stamp (GAP-0633). A file is deleted,
// not fixed with icacls: an identical rewrite keeps the old object, and a
// handle the account opened while it could write the file keeps working on
// it (g582 review 3 S2).
func standaloneMachinePolicyDriftRecovery(path string, cause error) string {
	verify := "`" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") + "`. " + WindowsSetupSource
	var writers, drift []string
	var principal interface{ untrustedSID() (string, bool) }
	if errors.As(cause, &principal) {
		if sid, _ := principal.untrustedSID(); sid != "" {
			writers = []string{sid}
		}
	} else if cause != nil {
		// A verdict that reached here as text (wrapped without its type) still
		// names its accounts: "untrusted principal S-1-... has write access",
		// "owner S-1-... is not trusted".
		for _, match := range standaloneCauseWriterSID.FindAllStringSubmatch(cause.Error(), -1) {
			writers = append(writers, match[1])
		}
		for _, match := range standaloneDriftOwnerSID.FindAllStringSubmatch(cause.Error(), -1) {
			drift = append(drift, "owner "+match[1]+" is not trusted")
		}
	}
	info, statErr := os.Lstat(path)
	fix := standaloneExactFix(path, statErr == nil && info.IsDir(), writers, drift)
	if len(writers) == 0 && len(drift) == 0 && cause != nil && strings.Contains(cause.Error(), "untrusted writer above") {
		// The writer is a folder above the object, not the object itself:
		// the common one is BUILTIN\Users, taken off the parent folder here;
		// the message names the folder and account when it is another.
		fix += ` and, on the folder above it, icacls "` + filepath.Dir(path) + `" /remove:g *` + sidUsers
	}
	if statErr == nil && info.IsDir() {
		return "the hook guardian leaves it as it is and every DefenseClaw reader keeps refusing it: from an elevated PowerShell prompt run " +
			fix + ` (for an inherited entry first run icacls "` + path + `" /inheritance:d, ` +
			"which keeps copies of the inherited entries), which gives the folder back to Administrators, check what is in it, then run `" +
			WindowsSetupCommand("/ensure") + "` and " + verify
	}
	return "the hook guardian leaves it as it is and every DefenseClaw reader keeps refusing it: " +
		`from an elevated PowerShell prompt delete the file (Remove-Item -LiteralPath "` + path + `" -Force; for the ownership record .defenseclaw-managed-hooks.state delete the ` +
		"DefenseClaw policy file beside it too, 90-defenseclaw.json or requirements.toml; for Cursor delete the record, " +
		".defenseclaw-managed-hooks.receipt and defenseclaw-hook.ps1 together), then run `" + WindowsSetupCommand("/ensure") +
		"`, which writes them new from Setup's own state, and " + verify +
		" Removing the entry alone is not enough, because a program that opened the file while it could write it can still change it; it only takes the account's access away: " + fix
}

func (e *StandaloneContentDriftError) Error() string {
	return e.Err.Error() + "; a standalone install does not repair this file in place, because an account that could " +
		"write it may have changed it: " + e.recovery()
}

func (e *StandaloneContentDriftError) recovery() string {
	if e.Recovery != "" {
		return e.Recovery
	}
	return standaloneContentDriftRecovery(e.Err)
}

func (e *StandaloneContentDriftError) Unwrap() error { return e.Err }

// RefuseStandaloneContentDrift returns err as a StandaloneContentDriftError,
// or nil for nil.
func RefuseStandaloneContentDrift(err error) error {
	if err == nil {
		return nil
	}
	return &StandaloneContentDriftError{Err: err}
}

// RefuseStandaloneMachinePolicyDrift is RefuseStandaloneContentDrift for a
// vendor machine policy folder or a DefenseClaw file in it, which the hook
// guardian refuses to re-stamp on standalone (GAP-0633).
func RefuseStandaloneMachinePolicyDrift(path string, err error) error {
	if err == nil {
		return nil
	}
	return &StandaloneContentDriftError{Err: err, Recovery: standaloneMachinePolicyDriftRecovery(path, err)}
}

// standaloneExactFix is the elevated-prompt icacls command that takes back
// what makes path untrusted: one /remove:g for each account that can write
// it, and /setowner when an untrusted account owns it (or when the account
// is not known). Every refusal names these with the real path and accounts,
// never a template (GAP-0602 class rule: a refusal names the exact command).
func standaloneExactFix(path string, directory bool, writers, drift []string) string {
	quoted := `"` + path + `"`
	var commands []string
	seen := map[string]bool{}
	remove := func(sid string) {
		if sid != "" && !seen[sid] {
			seen[sid] = true
			commands = append(commands, "icacls "+quoted+" /remove:g *"+sid)
		}
	}
	// Only a real SID is a command: the assessment also names an entry it
	// cannot read ("object-ace-N") and Everyone for a null access list, which
	// /remove:g can do nothing with. Those are put right by writing the
	// administrator-only access list again.
	needsReset := false
	for _, entry := range drift {
		if strings.Contains(entry, "DACL is null") {
			needsReset = true
		}
	}
	for _, sid := range writers {
		if standaloneSIDPattern.MatchString(sid) && (!needsReset || sid != sidEveryone) {
			remove(sid)
		} else {
			needsReset = true
		}
	}
	// An untrusted owner is named in the drift ("owner S-1-5-... is not
	// trusted"); its own entry goes too, and Administrators take the object
	// back whoever owned it.
	for _, entry := range drift {
		if match := standaloneDriftOwnerSID.FindStringSubmatch(entry); match != nil {
			remove(match[1])
		}
	}
	if len(commands) == 0 {
		needsReset = true
	}
	if needsReset {
		inherit := ""
		if directory {
			inherit = "(OI)(CI)"
		}
		commands = append(commands, "icacls "+quoted+" /inheritance:r /grant:r \"*"+sidLocalSystem+":"+inherit+"(F)\" \"*"+sidAdministrators+":"+inherit+"(F)\"")
	}
	commands = append(commands, "icacls "+quoted+" /setowner *S-1-5-32-544")
	return strings.Join(commands, " and ")
}

var (
	standaloneDriftOwnerSID  = regexp.MustCompile(`\bowner (S-1-[0-9-]+) is not trusted`)
	standaloneSIDPattern     = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
	standaloneCauseWriterSID = regexp.MustCompile(`untrusted (?:Windows )?principal (S-1-[0-9]+(?:-[0-9]+)+)`)
)

// standaloneInPlaceRecovery is the recovery text of a managed file or folder
// that another account can write or owns, with the exact commands: the
// icacls fix, then Setup and verify. An inherited entry cannot be removed
// from the object itself, so its fix is named too.
func standaloneInPlaceRecovery(path string, directory bool, writers, drift []string) string {
	what, check := "file", "check it"
	if directory {
		what, check = "folder", "check what is in it"
	}
	return "from an elevated prompt run " + standaloneExactFix(path, directory, writers, drift) +
		` (for an inherited entry first run icacls "` + path + `" /inheritance:d, which keeps copies of the inherited entries), ` +
		"which gives the " + what + " back to Administrators; " + check + ", then run `" + WindowsSetupCommand("/ensure") +
		"` and `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") + "`. " + WindowsSetupSource
}

// standaloneStructuralRecovery is the recovery text of a managed object that
// is a link, a second hard link or the wrong kind of object: it is not judged
// by its access list at all.
func standaloneStructuralRecovery(path string) string {
	return `from an elevated prompt check where "` + path + `" leads, remove it (Remove-Item -LiteralPath "` + path + `" -Force), then run ` +
		"`" + WindowsSetupCommand("/ensure") + "` and `" + WindowsAdminCommand("enterprise", "windows", "verify", "--profile", "standalone") + "`. " + WindowsSetupSource
}

// RefuseStandaloneInPlaceRepair is the standalone refusal of an in-place
// owner or DACL repair of a managed object (the g582 class rule: on a
// standalone install a managed file or folder another account can write or
// owns is never given a trusted descriptor back in place). It reads the
// object's own descriptor (AssessCanonical as kind) without writing and
// returns a StandaloneContentDriftError that names the object and the way
// out when an untrusted principal can write or owns it, or when the object
// cannot be judged at all (an assessment error other than a missing object:
// a descriptor nobody can read, a reparse point, a hard link), because a
// repair of what was not judged would trust it blind (g582 review 4 F1). It
// is nil off standalone, for trusted-only drift, and for a missing object.
func RefuseStandaloneInPlaceRepair(path string, kind ObjectKind) error {
	return RefuseStandaloneInPlaceRepairAs(path, kind, "")
}

// RefuseStandaloneInPlaceRepairAs is RefuseStandaloneInPlaceRepair for a
// process that carries no gateway service pin (Setup's staged CLI): the
// gateway's NT SERVICE account is named, so the gateway's own write entry on
// a runtime folder is not taken for an untrusted writer. With no account it
// resolves the pinned one, as before.
func RefuseStandaloneInPlaceRepairAs(path string, kind ObjectKind, gatewayServiceAccount string) error {
	if !StandaloneRefusesContentDrift() {
		return nil
	}
	result, err := AssessCanonical(path, kind, CanonicalOptions{Quiet: true, GatewayServiceAccount: gatewayServiceAccount})
	if err != nil {
		return &StandaloneContentDriftError{
			Err:      fmt.Errorf("cannot judge who can write or owns %s: %w", path, err),
			Recovery: standaloneInPlaceRecovery(path, kind.Directory(), nil, nil),
		}
	}
	if result.Outcome != CanonicalBoundary {
		return nil
	}
	return &StandaloneContentDriftError{
		Err:      fmt.Errorf("an untrusted principal can write or owns %s: %s", path, strings.Join(result.Drift, "; ")),
		Recovery: standaloneInPlaceRecovery(path, kind.Directory(), result.UntrustedWriters, result.Drift),
	}
}

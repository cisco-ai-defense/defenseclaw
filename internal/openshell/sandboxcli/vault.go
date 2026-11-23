// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// VaultDir is this account's vault directory: in the sandbox daemon's state
// directory on a managed computer (the account's own; no per-user
// config.yaml exists there), else in the DefenseClaw data directory. The
// per-user gateway and the sandbox daemon resolve the same directory.
func (a *App) VaultDir() string {
	if a.ManagedHost() || onManagedHost() {
		a.defaults()
		if home, err := a.Home(); err == nil {
			if dir := sandboxapi.ManagedStateDir(a.GOOS, home); dir != "" {
				return vault.DirIn(dir)
			}
		}
	}
	return vault.DirIn(a.dataDir())
}

func (a *App) vault() *vault.Store { return vault.Open(a.VaultDir()) }

// vaultJSONEntry is one entry in --output json: the metadata and the
// derived status and target; never the value.
type vaultJSONEntry struct {
	vault.Entry
	Target string       `json:"target"`
	Status vault.Status `json:"status"`
}

func vaultJSON(e vault.Entry) vaultJSONEntry {
	return vaultJSONEntry{Entry: e, Target: e.Target(), Status: e.Status()}
}

// VaultList prints the vault. Values are never printed.
func (a *App) VaultList(format OutputFormat) error {
	st := a.vault()
	list, err := st.List()
	if err != nil {
		return err
	}
	if format == OutputJSON {
		out := make([]vaultJSONEntry, 0, len(list))
		for _, e := range list {
			out = append(out, vaultJSON(e))
		}
		return writeJSON(a.IO.Out, map[string]any{"path": st.Path(), "entries": out})
	}
	if len(list) == 0 {
		a.note("the vault is empty; add a secret with `" + CommandName + " vault add NAME --host HOST`")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, e := range list {
		rows = append(rows, []string{e.Name, firstNonEmpty(e.Target(), "—"), vaultStatusText(e.Status()), string(e.Source), vaultUsedText(e)})
	}
	a.table([]string{"NAME", "HOST", "STATUS", "SOURCE", "LAST USED"}, rows)
	for _, e := range list {
		switch e.Status() {
		case vault.StatusNeedsHost:
			a.note(fmt.Sprintf("%s has no host yet; bind one: %s vault bind %s --host HOST", e.Name, CommandName, e.Name))
		case vault.StatusExposed:
			a.warn(fmt.Sprintf("%s may have been seen by an agent's model; rotate it with its issuer, then: %s vault replace %s", e.Name, CommandName, e.Name))
		case vault.StatusUnconfirmed:
			a.note(fmt.Sprintf("%s was captured from a sandbox; check it is yours, then: %s vault confirm %s", e.Name, CommandName, e.Name))
		}
	}
	return nil
}

// VaultShow prints one entry.
func (a *App) VaultShow(name string, format OutputFormat) error {
	e, err := a.vault().Get(name)
	if err != nil {
		return err
	}
	if format == OutputJSON {
		return writeJSON(a.IO.Out, vaultJSON(e))
	}
	a.printf("%s\n", e.Name)
	rows := [][2]string{
		{"Host", firstNonEmpty(e.Target(), "none yet")},
		{"Status", vaultStatusText(e.Status())},
		{"Source", string(e.Source)},
	}
	if e.Kind != "" {
		rows = append(rows, [2]string{"Kind", e.Kind})
	}
	if e.CapturedFrom != "" {
		rows = append(rows, [2]string{"Captured from", e.CapturedFrom})
	}
	rows = append(rows,
		[2]string{"Added", e.CreatedAt.Local().Format(time.RFC3339)},
		[2]string{"Changed", e.UpdatedAt.Local().Format(time.RFC3339)},
		[2]string{"Last used", vaultUsedText(e)},
		[2]string{"In a sandbox", "$" + e.Name + " (a placeholder; OpenShell sends the value only to " + firstNonEmpty(e.Target(), "its host") + ")"},
	)
	for _, r := range rows {
		a.line(fmt.Sprintf("%-14s %s", r[0], r[1]))
	}
	return nil
}

// VaultValueOptions say where a value comes from.
type VaultValueOptions struct {
	// Stdin reads one line from standard input (--value-stdin).
	Stdin bool
}

// VaultAdd adds a secret.
func (a *App) VaultAdd(name, host string, opts VaultValueOptions) error {
	if err := vault.ValidName(name); err != nil {
		return err
	}
	if _, _, err := vault.ParseHost(host); err != nil {
		return err
	}
	value, err := a.readVaultValue(fmt.Sprintf("Value for %s (input hidden): ", name), opts)
	if err != nil {
		return err
	}
	e, err := a.vault().Add(vault.AddInput{Name: name, Value: value, Host: host, Source: vault.SourceManual})
	if err != nil {
		return err
	}
	a.ok(fmt.Sprintf("added %s for %s", e.Name, e.Target()))
	a.note(fmt.Sprintf("use it in a sandbox: %s run claude --vault %s", CommandName, e.Name))
	return nil
}

// VaultReplace sets a new value.
func (a *App) VaultReplace(name string, opts VaultValueOptions) error {
	if _, err := a.vault().Get(name); err != nil {
		return err
	}
	value, err := a.readVaultValue(fmt.Sprintf("New value for %s (input hidden): ", name), opts)
	if err != nil {
		return err
	}
	e, err := a.vault().ReplaceValue(name, value)
	if err != nil {
		return err
	}
	a.ok("replaced the value of " + e.Name)
	a.note("sandboxes created from now on use the new value; a sandbox created with the old one is refused at start: delete it and start a new one")
	return nil
}

// VaultBind sets the host a secret may be sent to.
func (a *App) VaultBind(name, host string) error {
	e, err := a.vault().Bind(name, host)
	if err != nil {
		return err
	}
	a.ok(fmt.Sprintf("%s may now be sent to %s only", e.Name, e.Target()))
	return nil
}

// VaultRename renames a secret.
func (a *App) VaultRename(name, newName string) error {
	e, err := a.vault().Rename(name, newName)
	if err != nil {
		return err
	}
	a.ok(fmt.Sprintf("renamed %s to %s", name, e.Name))
	return nil
}

// VaultConfirm marks a captured secret as the person's own, after showing
// where it came from and the last 4 characters of its value.
func (a *App) VaultConfirm(name string, yes bool) error {
	st := a.vault()
	e, err := st.Get(name)
	if err != nil {
		return err
	}
	if e.Source != vault.SourceCaptured {
		a.note(name + " was added by you; it needs no confirmation")
		return nil
	}
	hint, err := st.Hint(name)
	if err != nil {
		return err
	}
	a.printf("%s\n", name)
	a.line(fmt.Sprintf("%-14s %s", "Kind", firstNonEmpty(e.Kind, "unknown")))
	a.line(fmt.Sprintf("%-14s %s", "Captured from", firstNonEmpty(e.CapturedFrom, "a sandbox")))
	a.line(fmt.Sprintf("%-14s %s", "Captured", e.CreatedAt.Local().Format(time.RFC3339)))
	if hint != "" {
		a.line(fmt.Sprintf("%-14s …%s", "Ends with", hint))
	}
	a.line(fmt.Sprintf("%-14s %s", "Host", firstNonEmpty(e.Target(), "none yet")))
	a.note("An agent in a sandbox can make a call that looks like your prompt, so confirm only a secret you gave it.")
	ok, err := a.confirm(fmt.Sprintf("Is %s your own secret?", name), yes)
	if err != nil {
		return err
	}
	if !ok {
		a.note("not confirmed; remove it with `" + CommandName + " vault remove " + name + "` if it is not yours")
		return nil
	}
	if _, err := st.Confirm(name); err != nil {
		return err
	}
	a.ok("confirmed " + name)
	return nil
}

// VaultRemove deletes a secret.
func (a *App) VaultRemove(name string, yes bool) error {
	st := a.vault()
	if _, err := st.Get(name); err != nil {
		return err
	}
	ok, err := a.confirm(fmt.Sprintf("Remove %s from the vault?", name), yes)
	if err != nil {
		return err
	}
	if !ok {
		a.note("nothing removed")
		return nil
	}
	if err := st.Remove(name); err != nil {
		return err
	}
	a.ok("removed " + name)
	a.note("sandboxes created with it keep the value until you delete them (a stopped one is refused at start); revoke it with its issuer if it may have leaked")
	return nil
}

// errNoValueSource: no terminal to ask on and no --value-stdin.
var errNoValueSource = errors.New("there is no terminal to type the value in; pipe it with --value-stdin")

func (a *App) readVaultValue(prompt string, opts VaultValueOptions) (string, error) {
	a.defaults()
	var value string
	switch {
	case opts.Stdin:
		in := a.IO.In
		if in == nil {
			in = os.Stdin
		}
		reader := bufio.NewReaderSize(in, vault.MaxValueBytes+2)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read the value from standard input: %w", err)
		}
		value = strings.TrimRight(line, "\r\n")
		// A value is one line: more text after it is a mistake (a pasted
		// file, two values), never silently dropped.
		if !a.IO.InTTY {
			rest, _ := io.ReadAll(io.LimitReader(reader, 1<<16))
			if strings.TrimSpace(string(rest)) != "" {
				return "", errors.New("standard input has more than one line; pipe only the value")
			}
		}
	case a.ReadSecret != nil:
		v, err := a.ReadSecret(prompt)
		if err != nil {
			return "", err
		}
		value = v
	case a.IO.InTTY:
		fmt.Fprint(a.IO.Out, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(a.IO.Out)
		if err != nil {
			return "", fmt.Errorf("read the value: %w", err)
		}
		value = string(b)
	default:
		return "", errNoValueSource
	}
	if err := vault.ValidValue(value); err != nil {
		return "", err
	}
	return value, nil
}

func vaultStatusText(s vault.Status) string {
	switch s {
	case vault.StatusReady:
		return "ready"
	case vault.StatusNeedsHost:
		return "needs a host"
	case vault.StatusExposed:
		return "exposed: rotate"
	case vault.StatusUnconfirmed:
		return "unconfirmed"
	}
	return string(s)
}

func vaultUsedText(e vault.Entry) string {
	if e.LastUsedAt == nil {
		return "never"
	}
	text := humanDuration(time.Since(*e.LastUsedAt)) + " ago"
	if e.LastUsedBy != "" {
		text += " (" + e.LastUsedBy + ")"
	}
	return text
}

// vaultVersions records each vault entry's version as the sandbox is
// created with it.
func (a *App) vaultVersions(names []string) map[string]string {
	if len(names) == 0 {
		return nil
	}
	st := a.vault()
	out := map[string]string{}
	for _, n := range names {
		if e, err := st.Get(n); err == nil {
			out[n] = e.UpdatedAt.UTC().Format(time.RFC3339Nano)
		}
	}
	return out
}

// vaultGrantsCurrent refuses to start a stopped sandbox whose vault secrets
// were removed, exposed, replaced, rebound or are no longer confirmed since
// it was created: it still holds the old value, which only a new sandbox
// drops. A sandbox created without --vault is not affected.
func (a *App) vaultGrantsCurrent(sb *sandboxapi.Sandbox) error {
	rec := a.runLaunchOf(sb)
	if rec == nil || len(rec.Vault) == 0 {
		return nil
	}
	// Metadata only: this check never opens a value, so it needs no key.
	st := a.vault()
	for _, n := range rec.Vault {
		e, err := st.Get(n)
		var why string
		switch {
		case errors.Is(err, vault.ErrNotFound):
			return fmt.Errorf("%s was created with the vault secret %s, which is no longer in your vault; "+
				"the sandbox would keep the old value, so it is not started: delete it (`%s delete %s`) and start a new one without that secret, or add it again first",
				sb.Name, n, CommandName, sb.Name)
		case err != nil:
			why = err.Error()
		case e.Status() != vault.StatusReady:
			why = "its status is now " + string(e.Status())
		case rec.VaultVersions[n] != "" && e.UpdatedAt.UTC().Format(time.RFC3339Nano) != rec.VaultVersions[n]:
			why = "it was replaced, rebound or renamed in your vault"
		default:
			continue
		}
		return fmt.Errorf("%s was created with the vault secret %s, which is no longer the same (%s); "+
			"the sandbox would keep the old value, so it is not started: delete it (`%s delete %s`) and start a new one with --vault %s",
			sb.Name, n, why, CommandName, sb.Name, n)
	}
	return nil
}

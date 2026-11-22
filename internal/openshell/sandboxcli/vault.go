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
	a.note("sandboxes started from now on use the new value; restart running ones to pick it up")
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
	a.note("running sandboxes keep the value until they stop; revoke it with its issuer if it may have leaked")
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
		rest, _ := io.ReadAll(io.LimitReader(reader, 1<<16))
		if strings.TrimSpace(string(rest)) != "" {
			return "", errors.New("standard input has more than one line; pipe only the value")
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

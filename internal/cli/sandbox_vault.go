// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

const sandboxVaultLong = `The vault keeps your secrets for your sandboxes. Each secret is bound to the one host
it may be sent to. Start a sandbox with "--vault NAME" and the agent inside sees only a
placeholder in $NAME; OpenShell puts the real value in on the way out, to that host only.

DefenseClaw also captures secrets for you: when an agent in a sandbox is given a secret
with a well-known shape (an Anthropic, OpenAI, GitHub, Slack, Stripe or Google API key),
in a prompt or a tool call, the secret goes into your vault and the call is stopped
before the value reaches the model.

The vault is a file only your account can read, in your DefenseClaw state directory.
Values are never printed: list and show give names, hosts and status only.`

func newSandboxVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Keep your secrets for your sandboxes: list, add, replace, bind and remove",
		Long:  sandboxVaultLong,
	}
	defaults := map[string]string{sandboxConfigDefault: "true"}

	list := &cobra.Command{
		Use:         "list",
		Short:       "List your secrets (names, hosts and status; never values)",
		Args:        cobra.NoArgs,
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, cmd *cobra.Command, _ []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.VaultList(out)
		}),
	}
	outputFlag(list)

	show := &cobra.Command{
		Use:         "show <name>",
		Short:       "Show one secret's host, status, source and use (never its value)",
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, cmd *cobra.Command, args []string) error {
			out, err := parseOutput(cmd.Flag("output").Value.String())
			if err != nil {
				return err
			}
			return app.VaultShow(args[0], out)
		}),
	}
	outputFlag(show)

	var addHost string
	var addOpts sandboxcli.VaultValueOptions
	add := &cobra.Command{
		Use:   "add <name> --host HOST",
		Short: "Add a secret bound to one host (asks for the value with echo off)",
		Long: `Adds a secret. NAME is the environment variable the sandbox sees (for example
STRIPE_API_KEY); --host is the only host the value is ever sent to (api.stripe.com, or
host:port). The value is typed with echo off, or piped with --value-stdin; it never goes
on the command line.`,
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultAdd(args[0], addHost, addOpts)
		}),
	}
	add.Flags().StringVar(&addHost, "host", "", "the only host the secret may be sent to (host or host:port)")
	_ = add.MarkFlagRequired("host")
	add.Flags().BoolVar(&addOpts.Stdin, "value-stdin", false, "read the value from standard input (one line)")

	var replaceOpts sandboxcli.VaultValueOptions
	replace := &cobra.Command{
		Use:         "replace <name>",
		Short:       "Replace a secret's value (after you rotate it)",
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultReplace(args[0], replaceOpts)
		}),
	}
	replace.Flags().BoolVar(&replaceOpts.Stdin, "value-stdin", false, "read the value from standard input (one line)")

	var bindHost string
	bind := &cobra.Command{
		Use:         "bind <name> --host HOST",
		Short:       "Set the one host a secret may be sent to",
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultBind(args[0], bindHost)
		}),
	}
	bind.Flags().StringVar(&bindHost, "host", "", "the only host the secret may be sent to (host or host:port)")
	_ = bind.MarkFlagRequired("host")

	rename := &cobra.Command{
		Use:         "rename <name> <new-name>",
		Short:       "Rename a secret (the variable the sandbox sees)",
		Args:        cobra.ExactArgs(2),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultRename(args[0], args[1])
		}),
	}

	var confirmYes bool
	confirm := &cobra.Command{
		Use:   "confirm <name>",
		Short: "Confirm a captured secret is yours, so sandboxes can use it",
		Long: `A secret DefenseClaw captured from a sandbox is unconfirmed until you confirm it:
an agent in a sandbox can make a call that looks like your prompt, so a captured value
may be one it planted. confirm shows where the secret came from and the last 4
characters of its value, then asks.`,
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultConfirm(args[0], confirmYes)
		}),
	}
	confirm.Flags().BoolVarP(&confirmYes, "yes", "y", false, "do not ask")

	var removeYes bool
	remove := &cobra.Command{
		Use:         "remove <name>",
		Short:       "Remove a secret from the vault",
		Args:        nameArg("secret"),
		Annotations: defaults,
		RunE: sandboxRunE(func(_ context.Context, app *sandboxcli.App, _ *cobra.Command, args []string) error {
			return app.VaultRemove(args[0], removeYes)
		}),
	}
	remove.Flags().BoolVarP(&removeYes, "yes", "y", false, "do not ask")

	cmd.AddCommand(list, show, add, replace, confirm, bind, rename, remove)
	return cmd
}

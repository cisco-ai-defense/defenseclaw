// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package main dumps the defenseclaw-gateway Cobra command tree as JSON
// for the docs-site generator pipeline. See scripts/docgen/cli_go.py.
//
// Usage:
//
//	go run ./cmd/docgen-go > /tmp/gateway-cli.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

type flagDoc struct {
	Name        string   `json:"name"`
	Shorthand   string   `json:"shorthand,omitempty"`
	Type        string   `json:"type"`
	Default     string   `json:"default,omitempty"`
	Usage       string   `json:"usage,omitempty"`
	Persistent  bool     `json:"persistent,omitempty"`
	Deprecated  string   `json:"deprecated,omitempty"`
	NoOptDefVal string   `json:"no_opt_def_val,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
}

type cmdDoc struct {
	Use              string     `json:"use"`
	Name             string     `json:"name"`
	FullName         string     `json:"full_name"`
	Short            string     `json:"short,omitempty"`
	Long             string     `json:"long,omitempty"`
	Example          string     `json:"example,omitempty"`
	Hidden           bool       `json:"hidden,omitempty"`
	Deprecated       string     `json:"deprecated,omitempty"`
	Aliases          []string   `json:"aliases,omitempty"`
	ArgsDescription  string     `json:"args_description,omitempty"`
	Runnable         bool       `json:"runnable"`
	ValidArgs        []string   `json:"valid_args,omitempty"`
	LocalFlags       []flagDoc  `json:"local_flags,omitempty"`
	InheritedFlags   []flagDoc  `json:"inherited_flags,omitempty"`
	PersistentFlags  []flagDoc  `json:"persistent_flags,omitempty"`
	Subcommands      []cmdDoc   `json:"subcommands,omitempty"`
}

func flagDocs(fs *pflag.FlagSet, persistent bool) []flagDoc {
	if fs == nil {
		return nil
	}
	var out []flagDoc
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		out = append(out, flagDoc{
			Name:        f.Name,
			Shorthand:   f.Shorthand,
			Type:        f.Value.Type(),
			Default:     f.DefValue,
			Usage:       f.Usage,
			Persistent:  persistent,
			Deprecated:  f.Deprecated,
			NoOptDefVal: f.NoOptDefVal,
		})
	})
	return out
}

func convert(cmd *cobra.Command, parent string) cmdDoc {
	full := cmd.Name()
	if parent != "" {
		full = parent + " " + cmd.Name()
	}
	doc := cmdDoc{
		Use:             cmd.Use,
		Name:            cmd.Name(),
		FullName:        full,
		Short:           cmd.Short,
		Long:            cmd.Long,
		Example:         cmd.Example,
		Hidden:          cmd.Hidden,
		Deprecated:      cmd.Deprecated,
		Aliases:         cmd.Aliases,
		Runnable:        cmd.Runnable(),
		ValidArgs:       cmd.ValidArgs,
		LocalFlags:      flagDocs(cmd.LocalFlags(), false),
		PersistentFlags: flagDocs(cmd.PersistentFlags(), true),
	}
	for _, c := range cmd.Commands() {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		doc.Subcommands = append(doc.Subcommands, convert(c, full))
	}
	return doc
}

func main() {
	root := cli.RootCmd()
	if root == nil {
		fmt.Fprintln(os.Stderr, "docgen-go: cli.RootCmd() returned nil")
		os.Exit(1)
	}
	doc := convert(root, "")
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "docgen-go: %v\n", err)
		os.Exit(1)
	}
}

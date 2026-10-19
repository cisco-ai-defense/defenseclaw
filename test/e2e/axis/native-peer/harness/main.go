// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor harness; no production activation or default execution.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"time"
)

type options struct{ receipt, evidence, suite string }

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("native-peer-fixed", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	explicit := flags.Bool("run-fixed", false, "explicit reviewed contributor experiment")
	flags.StringVar(&opts.receipt, "receipt", "", "exact reviewed artifact set receipt")
	flags.StringVar(&opts.evidence, "evidence", "", "fresh private result directory")
	flags.StringVar(&opts.suite, "suite", "baseline", "fixed baseline or lifecycle suite")
	if flags.Parse(args) != nil || !*explicit || flags.NArg() != 0 || opts.receipt == "" || opts.evidence == "" || len(opts.receipt) > 4096 || len(opts.evidence) > 4096 || !validSuite(opts.suite) {
		return opts, errors.New("explicit fixed selector and reviewed receipt/evidence metadata required")
	}
	return opts, nil
}

func workerOptions(args []string) (options, error) {
	if (len(args) != 4 && len(args) != 6) || args[0] != "--receipt" || args[2] != "--evidence" || len(args) == 6 && args[4] != "--suite" {
		return options{}, errors.New("fixed worker metadata refused")
	}
	return parseOptions(append([]string{"--run-fixed"}, args...))
}

func execute(args []string) (map[string]any, *cleanupOwner, error) {
	opts, err := parseOptions(args)
	if err != nil {
		return executeWithRegistry(args, reviewedRegistry{}, runSupervised)
	}
	return executeWithRegistry(args, registryForSuite(opts.suite), runSupervised)
}

type supervisedRun func(context.Context, options, reviewedRegistry, map[string]any, *cleanupOwner) error

// Tests inject an unreviewed registry or a fake supervisor. They never inherit
// native execution authority from the separately reviewed contributor entry.
func executeWithRegistry(args []string, registry reviewedRegistry, supervise supervisedRun) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": harnessScope, "passed": false, "execution_performed": false, "production_certification": false, "common_launch_gate_qualified": false}
	owner := &cleanupOwner{}
	opts, err := parseOptions(args)
	if err != nil {
		return record, owner, err
	}
	record["fixed_suite"] = opts.suite
	// This is before any artifact read, fixture creation, memfd or native clone.
	if err := registry.validate(); err != nil {
		return record, owner, err
	}
	if !registry.supportsSuite(opts.suite) {
		return record, owner, errUnreviewed
	}
	record["scope"] = registry.Receipt.Scope
	if supervise == nil {
		return record, owner, errors.New("fixed contributor supervisor required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return record, owner, supervise(ctx, opts, registry, record, owner)
}

func main() {
	var record map[string]any
	var err error
	var cleanup *cleanupOwner
	if len(os.Args) >= 2 && os.Args[1] == "--owned-fixed-worker" {
		record, cleanup, err = executeWorker(os.Args[2:])
	} else {
		record, cleanup, err = execute(os.Args[1:])
	}
	if err != nil {
		record["error"] = "fixed_contributor_admission_or_observation_failed"
		record["passed"] = false
	}
	writeErr := json.NewEncoder(os.Stdout).Encode(record)
	runtime.KeepAlive(cleanup) // pending custody remains reachable through reporting
	if writeErr != nil || err != nil {
		os.Exit(1)
	}
}

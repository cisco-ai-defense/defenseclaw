// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Fixed contributor outer custody. No production runtime or arbitrary launcher.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"
)

const outputLimit = 64 << 10
const scope = "fixed_linux_native_peer_outer_driver_v1"
const receiptSHA = "6db10d2a73ee7860bb0d7ad8a6155166d2b59e7d504513e1222a634aac55c668"

var errUnreviewed = errors.New("fixed wrapper artifact has no reviewed driver admission")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type wrapperAdmission struct {
	VersionOnly bool
	Reviewed    bool
	SHA         string
	Size        int64
}

// Source, Actions/archive/provenance and static image independently reviewed by
// two reviewers. This admits only the fixed contributor wrapper as an input;
// the driver needs its own build/image review before any run. No CLI/env override.
var liveAdmission = wrapperAdmission{Reviewed: true,
	SHA:  "485aa37bf8fda4aa35f41247c802931fd73decfac28eda60ed8ea44577f63e87",
	Size: 3473534,
}

func (a wrapperAdmission) validate() error {
	if !a.Reviewed || !digestPattern.MatchString(a.SHA) || a.Size < 64 || a.Size > 32<<20 {
		return errUnreviewed
	}
	return nil
}

type options struct{ receipt, evidence, suite string }
type driverRun func(context.Context, options, wrapperAdmission, map[string]any, *cleanupOwner) error

func digestBytes(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func execute(args []string, admission wrapperAdmission, run driverRun) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": scope, "passed": false, "execution_performed": false, "production_certification": false}
	owner := &cleanupOwner{}
	// Before metadata paths, filesystem reads, memfds or any native launch.
	if err := admission.validate(); err != nil {
		return record, owner, err
	}
	flags := flag.NewFlagSet("fixed-native-outer-driver", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	explicit := flags.Bool("run-fixed", false, "explicit reviewed fixed contributor experiment")
	var opts options
	flags.StringVar(&opts.receipt, "receipt", "", "fixed reviewed artifact metadata")
	flags.StringVar(&opts.evidence, "evidence", "", "fresh private wrapper evidence metadata")
	flags.StringVar(&opts.suite, "suite", "baseline", "fixed baseline or lifecycle suite")
	if flags.Parse(args) != nil || !*explicit || flags.NArg() != 0 || opts.receipt == "" || opts.evidence == "" || len(opts.receipt) > 4096 || len(opts.evidence) > 4096 || !validSuite(opts.suite) || admission.VersionOnly != (opts.suite == claudeVersionSuite) || run == nil {
		return record, owner, errors.New("fixed contributor selector and bounded metadata required")
	}
	record["fixed_suite"] = opts.suite
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return record, owner, run(ctx, opts, admission, record, owner)
}

func validSuite(suite string) bool {
	return suite == "baseline" || suite == "lifecycle" || suite == claudeVersionSuite
}

func bootstrapOptions(args []string) (options, error) {
	if (len(args) != 4 && len(args) != 6) || args[0] != "--receipt" || args[2] != "--evidence" || args[1] == "" || len(args[1]) > 4096 || args[3] == "" || len(args[3]) > 4096 {
		return options{}, errors.New("fixed bootstrap metadata required")
	}
	opts := options{receipt: args[1], evidence: args[3], suite: "baseline"}
	if len(args) == 6 {
		if args[4] != "--suite" || !validSuite(args[5]) {
			return options{}, errors.New("fixed bootstrap suite refused")
		}
		opts.suite = args[5]
	}
	return opts, nil
}

func main() {
	var record map[string]any
	var owner *cleanupOwner
	var err error
	if len(os.Args) > 1 && os.Args[1] == "--owned-wrapper-bootstrap" {
		record, owner, err = bootstrap(os.Args[2:], admissionForArgs(os.Args[2:]))
	} else {
		record, owner, err = execute(os.Args[1:], admissionForArgs(os.Args[1:]), runDriver)
	}
	if err != nil {
		record["error"] = "fixed_outer_driver_admission_or_observation_failed"
		record["passed"] = false
	}
	writeErr := json.NewEncoder(os.Stdout).Encode(record)
	runtime.KeepAlive(owner)
	if writeErr != nil || err != nil {
		os.Exit(1)
	}
}

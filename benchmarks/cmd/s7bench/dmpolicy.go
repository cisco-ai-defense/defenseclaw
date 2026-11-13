// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// dmLoopback reports whether a decision-model endpoint stays on this machine (a local stub or a tunnel to the proxy).
func dmLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// dmCorpusAllowed is the corpus allowlist of an external decision-model endpoint (rel-1-0-10 S1 cascade): the owner-trace corpora and any corpus
// not named in -dm-allow-corpus (names separated by "," or "+") are never sent to an endpoint that is not on this machine. A loopback endpoint
// (the local stub) has no restriction. An external endpoint without a corpus name or an allowlist is refused.
func dmCorpusAllowed(endpoint, corpus, allow string) error {
	if endpoint == "" || dmLoopback(endpoint) {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(allow), "*") {
		return fmt.Errorf("-dm-allow-corpus must name corpora; * is not accepted")
	}
	names := strings.FieldsFunc(allow, func(r rune) bool { return r == ',' || r == '+' })
	if len(names) == 0 {
		return fmt.Errorf("the decision model endpoint is not on this machine: -dm-allow-corpus must name the corpora that may be sent to it")
	}
	if corpus == "" {
		return fmt.Errorf("the decision model endpoint is not on this machine: -corpus-name is required to check -dm-allow-corpus")
	}
	for _, n := range names {
		if n == corpus {
			return nil
		}
	}
	return fmt.Errorf("corpus %q is not in -dm-allow-corpus: it may not be sent to the external decision model endpoint", corpus)
}

// dmKeyFromEnv checks the secret the gateway client reads (DEFENSECLAW_DECISION_MODEL_KEY); the value is never printed.
func dmKeyPresent() bool { return os.Getenv("DEFENSECLAW_DECISION_MODEL_KEY") != "" }

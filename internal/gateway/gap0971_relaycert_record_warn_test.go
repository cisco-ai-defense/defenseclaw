//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// downRecord is a leader whose record of live relay certificates cannot be
// read.
type downRecord struct{ *registry.FileStore }

func (downRecord) LiveRelayCert(context.Context, string, string) (registry.RelayCert, bool, error) {
	return registry.RelayCert{}, false, errors.New("leader: connection refused")
}

// GAP-0971: under flag, an attach that cannot reach the leader's record
// takes any certificate the CA signed (as before) and now writes a WARN
// audit row saying nothing was checked. Under refuse it is refused.
func TestGAP0971FlagAttachWithoutRecordWritesWarn(t *testing.T) {
	ca, store := tixRelayCA(t), gap0928Store(t)
	issue := gap0861New(ca, store, false, config.SubstrateRelayCertReissueFlag)
	_, _, r1, _ := gap0928Cert(t, issue)

	flag := gap0861New(ca, downRecord{store}, false, config.SubstrateRelayCertReissueFlag)
	if err := flag.attach(t, r1); err != nil {
		t.Fatalf("flag attach with the record unreachable: %v", err)
	}
	if want := []string{"WARN substrate.relay.cert_record_unavailable"}; !slices.Equal(flag.rows, want) {
		t.Fatalf("rows %v, want %v", flag.rows, want)
	}

	refuse := gap0861New(ca, downRecord{store}, true, "")
	if err := refuse.attach(t, r1); err == nil {
		t.Fatal("refuse attach with the record unreachable")
	}
	if len(refuse.rows) != 0 {
		t.Fatalf("refuse rows %v", refuse.rows)
	}
}

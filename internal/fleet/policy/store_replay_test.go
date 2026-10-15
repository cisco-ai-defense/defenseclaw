// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func testEmergencyRecord(seq, previous uint32, command EmergencyCommand) []byte {
	message := make([]byte, EmergencyMsgSize)
	binary.BigEndian.PutUint32(message[0:4], seq)
	binary.BigEndian.PutUint32(message[44:48], previous)
	message[8] = byte(command)
	copy(message[48:80], bytes.Repeat([]byte{0x5a}, 32))
	return message
}

func TestSQLiteEmergencyReplaySurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fleet-state")
	if err := safefile.ProtectDirectory(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policies.db")
	store, err := NewSQLitePolicyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	command := testEmergencyRecord(7, 0, EmergencyBlockAll)
	if err := store.SaveEmergency(1, 2, 7, command); err != nil {
		t.Fatal(err)
	}
	forceSync := testEmergencyRecord(9, 7, EmergencyForceSync)
	if err := store.SaveEmergency(1, 2, 9, forceSync); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewSQLitePolicyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seq, err := store.GetEmergencySeq()
	if err != nil || seq != 9 {
		t.Fatalf("durable sequence=%d err=%v, want 9", seq, err)
	}
	record, err := store.GetLastEmergency(1, 2)
	if err != nil || record == nil || record.Sequence != 9 || !bytes.Equal(record.Message, forceSync) {
		t.Fatalf("durable command=%+v err=%v", record, err)
	}
	history, err := store.GetEmergenciesAfter(1, 2, 0, 32)
	if err != nil || len(history) != 2 || !bytes.Equal(history[0].Message, command) || !bytes.Equal(history[1].Message, forceSync) {
		t.Fatalf("ordered BLOCK_ALL then FORCE_SYNC history=%+v err=%v", history, err)
	}
	page, err := store.GetEmergenciesAfter(1, 2, 7, 1)
	if err != nil || len(page) != 1 || page[0].Sequence != 9 {
		t.Fatalf("paged history=%+v err=%v", page, err)
	}
	if err := store.SaveEmergency(1, 2, 7, command); err == nil {
		t.Fatal("duplicate emergency sequence accepted")
	}
	if err := store.SaveEmergency(1, 3, 6, command); err == nil {
		t.Fatal("older global emergency sequence accepted")
	}
	if other, err := store.GetLastEmergency(1, 3); err != nil || other != nil {
		t.Fatalf("failed transaction wrote another fleet: %+v err=%v", other, err)
	}
	if err := store.SaveEmergency(1, 2, 10, testEmergencyRecord(10, 7, EmergencyReleaseLockdown)); err == nil {
		t.Fatal("command with skipped fleet predecessor accepted")
	}
}

func TestServiceReplaysLatestPolicyAndEmergencyOnce(t *testing.T) {
	svc, client, store := newTestService()
	blob := BuildPolicyBlob(2, 0, []byte{1, 2, 3})
	signed, err := svc.Sign(blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SavePolicy(1, 2, 2, blob, signed[len(blob):], "edge"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DistributeEmergency(context.Background(), 1, 2, EmergencyBlockAll); err != nil {
		t.Fatal(err)
	}
	emergency := client.getPublished()[0].Payload
	seq, err := svc.ReplayLatestForDevice(context.Background(), 1, 2, 1, 0)
	if err != nil || seq != 1 {
		t.Fatalf("replay seq=%d err=%v, want 1", seq, err)
	}
	msgs := client.getPublished()
	if len(msgs) != 3 || msgs[1].Topic != "defenseclaw/1/2/ota/policy" ||
		!bytes.Equal(msgs[1].Payload, signed) ||
		msgs[2].Topic != "defenseclaw/1/2/ota/emergency" ||
		!bytes.Equal(msgs[2].Payload, emergency) {
		t.Fatalf("replay did not publish exact stored signed policy/emergency: %+v", msgs)
	}
	seq, err = svc.ReplayLatestForDevice(context.Background(), 1, 2, 2, 1)
	if err != nil || seq != 1 || len(client.getPublished()) != 3 {
		t.Fatalf("up-to-date device received duplicate replay: seq=%d err=%v messages=%d", seq, err, len(client.getPublished()))
	}
}

func TestEmergencyHistoryPreservesBlockBeforeLaterForceAndCrossFleetGap(t *testing.T) {
	svc, client, store := newTestService()
	ctx := context.Background()
	if err := svc.DistributeEmergency(ctx, 1, 2, EmergencyBlockAll); err != nil {
		t.Fatal(err)
	}
	if err := svc.DistributeEmergency(ctx, 1, 2, EmergencyForceSync); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		if err := svc.DistributeEmergency(ctx, 1, 3, EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.DistributeEmergency(ctx, 1, 2, EmergencyRevokeSessions); err != nil {
		t.Fatal(err)
	}
	history, err := store.GetEmergenciesAfter(1, 2, 0, 32)
	if err != nil || len(history) != 3 {
		t.Fatalf("fleet-scoped history=%+v err=%v", history, err)
	}
	for i, want := range []struct {
		seq, previous uint32
		command       EmergencyCommand
	}{
		{1, 0, EmergencyBlockAll}, {2, 1, EmergencyForceSync}, {14, 2, EmergencyRevokeSessions},
	} {
		record := history[i]
		if record.Sequence != want.seq || record.Message[8] != byte(want.command) ||
			binary.BigEndian.Uint32(record.Message[44:48]) != want.previous {
			t.Fatalf("history[%d] breaks signed predecessor chain: %+v", i, record)
		}
		if err := svc.emergencySigner.Verify(record.Message[:48], record.Message[48:80]); err != nil {
			t.Fatalf("history[%d] HMAC invalid: %v", i, err)
		}
	}
	before := len(client.getPublished())
	last, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 0)
	if err != nil || last != 14 {
		t.Fatalf("replay last sequence=%d err=%v", last, err)
	}
	messages := client.getPublished()[before:]
	if len(messages) != 3 {
		t.Fatalf("replay sent %d messages instead of 3", len(messages))
	}
	for i, msg := range messages {
		if !bytes.Equal(msg.Payload, history[i].Message) || msg.Topic != "defenseclaw/1/2/ota/emergency" {
			t.Fatalf("replay[%d] changed signed bytes or tenant/fleet topic", i)
		}
	}
	if last, err := svc.ReplayLatestForDevice(ctx, 1, 2, 0, 14); err != nil || last != 14 || len(client.getPublished()) != before+3 {
		t.Fatalf("up-to-date device got duplicate history: last=%d err=%v", last, err)
	}
}

func TestEmergencyHistoryReplayPagesAt32(t *testing.T) {
	svc, _, store := newTestService()
	for i := 0; i < 33; i++ {
		if err := svc.DistributeEmergency(context.Background(), 1, 2, EmergencyForceSync); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.GetEmergenciesAfter(1, 2, 0, 32)
	if err != nil || len(first) != 32 || first[31].Sequence != 32 {
		t.Fatalf("first replay page=%d err=%v", len(first), err)
	}
	second, err := store.GetEmergenciesAfter(1, 2, 32, 32)
	if err != nil || len(second) != 1 || second[0].Sequence != 33 {
		t.Fatalf("second replay page=%+v err=%v", second, err)
	}
}

func TestPolicyReplayCooldownBoundsFleetBroadcasts(t *testing.T) {
	svc, client, store := newTestService()
	for _, version := range []uint16{2, 3} {
		blob := BuildPolicyBlob(version, 0, []byte{1, 2, 3})
		signed, err := svc.Sign(blob)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.SavePolicy(1, 2, uint32(version), blob, signed[len(blob):], "edge"); err != nil {
			t.Fatal(err)
		}
		if version == 2 {
			ctx := context.Background()
			for i := 0; i < 20; i++ {
				if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 1, 0); err != nil {
					t.Fatal(err)
				}
			}
			if got := len(client.getPublished()); got != 1 {
				t.Fatalf("repeated stale registrations amplified policy: %d broadcasts", got)
			}
			svc.policyReplayMu.Lock()
			svc.policyReplays[fleetKey(1, 2)] = policyReplayAttempt{version: 2, at: time.Now().Add(-31 * time.Second)}
			svc.policyReplayMu.Unlock()
			if _, err := svc.ReplayLatestForDevice(ctx, 1, 2, 1, 0); err != nil || len(client.getPublished()) != 2 {
				t.Fatalf("expired cooldown did not retry: %v", err)
			}
		}
	}
	if _, err := svc.ReplayLatestForDevice(context.Background(), 1, 2, 1, 0); err != nil || len(client.getPublished()) != 3 {
		t.Fatalf("new version did not bypass cooldown: %v", err)
	}
}

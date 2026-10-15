// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
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
	path := filepath.Join(t.TempDir(), "policies.db")
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

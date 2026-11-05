// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// cowork-1-0-8 GAP-0067: an exec's image digest state crosses with the exec,
// and the digest read after the exec went out travels in a member of its
// own. A gateway that predates both ignores the state and skips the member,
// seeing every exec as before; a helper that predates them sends neither.
func TestImageDigestsTravelInTheirOwnFrame(t *testing.T) {
	at := time.Unix(0, 1_791_336_250_111_000_000)
	exec := plane.Event{Kind: plane.KindExec, PID: 42, Name: "claude", Cmdline: "claude -p x", At: at,
		ImageVersion: "2.1.317", ImageDigestState: plane.DigestPending, Fork: true}
	digest := plane.Event{Kind: plane.KindImageDigest, PID: 42, At: at, ImageVersion: "2.1.317",
		ImageSHA256: "ab12", ImageDigestState: plane.DigestRead}

	stub := newStubSource(tetragonCoverage())
	helper := serveStub(t, ServerConfig{}, stubAcquirer{stub})
	source := helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stub.events <- exec
	stub.events <- digest
	var got []plane.Event
	for len(got) < 2 {
		select {
		case event := <-source.Events():
			got = append(got, event)
		case <-time.After(5 * time.Second):
			t.Fatalf("events %+v", got)
		}
	}
	if !reflect.DeepEqual(got, []plane.Event{exec, digest}) {
		t.Fatalf("got\n %+v\nwant\n %+v", got, []plane.Event{exec, digest})
	}

	// The gateway of 1.0.8 and before, on a helper of its own.
	stub = newStubSource(tetragonCoverage())
	helper = serveStub(t, ServerConfig{}, stubAcquirer{stub})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{Version: protocolVersion, Op: OpEvents}, requestDeadline); err != nil {
		t.Fatal(err)
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		t.Fatal(err)
	}
	type oldFrame struct {
		Event *struct {
			Kind         string `json:"kind"`
			PID          int    `json:"pid"`
			ImageVersion string `json:"image_version"`
		} `json:"event"`
		PolicyEvent *json.RawMessage `json:"policy_event"`
	}
	stub.events <- exec
	stub.events <- digest
	stub.events <- plane.Event{Kind: plane.KindExit, PID: 42}
	var kinds []string
	skipped := 0
	for len(kinds) < 2 {
		var response Response
		if err := readFrame(conn, &response, 5*time.Second); err != nil {
			t.Fatalf("after %v: %v", kinds, err)
		}
		var frame oldFrame
		if err := json.Unmarshal(response.Body, &frame); err != nil || frame.Event == nil {
			if frame.PolicyEvent != nil {
				t.Fatal("an image digest went out as a policy event")
			}
			skipped++
			continue
		}
		kinds = append(kinds, frame.Event.Kind)
	}
	if !reflect.DeepEqual(kinds, []string{"exec", "exit"}) || skipped != 1 {
		t.Fatalf("an old gateway saw %v and skipped %d frames", kinds, skipped)
	}

	// GAP-0071 (S1 review 3 F3): events the gateway's own buffer for the
	// helper stream drops are named in the coverage.
	gateway := &helperPlaneSource{buffer: plane.NewBuffer(), coverage: plane.Coverage{Mechanism: "cn_proc"}}
	if limits := gateway.Coverage().Limitations; len(limits) != 0 {
		t.Fatalf("limitations before any drop: %v", limits)
	}
	for index := 0; index <= 4096; index++ {
		gateway.buffer.Push(plane.Event{Kind: plane.KindFileRead, PID: index})
	}
	if limits := gateway.Coverage().Limitations; len(limits) != 1 ||
		limits[0] != "1 events from the sensor helper were dropped from the gateway's event buffer under back-pressure" {
		t.Fatalf("gateway buffer limitations = %v", limits)
	}

	// An exec from a helper that predates the state decodes with none.
	var wire wireEvent
	if err := json.Unmarshal([]byte(`{"kind":"exec","pid":7,"image_version":"2.1.317"}`), &wire); err != nil {
		t.Fatal(err)
	}
	if event := decodeEvent(wire); event.ImageDigestState != "" || event.Fork || event.ImageVersion != "2.1.317" {
		t.Fatalf("old helper exec = %+v", event)
	}
}

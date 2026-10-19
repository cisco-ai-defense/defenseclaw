// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func preparationFixture(t *testing.T) (Preparation, Binding) {
	t.Helper()
	plan := Preparation{
		Backend: "bubblewrap", Argv: []string{"/fixed/bootstrap", "", "a b", `a"b`, "λ-雪", `tail\`, "$HOME;$(fixed)&|<>"},
		Environment: []Variable{{Name: "HOME", Value: "/fixed/home"}}, Workdir: "/fixed/work",
		Filesystem: Filesystem{Read: []string{"/fixed/bootstrap"}, Write: []string{"/fixed/work"}, Deny: []string{}},
		Offline:    true, Terminal: &Size{Rows: 30, Columns: 100}, TimeoutMS: 30000, OutputLimit: 1 << 20,
	}
	digest, err := PreparationDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{SessionID: "fixed-session", SessionDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), RuntimeDigest: "sha256:" + strings.Repeat("c", 64),
		HarnessDigest: "sha256:" + strings.Repeat("d", 64), PreparationHash: digest}
	return plan, binding
}

func fixtureFrame(t *testing.T) Frame {
	t.Helper()
	plan, binding := preparationFixture(t)
	return Frame{Version: Version, Sequence: 1, Request: 1, Binding: binding, Kind: Prepare, Plan: &plan}
}

func TestProtocolLiteralPreparationRoundTripAndNoReadAhead(t *testing.T) {
	want := fixtureFrame(t)
	// Independently computed with Python struct.pack big-endian primitives.
	if want.Binding.PreparationHash != "sha256:2b70112993942ea7aecfe3d146550fcda20a7de01f9646e5223e07f637ae9174" {
		t.Fatal("cross-language preparation digest vector changed")
	}
	var stream bytes.Buffer
	encoder := NewEncoder(&stream)
	if err := encoder.Encode(want); err != nil {
		t.Fatal(err)
	}
	stream.WriteString("fixed-next-frame-sentinel")
	got, err := NewDecoder(&stream).Decode()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("literal roundtrip changed: %v", err)
	}
	if stream.String() != "fixed-next-frame-sentinel" {
		t.Fatal("decoder consumed bytes beyond the admitted frame")
	}
}

func TestProtocolRejectsAmbiguousJSONAndPoisonsStream(t *testing.T) {
	encoded, err := json.Marshal(fixtureFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	cases := map[string][]byte{
		"duplicate":        []byte(strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1)),
		"case_alias":       []byte(strings.Replace(valid, `"version":1`, `"version":1,"Version":1`, 1)),
		"unknown_nested":   []byte(strings.Replace(valid, `"rows":30`, `"rows":30,"unknown":0`, 1)),
		"duplicate_nested": []byte(strings.Replace(valid, `"rows":30`, `"rows":30,"rows":30`, 1)),
		"missing_required": []byte(strings.Replace(valid, `"rows":30,`, "", 1)),
		"null_payload":     []byte(strings.Replace(valid, `"terminal":{"rows":30,"columns":100}`, `"terminal":null`, 1)),
		"null_scalar":      []byte(strings.Replace(valid, `"offline":true`, `"offline":null`, 1)),
		"trailing":         append(bytes.Clone(encoded), []byte(` {}`)...),
		"nul":              []byte(strings.Replace(valid, `"a b"`, `"a\u0000b"`, 1)),
		"invalid_utf8":     bytes.Replace(encoded, []byte("a b"), []byte{'a', 0xff, 'b'}, 1),
		"unpaired_high":    []byte(strings.Replace(valid, `"a b"`, `"a\ud800b"`, 1)),
		"unpaired_low":     []byte(strings.Replace(valid, `"a b"`, `"a\udc00b"`, 1)),
		"deep":             []byte(strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(data, encoded) {
				t.Fatal("negative case did not mutate the valid frame")
			}
			var stream bytes.Buffer
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(data)))
			stream.Write(header[:])
			stream.Write(data)
			stream.WriteString("next")
			decoder := NewDecoder(&stream)
			if _, err := decoder.Decode(); !errors.Is(err, ErrProtocol) {
				t.Fatalf("ambiguous JSON accepted: %v", err)
			}
			remaining := stream.Len()
			if _, err := decoder.Decode(); !errors.Is(err, ErrProtocol) || stream.Len() != remaining {
				t.Fatal("poisoned stream retried input")
			}
		})
	}
}

func TestProtocolUnicodeEscapeDomain(t *testing.T) {
	for _, value := range []string{`"\ud83d\ude80"`, `"literal\\ud800"`, `"\ufffd"`, `"雪"`} {
		if !pairedUnicodeEscapes([]byte(value)) {
			t.Fatalf("valid lossless Unicode rejected: %s", value)
		}
	}
	for _, value := range []string{`"\ud83d"`, `"\ude80"`, `"\ud83d\u0041"`, `"\ud83d\ud83d"`} {
		if pairedUnicodeEscapes([]byte(value)) {
			t.Fatal("lossy Unicode accepted")
		}
	}
}

type boundedRead struct{ calls int }

func (r *boundedRead) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("body must not be read")
}

type partialWriter struct{ calls int }

func (w *partialWriter) Write(data []byte) (int, error) {
	w.calls++
	return min(1, len(data)), io.ErrClosedPipe
}

func TestProtocolLengthAndPartialIOFailuresRemainClosed(t *testing.T) {
	for _, size := range []uint32{0, MaxFrameBytes + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		body := &boundedRead{}
		decoder := NewDecoder(io.MultiReader(bytes.NewReader(header[:]), body))
		if _, err := decoder.Decode(); !errors.Is(err, ErrProtocol) || body.calls != 0 {
			t.Fatal("invalid length caused body read/allocation")
		}
	}
	for _, truncated := range [][]byte{{0, 0}, {0, 0, 0, 3, '{'}} {
		decoder := NewDecoder(bytes.NewReader(truncated))
		if _, err := decoder.Decode(); err == nil {
			t.Fatal("truncated pipe accepted")
		}
	}
	writer := &partialWriter{}
	encoder := NewEncoder(writer)
	if err := encoder.Encode(fixtureFrame(t)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("partial pipe write not surfaced")
	}
	if err := encoder.Encode(fixtureFrame(t)); !errors.Is(err, io.ErrClosedPipe) || writer.calls != 1 {
		t.Fatal("partial frame was retried")
	}
}

func TestProtocolPreparationRefusesChangedPlanAndWindowsEnvAliases(t *testing.T) {
	frame := fixtureFrame(t)
	frame.Plan.Argv[1] = "changed after binding"
	if frame.Validate() == nil {
		t.Fatal("changed preparation accepted under old digest")
	}
	plan, _ := preparationFixture(t)
	plan.Backend, plan.Argv[0], plan.Workdir = "windows_psec", `C:\fixed\bootstrap.exe`, `C:\fixed\work`
	plan.Filesystem = Filesystem{Read: []string{}, Write: []string{}, Deny: []string{}}
	plan.Environment = []Variable{{Name: "Path", Value: "fixed"}, {Name: "PATH", Value: "other"}}
	if plan.Validate() == nil {
		t.Fatal("case-insensitive Windows env alias accepted")
	}
	plan.Environment = []Variable{}
	if plan.Validate() != nil {
		t.Fatal("explicit empty Windows environment refused")
	}
	plan.Offline = false
	if plan.Validate() == nil {
		t.Fatal("unqualified broker/network route accepted")
	}
}

func runningConversation(t *testing.T) (*Conversation, Binding) {
	t.Helper()
	frame := fixtureFrame(t)
	conversation, err := NewConversation(frame.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := conversation.Host(frame); err != nil {
		t.Fatal(err)
	}
	frame.Plan, frame.Kind = nil, Prepared
	if err := conversation.Bridge(frame); err != nil {
		t.Fatal(err)
	}
	frame.Sequence, frame.Request, frame.Kind = 2, 2, Launch
	if err := conversation.Host(frame); err != nil {
		t.Fatal(err)
	}
	frame.Kind = Started
	if err := conversation.Bridge(frame); err != nil {
		t.Fatal(err)
	}
	return conversation, frame.Binding
}

func TestProtocolRunningCancellationCompletionAndDestroy(t *testing.T) {
	c, binding := runningConversation(t)
	host := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 3, Kind: Wait}
	if err := c.Host(host); err != nil {
		t.Fatal(err)
	}
	host.Sequence, host.Request, host.Kind = 4, 4, Cancel
	if err := c.Host(host); err != nil || c.Phase() != PhaseStopping {
		t.Fatal("cancel did not enter stopping")
	}
	reply := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 2, Kind: Output,
		Data: &Data{Stream: "stdout", Bytes: []byte{0, 255, '\n'}}}
	if err := c.Bridge(reply); err != nil {
		t.Fatal("bounded output while stopping refused")
	}
	reply.Sequence, reply.Request, reply.Kind, reply.Data = 4, 2, Exited, nil
	reply.Result = &Result{ExitCode: 23}
	if err := c.Bridge(reply); err != nil || c.Phase() != PhaseExited {
		t.Fatal("completion did not match its launch")
	}
	host.Sequence, host.Request, host.Kind = 5, 5, Destroy
	if err := c.Host(host); err != nil {
		t.Fatal(err)
	}
	reply.Sequence, reply.Request, reply.Kind, reply.Result = 5, 5, Destroyed, nil
	if err := c.Bridge(reply); err != nil || c.Phase() != PhaseDestroyed || c.PeerClosed() {
		t.Fatal("owned destroy completion not recorded")
	}
}

func TestProtocolCompletionCrossingInFlightControls(t *testing.T) {
	host, binding := runningConversation(t)
	bridge, _ := runningConversation(t)
	exit := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 2, Kind: Exited, Result: &Result{ExitCode: 23}}
	if err := bridge.Bridge(exit); err != nil {
		t.Fatal(err)
	}
	// The helper already emitted completion, but the owner has not received
	// it. These bounded controls must become no-ops at the completed helper.
	for index, kind := range []Kind{Input, InputEOF, Resize, Wait, Cancel} {
		frame := Frame{Version: Version, Binding: binding, Sequence: uint64(index + 3), Request: uint64(index + 3), Kind: kind}
		if kind == Input {
			frame.Data = &Data{Stream: "stdin", Bytes: []byte("fixed")}
		}
		if kind == Resize {
			frame.Size = &Size{Rows: 40, Columns: 160}
		}
		if host.Host(frame) != nil || bridge.Host(frame) != nil {
			t.Fatalf("legitimate completion/control crossing refused for %s", kind)
		}
	}
	if host.Bridge(exit) != nil || host.Phase() != PhaseExited || bridge.Phase() != PhaseExited {
		t.Fatal("two-way completion ordering diverged")
	}
	destroy := Frame{Version: Version, Binding: binding, Sequence: 8, Request: 8, Kind: Destroy}
	if host.Host(destroy) != nil || bridge.Host(destroy) != nil {
		t.Fatal("crossed completion could not be destroyed")
	}
	destroy.Sequence, destroy.Kind = 4, Destroyed
	if host.Bridge(destroy) != nil || bridge.Bridge(destroy) != nil {
		t.Fatal("destroy acknowledgement diverged")
	}
}

func TestProtocolOutputLimitIncludesAllAcceptedFrames(t *testing.T) {
	c, binding := runningConversation(t)
	frame := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 2, Kind: Output,
		Data: &Data{Stream: "stdout", Bytes: make([]byte, MaxDataBytes)}}
	for range (1 << 20) / MaxDataBytes {
		if err := c.Bridge(frame); err != nil {
			t.Fatal("output at admitted aggregate limit refused")
		}
		frame.Sequence++
	}
	frame.Data.Bytes = []byte{1}
	if !errors.Is(c.Bridge(frame), ErrProtocol) || !c.PeerClosed() {
		t.Fatal("peer exceeded aggregate output without containment refusal")
	}
}

func TestProtocolAdmittedFailureStillRequiresOwnedCleanup(t *testing.T) {
	c, binding := runningConversation(t)
	frame := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 2, Kind: Failed,
		Failure: &Failure{Code: "io_failed"}}
	if err := c.Bridge(frame); err != nil || c.Phase() != PhaseClosed || !c.PeerClosed() {
		t.Fatal("accepted terminal failure did not preserve cleanup obligation")
	}
}

func TestProtocolReplaysForeignBindingsAndEarlyLaunchPermanentlyRefuse(t *testing.T) {
	for _, attack := range []string{"replay", "request_replay", "foreign_binding", "bridge_command", "early_exit", "output_after_eof"} {
		t.Run(attack, func(t *testing.T) {
			c, binding := runningConversation(t)
			frame := Frame{Version: Version, Binding: binding, Sequence: 3, Request: 3, Kind: Cancel}
			var err error
			switch attack {
			case "replay":
				frame.Sequence = 2
				err = c.Host(frame)
			case "request_replay":
				frame.Request = 2
				err = c.Host(frame)
			case "foreign_binding":
				frame.Binding.SessionID = "other-session"
				err = c.Host(frame)
			case "bridge_command":
				err = c.Bridge(frame)
			case "early_exit":
				frame.Kind = Exited
				frame.Result = &Result{}
				err = c.Bridge(frame) // request3 was never issued; launch is2
			case "output_after_eof":
				frame.Kind = InputEOF
				if err := c.Host(frame); err != nil {
					t.Fatal(err)
				}
				frame.Sequence, frame.Request, frame.Kind = 4, 4, Input
				frame.Data = &Data{Stream: "stdin", Bytes: []byte("fixed")}
				err = c.Host(frame)
			}
			if !errors.Is(err, ErrProtocol) || c.Phase() != PhaseClosed || !c.PeerClosed() {
				t.Fatal("invalid conversation did not close with resources outstanding")
			}
			frame = Frame{Version: Version, Binding: binding, Sequence: 3, Request: 3, Kind: Cancel}
			if c.Host(frame) == nil {
				t.Fatal("closed conversation resumed")
			}
		})
	}
	frame := fixtureFrame(t)
	c, _ := NewConversation(frame.Binding)
	frame.Plan, frame.Kind = nil, Launch
	if c.Host(frame) == nil {
		t.Fatal("unprepared launch accepted")
	}
}

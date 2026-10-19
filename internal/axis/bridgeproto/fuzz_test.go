// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// These fuzz targets exercise parser and conversation admission only. They
// neither start a helper nor establish native containment or cleanup.
func fuzzPreparation() Preparation {
	return Preparation{
		Backend: "bubblewrap", Argv: []string{"/fixed/child", "a b", "雪", "🚀"},
		Environment: []Variable{}, Workdir: "/fixed/work",
		Filesystem: Filesystem{Read: []string{"/fixed/child"}, Write: []string{"/fixed/work"}, Deny: []string{}},
		Offline:    true, Terminal: &Size{Rows: 24, Columns: 80}, TimeoutMS: 250, OutputLimit: 1024,
	}
}

// Build valid, digest-bound frames and then make one unambiguous JSON
// mutation. The negative cases must refuse even when encoding/json could
// otherwise discard an alias or replace an invalid surrogate with U+FFFD.
func FuzzStrictFrameMutations(f *testing.F) {
	frame, err := fuzzPrepareFrame()
	if err != nil {
		f.Fatal(err)
	}
	base, err := json.Marshal(frame)
	if err != nil {
		f.Fatal(err)
	}
	for mode := uint8(0); mode < 14; mode++ {
		f.Add(mode, []byte("fixed"))
	}
	f.Fuzz(func(t *testing.T, mode uint8, payload []byte) {
		if len(payload) > 256 {
			payload = payload[:256]
		}
		value, err := json.Marshal(string(payload))
		if err != nil {
			t.Fatal(err)
		}
		variant := mode % 14
		trial := frame
		var changed []byte
		wantValid := false
		switch variant {
		case 0: // exact duplicate, including a same-value duplicate
			changed = append([]byte(`{"version":1,`), base[1:]...)
		case 1: // case-insensitive decoder alias
			changed = append([]byte(`{"Version":1,`), base[1:]...)
		case 2: // decoded escaped key collides with version
			changed = append([]byte(`{"\u0076ersion":1,`), base[1:]...)
		case 3:
			changed = append(append([]byte(`{"unknown":`), value...), ',')
			changed = append(changed, base[1:]...)
		case 4:
			changed = bytes.Replace(base, []byte(`"binding":{`),
				[]byte(`"binding":{"session_id":"fixed-fuzz-session",`), 1)
		case 5:
			changed = bytes.Replace(base, []byte(`"plan":{`),
				[]byte(`"plan":{"argv":["/fixed/child","a b","雪","🚀"],`), 1)
		case 6:
			changed = bytes.Replace(base, []byte(`"offline":true`), []byte(`"offline":null`), 1)
		case 7:
			changed = append([]byte(`{"failure":null,`), base[1:]...)
		case 8:
			changed = append(bytes.Clone(base), []byte(` {}`)...)
		case 9:
			changed = bytes.Replace(base, []byte(`"rows":24`), []byte(`"rows":24,"unknown":0`), 1)
		case 10, 11:
			plan := fuzzPreparation()
			plan.Argv[1] = "fixed-" + hex.EncodeToString(payload[:min(len(payload), 16)]) + "�-end"
			digest, err := PreparationDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			trial.Plan, trial.Binding.PreparationHash = &plan, digest
			lossyBase, err := json.Marshal(trial)
			if err != nil {
				t.Fatal(err)
			}
			escape := []byte(`\ud800`)
			if variant == 11 {
				escape = []byte(`\udc00`)
			}
			changed = bytes.Replace(lossyBase, []byte("�"), escape, 1)
		case 12: // valid escaped pair preserves the bound literal rocket
			changed = bytes.Replace(base, []byte("🚀"), []byte(`\ud83d\ude80`), 1)
			wantValid = true
		case 13: // two literal backslashes are not a Unicode escape
			plan := fuzzPreparation()
			plan.Argv[1] = `literal\ud800`
			digest, err := PreparationDigest(plan)
			if err != nil {
				t.Fatal(err)
			}
			trial.Plan, trial.Binding.PreparationHash = &plan, digest
			changed, err = json.Marshal(trial)
			if err != nil {
				t.Fatal(err)
			}
			wantValid = true
		}
		if len(changed) == 0 {
			t.Fatal("mutation did not produce a frame")
		}
		got, err := Parse(changed)
		if wantValid {
			if err != nil || !reflect.DeepEqual(got, trial) {
				t.Fatalf("lossless Unicode form refused or changed: %v", err)
			}
		} else if !errors.Is(err, ErrProtocol) {
			t.Fatalf("ambiguous or lossy JSON mutation admitted: mode=%d err=%v", variant, err)
		}
	})
}

func fuzzPrepareFrame() (Frame, error) {
	plan := fuzzPreparation()
	digest, err := PreparationDigest(plan)
	if err != nil {
		return Frame{}, err
	}
	binding := Binding{
		SessionID: "fixed-fuzz-session", SessionDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), RuntimeDigest: "sha256:" + strings.Repeat("c", 64),
		HarnessDigest: "sha256:" + strings.Repeat("d", 64), PreparationHash: digest,
	}
	return Frame{Version: Version, Sequence: 1, Request: 1, Binding: binding, Kind: Prepare, Plan: &plan}, nil
}

func fuzzWire(size uint32, body []byte) []byte {
	wire := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(wire, size)
	return append(wire, body...)
}

func FuzzParseFrame(f *testing.F) {
	frame, err := fuzzPrepareFrame()
	if err != nil {
		f.Fatal(err)
	}
	valid, err := json.Marshal(frame)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid, nil, []byte(`{}`), []byte(`[]`), []byte(`null`),
		[]byte(`{"version":1,"version":1}`), []byte(`{"Version":1}`),
		[]byte(`{"plan":{"argv":["\ud800"]}}`),
		[]byte(`{"plan":{"argv":["\udc00"]}}`),
		[]byte(`{"plan":{"argv":["\ud83d\ude80"]}}`),
		[]byte(`{"plan":{"argv":["literal\\ud800"]}}`),
		[]byte(strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26)),
		append(bytes.Clone(valid), []byte(` {}`)...),
		bytes.Replace(valid, []byte("雪"), []byte{0xff}, 1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		parsed, err := Parse(raw)
		if len(raw) > MaxFrameBytes && err == nil {
			t.Fatal("oversized frame parsed")
		}
		if err != nil {
			return
		}
		if err := parsed.Validate(); err != nil {
			t.Fatalf("parser returned invalid frame: %v", err)
		}
		canonical, err := json.Marshal(parsed)
		if err != nil {
			t.Fatalf("accepted frame cannot marshal: %v", err)
		}
		if len(canonical) > MaxFrameBytes {
			return // canonical escaping can grow beyond the wire cap
		}
		again, err := Parse(canonical)
		if err != nil || !reflect.DeepEqual(again, parsed) {
			t.Fatalf("accepted frame changed on canonical roundtrip: %v", err)
		}
		var stream bytes.Buffer
		if err := NewEncoder(&stream).Encode(parsed); err != nil {
			t.Fatalf("accepted bounded frame cannot encode: %v", err)
		}
		stream.WriteString("fixed-next-frame-sentinel")
		decoded, err := NewDecoder(&stream).Decode()
		if err != nil || !reflect.DeepEqual(decoded, parsed) || stream.String() != "fixed-next-frame-sentinel" {
			t.Fatalf("accepted frame changed or decoder read ahead: %v", err)
		}
	})
}

func FuzzFrameLength(f *testing.F) {
	frame, err := fuzzPrepareFrame()
	if err != nil {
		f.Fatal(err)
	}
	valid, err := json.Marshal(frame)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		nil, {0, 0, 0}, fuzzWire(0, valid), fuzzWire(MaxFrameBytes+1, valid),
		fuzzWire(^uint32(0), nil), fuzzWire(uint32(len(valid)), valid),
		fuzzWire(uint32(len(valid)+1), valid), fuzzWire(uint32(len(valid)-1), valid),
		append(fuzzWire(uint32(len(valid)), valid), []byte("sentinel")...),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 2*MaxFrameBytes+4 {
			wire = wire[:2*MaxFrameBytes+4]
		}
		reader := bytes.NewReader(wire)
		decoder := NewDecoder(reader)
		got, err := decoder.Decode()
		if len(wire) < 4 {
			if err == nil {
				t.Fatal("truncated header decoded")
			}
		} else {
			size := binary.BigEndian.Uint32(wire[:4])
			switch {
			case size == 0 || size > MaxFrameBytes:
				if !errors.Is(err, ErrProtocol) || reader.Len() != len(wire)-4 {
					t.Fatalf("invalid length consumed body or was admitted: %v", err)
				}
			case uint64(size) > uint64(len(wire)-4):
				if err == nil {
					t.Fatal("truncated body decoded")
				}
			default:
				want, parseErr := Parse(wire[4 : 4+size])
				if (err == nil) != (parseErr == nil) || err == nil && !reflect.DeepEqual(got, want) {
					t.Fatalf("decoder disagrees with bounded parser: decode=%v parse=%v", err, parseErr)
				}
				if reader.Len() != len(wire)-4-int(size) {
					t.Fatal("decoder read beyond declared length")
				}
			}
		}
		if err != nil {
			remaining := reader.Len()
			if _, again := decoder.Decode(); again != err || reader.Len() != remaining {
				t.Fatal("failed decoder retried or consumed more input")
			}
		}
	})
}

// This reference follows the documented length-prefix format through a
// separate buffer writer, rather than using the implementation's append path.
func fuzzReferencePreparationDigest(p Preparation) string {
	var encoded bytes.Buffer
	encoded.WriteString("defenseclaw-mxc-preparation-v1\x00")
	put32 := func(value uint32) {
		var word [4]byte
		binary.BigEndian.PutUint32(word[:], value)
		encoded.Write(word[:])
	}
	putString := func(value string) {
		put32(uint32(len(value)))
		encoded.WriteString(value)
	}
	putStrings := func(values []string) {
		put32(uint32(len(values)))
		for _, value := range values {
			putString(value)
		}
	}
	putString(p.Backend)
	putStrings(p.Argv)
	put32(uint32(len(p.Environment)))
	for _, variable := range p.Environment {
		putString(variable.Name)
		putString(variable.Value)
	}
	putString(p.Workdir)
	putStrings(p.Filesystem.Read)
	putStrings(p.Filesystem.Write)
	putStrings(p.Filesystem.Deny)
	encoded.WriteByte(1)
	if p.Terminal == nil {
		encoded.WriteByte(0)
	} else {
		encoded.WriteByte(1)
		var pair [4]byte
		binary.BigEndian.PutUint16(pair[:2], p.Terminal.Rows)
		binary.BigEndian.PutUint16(pair[2:], p.Terminal.Columns)
		encoded.Write(pair[:])
	}
	put32(p.TimeoutMS)
	put32(p.OutputLimit)
	sum := sha256.Sum256(encoded.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

func FuzzPreparationDigest(f *testing.F) {
	for _, seed := range []struct {
		arg, value string
		flags      uint8
	}{
		{"", "", 0}, {`a b";$(fixed)`, "雪", 1}, {`tail\`, "literal\\ud800", 2},
		{"\x00", "fixed", 4}, {"fixed", "\xff", 8}, {"fixed", "fixed", 255},
	} {
		f.Add(seed.arg, seed.value, seed.flags)
	}
	f.Fuzz(func(t *testing.T, arg, value string, flags uint8) {
		if len(arg) > 128<<10 || len(value) > 32<<10 {
			return
		}
		plan := fuzzPreparation()
		plan.Argv[1] = arg
		plan.Environment = []Variable{{Name: "DC_FIXED", Value: value}}
		if flags&1 != 0 {
			plan.Backend = "seatbelt"
			plan.Filesystem.Deny = []string{"/fixed/denied"}
		}
		if flags&2 != 0 {
			plan.Backend, plan.Argv[0], plan.Workdir = "windows_psec", `C:\fixed\child.exe`, `C:\fixed\work`
			plan.Filesystem = Filesystem{Read: []string{`C:\fixed\child.exe`}, Write: []string{`C:\fixed\work`}, Deny: []string{}}
		}
		if flags&4 != 0 {
			plan.Terminal = nil
		}
		if flags&8 != 0 {
			plan.Offline = false
		}
		if flags&16 != 0 {
			plan.OutputLimit = 0
		}
		plan.TimeoutMS += uint32(flags)
		digest, err := PreparationDigest(plan)
		if plan.Validate() != nil {
			if err == nil {
				t.Fatal("invalid preparation acquired a digest")
			}
			return
		}
		if err != nil || digest != fuzzReferencePreparationDigest(plan) {
			t.Fatalf("preparation digest differs from documented binary encoding: %v", err)
		}
		encoded, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Preparation
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		again, err := PreparationDigest(decoded)
		if err != nil || again != digest {
			t.Fatal("JSON transport changed preparation identity")
		}
	})
}

func fuzzRunningConversation(t *testing.T) (*Conversation, Frame) {
	t.Helper()
	prepare, err := fuzzPrepareFrame()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConversation(prepare.Binding)
	if err != nil || c.Host(prepare) != nil {
		t.Fatal("fixed preparation refused")
	}
	prepared := Frame{Version: Version, Sequence: 1, Request: 1, Binding: prepare.Binding, Kind: Prepared}
	launch := Frame{Version: Version, Sequence: 2, Request: 2, Binding: prepare.Binding, Kind: Launch}
	started := Frame{Version: Version, Sequence: 2, Request: 2, Binding: prepare.Binding, Kind: Started}
	if c.Bridge(prepared) != nil || c.Host(launch) != nil || c.Bridge(started) != nil {
		t.Fatal("fixed launch trace refused")
	}
	return c, prepare
}

func FuzzConversationOrdering(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {1, 2, 3}, {0xff, 0x20, 0x40, 0x80}, []byte("fixed-cross-direction-controls")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, actions []byte) {
		if len(actions) > 128 {
			actions = actions[:128]
		}
		owner, prepare := fuzzRunningConversation(t)
		peer, _ := fuzzRunningConversation(t)
		binding := prepare.Binding
		output := Frame{Version: Version, Sequence: 3, Request: 2, Binding: binding, Kind: Output,
			Data: &Data{Stream: "stdout", Bytes: []byte{byte(len(actions)), 0}}}
		exit := Frame{Version: Version, Sequence: 4, Request: 2, Binding: binding, Kind: Exited,
			Result: &Result{ExitCode: 23}}
		if peer.Bridge(output) != nil || peer.Bridge(exit) != nil {
			t.Fatal("fixed peer output/completion refused")
		}
		next := uint64(3)
		for _, action := range actions[:min(len(actions), 8)] {
			control := Frame{Version: Version, Sequence: next, Request: next, Binding: binding}
			if action&1 == 0 {
				control.Kind, control.Data = Input, &Data{Stream: "stdin", Bytes: []byte{action}}
			} else {
				control.Kind, control.Size = Resize, &Size{Rows: uint16(action) + 1, Columns: 80}
			}
			if owner.Host(control) != nil || peer.Host(control) != nil {
				t.Fatal("crossed fixed input/resize refused")
			}
			next++
		}
		for _, kind := range []Kind{Wait, InputEOF, Cancel} {
			control := Frame{Version: Version, Sequence: next, Request: next, Binding: binding, Kind: kind}
			if owner.Host(control) != nil || peer.Host(control) != nil {
				t.Fatalf("crossed %s refused", kind)
			}
			next++
		}
		if owner.Bridge(output) != nil || owner.Bridge(exit) != nil || owner.Phase() != peer.Phase() {
			t.Fatal("crossed completion diverged")
		}
		destroy := Frame{Version: Version, Sequence: next, Request: next, Binding: binding, Kind: Destroy}
		ack := Frame{Version: Version, Sequence: 5, Request: next, Binding: binding, Kind: Destroyed}
		if owner.Host(destroy) != nil || peer.Host(destroy) != nil || owner.Bridge(ack) != nil || peer.Bridge(ack) != nil ||
			owner.Phase() != PhaseDestroyed || peer.Phase() != PhaseDestroyed {
			t.Fatal("crossed trace failed to destroy exact session")
		}

		// Arbitrary ordered and malformed commands must either be admitted in
		// sequence or permanently close the conversation on the first refusal.
		c, _ := fuzzRunningConversation(t)
		kinds := []Kind{Input, InputEOF, Resize, Wait, Cancel, Destroy, Output, Exited, Destroyed, Failed, Prepared, Started, Launch, Prepare}
		for _, action := range actions {
			kind := kinds[int(action)%len(kinds)]
			toHost := kind == Input || kind == InputEOF || kind == Resize || kind == Wait || kind == Cancel || kind == Destroy || kind == Launch || kind == Prepare
			if action&16 != 0 {
				toHost = !toHost
			}
			frame := Frame{Version: Version, Binding: binding, Kind: kind}
			if toHost {
				frame.Sequence, frame.Request = c.hostSeq+1, c.lastRequest+1
			} else {
				frame.Sequence, frame.Request = c.bridgeSeq+1, c.launch
				switch kind {
				case Prepared:
					frame.Request = c.prepare
				case Destroyed:
					frame.Request = c.destroy
				case Failed:
					frame.Request = c.lastRequest
				}
			}
			switch kind {
			case Prepare:
				frame.Plan = prepare.Plan
			case Input, Output:
				stream := "stdout"
				if kind == Input {
					stream = "stdin"
				}
				frame.Data = &Data{Stream: stream, Bytes: []byte{action}}
			case Resize:
				frame.Size = &Size{Rows: 1, Columns: 1}
			case Exited:
				frame.Result = &Result{ExitCode: 23}
			case Failed:
				frame.Failure = &Failure{Code: "io_failed"}
			}
			if action&32 != 0 {
				frame.Sequence++
			}
			if action&64 != 0 {
				frame.Request++
			}
			if action&128 != 0 {
				frame.Binding.SessionID = "foreign-session"
			}
			var err error
			if toHost {
				err = c.Host(frame)
			} else {
				err = c.Bridge(frame)
			}
			if err == nil {
				if frame.Validate() != nil || c.Phase() == PhaseClosed && kind != Failed {
					t.Fatal("invalid random command admitted")
				}
				if c.Phase() == PhaseClosed { // an admitted Failed event is terminal
					if !c.PeerClosed() || c.Host(frame) == nil {
						t.Fatal("terminal failure resumed or lost outstanding resources")
					}
					break
				}
				continue
			}
			if !errors.Is(err, ErrProtocol) || c.Phase() != PhaseClosed || !c.PeerClosed() || c.Host(frame) == nil {
				t.Fatal("random protocol refusal did not close outstanding resources")
			}
			break
		}
	})
}

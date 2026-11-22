// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

// TestGAP1320MaskRunInItsOwnLane: a run is looked for only in the fields of
// the lane it is open in. A run of the answer lane is masked in delta.text,
// never in the padding; a run the walker reads from the padding (the walker
// lane) is masked there, never in delta.text; and a run placed in a field
// the reader reads into another lane keeps everything held (GAP-1320).
func TestGAP1320MaskRunInItsOwnLane(t *testing.T) {
	s := &passthroughStream{bedrock: &bedrockEventStreamText{}}
	frame := func(text, pad string) []byte {
		return []byte(gap1307ConverseFrame("contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": text}, "p": pad}))
	}
	other := responseLane{field: responseFieldOther}
	pad := func(evs [][]byte) string {
		var sb strings.Builder
		for _, ev := range evs {
			msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(ev), nil)
			if err == nil {
				sb.Write(msg.Payload)
			}
		}
		return sb.String()
	}
	// Both lanes end in a digit run: each is masked in its own field.
	q := [][]byte{frame("port 80", "abcdefgh0123")}
	runs := []openRun{{lane: 0, text: "80"}, {lane: 1, key: other, text: "0123"}}
	out, ok := s.maskHeld(q, 1, runs, map[int][2]int{})
	if !ok || gap1307ConverseText(string(out[0])) != "port **" || !strings.Contains(pad(out), `"p":"abcdefgh****"`) {
		t.Fatalf("two lanes: ok=%v text %q events %s", ok, gap1307ConverseText(string(out[0])), pad(out))
	}
	// Only the walker lane is open: the text is not touched.
	out, ok = s.maskHeld(q, 1, runs[1:], map[int][2]int{})
	if !ok || gap1307ConverseText(string(out[0])) != "port 80" || !strings.Contains(pad(out), `"p":"abcdefgh****"`) {
		t.Fatalf("walker lane: ok=%v text %q events %s", ok, gap1307ConverseText(string(out[0])), pad(out))
	}
	// An answer run that only the padding ends with: nothing goes out.
	if _, ok := s.maskHeld([][]byte{frame("port 7", "abcdefgh0123")}, 1, []openRun{{text: "23"}}, map[int][2]int{}); ok {
		t.Fatal("an answer run found only in the padding went out")
	}
	// A walker run that only delta.text ends with: nothing goes out.
	if _, ok := s.maskHeld([][]byte{frame("port 80", "abcdefgh")}, 1, []openRun{{key: other, text: "80"}}, map[int][2]int{}); ok {
		t.Fatal("a walker-lane run found only in delta.text went out")
	}
}

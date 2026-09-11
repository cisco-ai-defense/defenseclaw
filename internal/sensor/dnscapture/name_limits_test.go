package dnscapture

import "testing"

// buildName encodes labels into wire form without a terminating root label,
// so a caller can append either a root byte or a compression pointer.
func buildName(labels ...string) []byte {
	var wire []byte
	for _, label := range labels {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return wire
}

func repeatLabel(size int) string {
	raw := make([]byte, size)
	for index := range raw {
		raw[index] = 'a'
	}
	return string(raw)
}

// TestReadNameRefusesOversizeName pins the RFC 1035 s2.3.4 ceiling. Without
// it a name assembled from labels is bounded only by the frame, and the
// decoded string is cached per address and emitted as telemetry content.
func TestReadNameRefusesOversizeName(t *testing.T) {
	payload := buildName(
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(62),
	)
	payload = append(payload, 0)

	if _, _, ok := readName(payload, 0, 0); ok {
		t.Fatal("readName accepted a 256-byte wire name")
	}
}

// TestReadNameAcceptsNameAtLimit proves the check rejects only what is over
// the line: a legitimate long name still decodes.
func TestReadNameAcceptsNameAtLimit(t *testing.T) {
	labels := []string{
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(61),
	}
	payload := buildName(labels...)
	payload = append(payload, 0)

	name, _, ok := readName(payload, 0, 0)
	if !ok {
		t.Fatal("readName rejected a well-formed name")
	}
	want := labels[0] + "." + labels[1] + "." + labels[2] + "." + labels[3]
	if name != want {
		t.Fatalf("readName length = %d, want %d", len(name), len(want))
	}
	if got := len(payload); got != maxNameTextBytes+2 {
		t.Fatalf("wire name length = %d, want 255", got)
	}
}

func TestReadNameAcceptsNameAtLimitThroughPointer(t *testing.T) {
	labels := []string{
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(63),
		repeatLabel(61),
	}
	payload := buildName(labels...)
	payload = append(payload, 0, 0xC0, 0x00)

	name, next, ok := readName(payload, maxNameTextBytes+2, 0)
	if !ok {
		t.Fatal("readName rejected a 255-byte wire name reached through a pointer")
	}
	if got, want := len(name), maxNameTextBytes; got != want {
		t.Fatalf("decoded name length = %d, want %d", got, want)
	}
	if got, want := next, len(payload); got != want {
		t.Fatalf("next offset = %d, want %d", got, want)
	}
}

// TestReadNameRefusesReservedLabelType covers the 01 and 10 label types.
// They have never been assigned, so reading one as a literal length accepts a
// packet no resolver emits and mis-frames everything after it.
func TestReadNameRefusesReservedLabelType(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix byte
	}{
		{name: "type 01", prefix: 0x41},
		{name: "type 10", prefix: 0x81},
	} {
		t.Run(test.name, func(t *testing.T) {
			// The label bytes are really present, so the only reason to
			// refuse this is the reserved type -- not a short read.
			payload := append([]byte{test.prefix}, repeatLabel(int(test.prefix))...)
			payload = append(payload, 0)

			if _, _, ok := readName(payload, 0, 0); ok {
				t.Fatalf("readName accepted reserved label type %#x", test.prefix)
			}
			if _, ok := skipName(payload, 0); ok {
				t.Fatalf("skipName accepted reserved label type %#x", test.prefix)
			}
		})
	}
}

// TestSkipNameRefusesTruncatedPointer keeps skipName from returning an offset
// past the payload when a pointer's second byte is missing.
func TestSkipNameRefusesTruncatedPointer(t *testing.T) {
	payload := []byte{0x03, 'a', 'p', 'i', 0xC0}

	if next, ok := skipName(payload, 0); ok {
		t.Fatalf("skipName accepted a truncated pointer, returning offset %d for a %d-byte payload", next, len(payload))
	}
}

// TestOversizeNameViaPointerChain covers the assembly path the depth cap
// alone does not bound: each level contributes labels, so sixteen legal hops
// can still exceed the name limit.
func TestOversizeNameViaPointerChain(t *testing.T) {
	label := repeatLabel(63)

	// Target name at offset 0: three maximal labels, root-terminated.
	payload := buildName(label, label, label)
	payload = append(payload, 0)
	target := len(payload)

	// A second name that adds two more maximal labels then points at the
	// first. Decoded, that is five labels: over the limit.
	payload = append(payload, buildName(label, label)...)
	payload = append(payload, 0xC0, 0x00)

	if _, _, ok := readName(payload, target, 0); ok {
		t.Fatal("readName accepted an oversize name assembled through a compression pointer")
	}
}

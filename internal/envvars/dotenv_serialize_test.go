package envvars

import (
	"reflect"
	"testing"
)

func TestDotEnvLineEndingIsCRLFOnlyForAnEntirelyCRLFFile(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"empty", "", "\n"},
		{"new file without a newline", "A=1", "\n"},
		{"lf", "A=1\nB=2\n", "\n"},
		{"crlf", "A=1\r\nB=2\r\n", "\r\n"},
		{"crlf without a final newline", "A=1\r\nB=2", "\r\n"},
		{"mixed crlf first", "A=1\r\nB=2\n", "\n"},
		{"mixed lf first", "A=1\nB=2\r\n", "\n"},
		{"mostly crlf", "A=1\r\nB=2\r\nC=3\n", "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DotEnvLineEnding([]byte(tc.body)); got != tc.want {
				t.Fatalf("ending = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDotEnvLinesDropEndingsAndTheFinalEmptyLine(t *testing.T) {
	got := DotEnvLines([]byte("A=1\r\n\nB=2\nC=3"))
	want := []string{"A=1", "", "B=2", "C=3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %q, want %q", got, want)
	}
	if got := DotEnvLines(nil); len(got) != 0 {
		t.Fatalf("lines of nothing = %q", got)
	}
}

func TestSerializeDotEnvWritesOneEndingFromAMixedFile(t *testing.T) {
	mixed := []byte("A=1\r\nB=2\nC=3\r\n")
	got := string(SerializeDotEnv(mixed, DotEnvLines(mixed)))
	if want := "A=1\nB=2\nC=3\n"; got != want {
		t.Fatalf("mixed input: %q, want %q", got, want)
	}
	crlf := []byte("A=1\r\nB=2\r\n")
	got = string(SerializeDotEnv(crlf, append(DotEnvLines(crlf), "C=3")))
	if want := "A=1\r\nB=2\r\nC=3\r\n"; got != want {
		t.Fatalf("crlf input: %q, want %q", got, want)
	}
}

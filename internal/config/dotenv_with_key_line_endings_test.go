package config

import "testing"

func TestDotEnvWithKeyWritesOneEndingFromAMixedFile(t *testing.T) {
	for _, tc := range []struct{ name, existing, want string }{
		{"append to a mixed file", "A=1\r\nB=2\n", "A=1\nB=2\nKEY=v\n"},
		{"fill an empty assignment in a mixed file", "A=1\r\nKEY=\nB=2\r\n", "A=1\nKEY=v\nB=2\n"},
		{"append to an entirely CRLF file", "A=1\r\nB=2\r\n", "A=1\r\nB=2\r\nKEY=v\r\n"},
		{"append to an LF file without a final newline", "A=1\nB=2", "A=1\nB=2\nKEY=v\n"},
		{"new file", "", "KEY=v\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := DotEnvWithKey([]byte(tc.existing), "KEY", "v")
			if !changed || string(got) != tc.want {
				t.Fatalf("got %q changed=%v, want %q", got, changed, tc.want)
			}
		})
	}
	same := []byte("A=1\r\nKEY=set\nB=2\r\n")
	if got, changed := DotEnvWithKey(same, "KEY", "v"); changed || string(got) != string(same) {
		t.Fatalf("an existing value must stay byte for byte: %q changed=%v", got, changed)
	}
}

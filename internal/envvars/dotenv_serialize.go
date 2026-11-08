package envvars

import "bytes"

// DotEnvLineEnding is the one line ending DefenseClaw writes into a .env that
// currently holds existing: CRLF only when the file is entirely CRLF, otherwise
// LF (also for an empty or new file). The readers accept both.
func DotEnvLineEnding(existing []byte) string {
	lf := bytes.Count(existing, []byte("\n"))
	if lf > 0 && lf == bytes.Count(existing, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// DotEnvLines splits a .env into its lines without their line endings, so a
// writer works on content and leaves the ending to SerializeDotEnv.
func DotEnvLines(existing []byte) []string {
	if len(existing) == 0 {
		return nil
	}
	parts := bytes.Split(existing, []byte("\n"))
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		lines = append(lines, string(bytes.TrimSuffix(part, []byte("\r"))))
	}
	return lines
}

// SerializeDotEnv is the one serializer every DefenseClaw .env writer ends
// with. It picks the file ending once from existing, the bytes being replaced,
// and ends every line with it, so a file an older writer left half CRLF and
// half LF leaves the first write with one ending.
func SerializeDotEnv(existing []byte, lines []string) []byte {
	eol := DotEnvLineEnding(existing)
	var out bytes.Buffer
	for _, line := range lines {
		out.WriteString(line)
		out.WriteString(eol)
	}
	return out.Bytes()
}

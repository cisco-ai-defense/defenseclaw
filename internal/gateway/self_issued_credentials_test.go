package gateway

import "testing"

// DefenseClaw writes its own gateway token into ~/.claude/settings.json four
// times; reading that file raised HIGH SEC-BEARER findings about the product's
// own configuration.
func TestSelfIssuedCredentialIsNotAFinding(t *testing.T) {
	resetSelfIssuedCredentialsForTest()
	token := "fe58289546a78110469da64533f35d1064603756a41263afe89ca82101095b1e"

	// The shape the OTLP header block actually produces, plus the bare value
	// as it appears elsewhere in managed config.
	header := "authorization=Bearer " + token
	for _, form := range []string{header, token} {
		if !acceptedCredentialMatch("SEC-BEARER", form) && form == header {
			t.Fatal("precondition: an unregistered high-entropy token must be reported")
		}
	}

	RegisterSelfIssuedCredential(token)
	for _, form := range []string{header, token} {
		if acceptedCredentialMatch("SEC-BEARER", form) {
			t.Errorf("registered self-issued token must not be a finding, form=%q", form)
		}
	}
}

func TestSelfIssuedRegistrationIsExactNotFuzzy(t *testing.T) {
	resetSelfIssuedCredentialsForTest()
	RegisterSelfIssuedCredential("fe58289546a78110469da64533f35d1064603756a41263afe89ca82101095b1e")

	// A different operator credential of the same shape must still alert.
	other := "authorization=Bearer aa11229546a78110469da64533f35d1064603756a41263afe89ca82101095b1e"
	if !acceptedCredentialMatch("SEC-BEARER", other) {
		t.Error("allowlisting our own token must not suppress an unrelated credential")
	}
}

func TestSelfIssuedRegistrationRejectsShortValues(t *testing.T) {
	resetSelfIssuedCredentialsForTest()
	RegisterSelfIssuedCredential("short")
	if isSelfIssuedCredential("short") {
		t.Error("a short value must not be allowlisted: it would suppress unrelated matches")
	}
	RegisterSelfIssuedCredential("")
	if isSelfIssuedCredential("") {
		t.Error("empty value must never be allowlisted")
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidIBANRequiresRegisteredCountryLength(t *testing.T) {
	if !validIBAN("GB82 WEST 1234 5698 7654 32") {
		t.Fatal("registered checksum-valid IBAN was rejected")
	}
	if !validIBAN("BI4210000100010000332045181") {
		t.Fatal("current 27-character Burundi format was rejected")
	}

	unknownCountry := checksumValidIBANForTest("ZZ", strings.Repeat("1", 18))
	if validIBAN(unknownCountry) {
		t.Fatalf("unregistered country was accepted: %q", unknownCountry)
	}

	wrongGBLength := checksumValidIBANForTest("GB", strings.Repeat("1", 17))
	if validIBAN(wrongGBLength) {
		t.Fatalf("registered country with the wrong length was accepted: %q", wrongGBLength)
	}
}

func checksumValidIBANForTest(country, bban string) string {
	remainder := 0
	for _, character := range bban + country + "00" {
		if character >= '0' && character <= '9' {
			remainder = (remainder*10 + int(character-'0')) % 97
			continue
		}
		remainder = (remainder*100 + int(character-'A') + 10) % 97
	}
	return fmt.Sprintf("%s%02d%s", country, 98-remainder, bban)
}

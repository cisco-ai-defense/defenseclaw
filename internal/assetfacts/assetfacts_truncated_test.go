// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
	"testing"
)

// GAP-1303: claims past the cap are dropped, and the facts say so.
func TestMoreSkillClaimsThanTheCapMarkTheFactsTruncated(t *testing.T) {
	var claims []Skill
	for i := range maxSkills + 1 {
		claims = append(claims, Skill{Folder: fmt.Sprintf("f%02d", i), Declared: fmt.Sprintf("d%02d", i)})
	}
	facts, ok := Decode(Encode(Facts{Skills: claims}))
	if !ok || len(facts.Skills) != maxSkills || !facts.SkillsTruncated {
		t.Fatalf("facts = %d claims, truncated %v (ok %v); want %d and truncated", len(facts.Skills), facts.SkillsTruncated, ok, maxSkills)
	}
	if got := facts.DeclaredFor(fmt.Sprintf("f%02d", maxSkills)); len(got) != 0 {
		t.Fatalf("the dropped claim survived: %v", got)
	}
	exact, _ := Decode(Encode(Facts{Skills: claims[:maxSkills]}))
	if exact.SkillsTruncated {
		t.Fatal("exactly the cap is not truncated")
	}
	// An invalid claim is not a dropped one.
	invalid, _ := Decode(Encode(Facts{Skills: append(claims[:maxSkills:maxSkills], Skill{Folder: "x", Declared: ""})}))
	if invalid.SkillsTruncated {
		t.Fatal("an empty declared name marked the facts truncated")
	}
}

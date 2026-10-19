// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func fixedClaudeMetadata() localClaudeReceipt {
	no := false
	return localClaudeReceipt{Schema: "fixed-reviewed-anthropic-claude-version-v1", Verified: true,
		ExecutionPerformed: &no, ProductionQualification: &no,
		Image: `C:\fixed\claude.exe`, SHA256: claudeImageSHA, Size: claudeImageSize,
		ProductVersion: claudeProductVersion, SignatureStatus: "Valid",
		SignerOrganization: "Anthropic, PBC", SignerThumbprint: claudeSignerThumbprint}
}

func TestLocalClaudeMetadataCannotSelectAnotherImageOrSignature(t *testing.T) {
	if err := validateLocalClaudeMetadata(fixedClaudeMetadata()); err != nil {
		t.Fatal(err)
	}
	yes := true
	for _, change := range []func(*localClaudeReceipt){
		func(v *localClaudeReceipt) { v.SHA256 = strings.Repeat("a", 64) },
		func(v *localClaudeReceipt) { v.Size-- },
		func(v *localClaudeReceipt) { v.ProductVersion = "other" },
		func(v *localClaudeReceipt) { v.SignatureStatus = "UnknownError" },
		func(v *localClaudeReceipt) { v.SignerOrganization = "other" },
		func(v *localClaudeReceipt) { v.SignerThumbprint = strings.Repeat("0", 40) },
		func(v *localClaudeReceipt) { v.ExecutionPerformed = nil },
		func(v *localClaudeReceipt) { v.ProductionQualification = &yes },
		func(v *localClaudeReceipt) { v.Verified = false },
	} {
		value := fixedClaudeMetadata()
		change(&value)
		if err := validateLocalClaudeMetadata(value); err == nil {
			t.Fatal("changed fixed local-image authority accepted")
		}
	}
}

func TestLocalClaudeReceiptRejectsAmbiguousJSONBeforeAnyImageRead(t *testing.T) {
	good, err := json.Marshal(fixedClaudeMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeLocalClaudeReceipt(good); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		append(append([]byte{}, good...), []byte(`{}`)...),
		append(append([]byte{}, good[:len(good)-1]...), []byte(`,"verified":true}`)...),
		append(append([]byte{}, good[:len(good)-1]...), []byte(`,"unknown":"x"}`)...),
		append(append([]byte{}, good[:len(good)-1]...), []byte(`,"Verified":true}`)...),
		[]byte(`{"verified": {"nested": true}}`), []byte(`[]`), []byte{0xff},
	} {
		if _, err := decodeLocalClaudeReceipt(raw); err == nil {
			t.Fatal("ambiguous local-image JSON accepted")
		}
	}
}

func TestLocalClaudeReceiptRefusesActualWrongBytesBeforeExecution(t *testing.T) {
	root := t.TempDir()
	value := fixedClaudeMetadata()
	value.Image = filepath.Join(root, "synthetic-never-executed.exe")
	if err := os.WriteFile(value.Image, []byte("fixed public fixture; never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "local-image.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if image, err := checkLocalClaudeReceipt(path, hex.EncodeToString(digest[:])); err == nil {
		image.held.Close()
		t.Fatal("synthetic content selected as the reviewed signed Claude image")
	}
	if image, err := checkLocalClaudeReceipt(path, strings.Repeat("0", 64)); err == nil {
		image.held.Close()
		t.Fatal("unpinned local-image receipt accepted")
	}
}

func TestFixedCopyUsesHeldRootAndRetainsOrdinaryAncestors(t *testing.T) {
	parent := t.TempDir()
	bin := filepath.Join(parent, "private-bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(parent, "fixed-public-input")
	data := []byte("fixed public synthetic content; no executable")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	held, err := pinImageParents(filepath.Join(bin, claudeSiblingName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.Rename(bin, filepath.Join(parent, "moved")); err == nil {
		t.Fatal("image ancestor was replaceable while pinned")
	}
	anchor, err := os.OpenRoot(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	digest := sha256.Sum256(data)
	sha := hex.EncodeToString(digest[:])
	if err := copyFixedImage(anchor, "other.exe", file, int64(len(data)), sha); err == nil {
		t.Fatal("arbitrary staging target accepted")
	}
	if err := copyFixedImage(anchor, claudeSiblingName, file, int64(len(data)), sha); err != nil {
		t.Fatal(err)
	}
	retained, observed, err := pinFile(filepath.Join(bin, claudeSiblingName), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if observed != sha {
		t.Fatal("fixed staged copy differs")
	}
	if err := os.WriteFile(filepath.Join(bin, claudeSiblingName), []byte("must refuse"), 0600); err == nil {
		t.Fatal("retained fixed image permits writes")
	}
	if err := copyFixedImage(anchor, claudeSiblingName, file, int64(len(data)), sha); err == nil {
		t.Fatal("existing staged image reused")
	}
}

func TestFixedClaudeImageConstantsMatchObservationBoundary(t *testing.T) {
	source, err := os.ReadFile("run_live.py")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"CLAUDE_IMAGE_SHA256": claudeImageSHA, "CLAUDE_PRODUCT_VERSION": claudeProductVersion} {
		matches := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(matches) != 1 || string(matches[0][1]) != want {
			t.Fatalf("fixed local image %s drifted", name)
		}
	}
	if !regexp.MustCompile(`(?m)^CLAUDE_IMAGE_SIZE = 254858400\r?$`).Match(source) || claudeImageSize != 254858400 {
		t.Fatal("fixed local-image size authority drifted")
	}
}

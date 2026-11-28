package config

import (
	"strings"
	"testing"
)

// RV5-8 (GAP-0785): the schemas (config v8 and the Helm values) take
// secret_action and placeholder_form as exact lower-case values. Go read them
// case-folded and trimmed, so Replace and " hold_back" passed Validate here
// while the schemas refused them. One rule now: exact.
func TestRV58UploadScanValuesAreExactLikeTheSchemas(t *testing.T) {
	for _, bad := range []SubstrateUploadScanConfig{
		{SecretAction: "Replace"}, {SecretAction: "HOLD_BACK"}, {SecretAction: " replace"},
		{PlaceholderForm: "Token"}, {PlaceholderForm: "ENV"}, {PlaceholderForm: "env "},
	} {
		s := SubstrateConfig{Launcher: SubstrateLauncherConfig{UploadScan: bad}}
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "launcher.upload_scan.") {
			t.Errorf("%+v: err = %v, want a refusal", bad, err)
		}
	}
	for _, ok := range []SubstrateUploadScanConfig{
		{SecretAction: "replace", PlaceholderForm: "token"}, {SecretAction: "hold_back", PlaceholderForm: "env"}, {},
	} {
		s := SubstrateConfig{Launcher: SubstrateLauncherConfig{UploadScan: ok}}
		if err := s.Validate(); err != nil && strings.Contains(err.Error(), "launcher.upload_scan.") {
			t.Errorf("%+v: %v", ok, err)
		}
	}
}

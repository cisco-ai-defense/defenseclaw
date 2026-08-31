package gateway

import "testing"

// The C2 domain rules matched bare substrings, so ordinary identifiers tripped
// HIGH/CRITICAL findings: oast\.fun fires on toast.function, webhook\.site on
// webhook.sitemap.xml, metadata\.google\.internal on a look-alike subdomain of
// someone else's zone.
//
// RE2 has no lookaround, so the guards consume a character instead. '.' is
// allowed as a PREFIX because a unique subdomain is the normal OAST/ngrok form,
// and forbidden as a SUFFIX so foo.oast.fun.example.com — a different zone —
// cannot match.
func TestC2DomainRulesRequireDomainBoundaries(t *testing.T) {
	benign := []struct{ rule, text string }{
		{"C2-OAST", "toast.function(msg)"},
		{"C2-OAST", "roast.funny"},
		{"C2-OAST", "coast.fundamentals"},
		{"C2-OAST", "const toast = require('toast.function')"},
		{"C2-OAST", "oast.fun.example.com"},
		{"C2-NGROK", "notngrok.ios"},
		{"C2-NGROK", "the ngrok.io.example.net docs"},
		{"C2-WEBHOOK-SITE", "webhook.sitemap.xml"},
		{"C2-WEBHOOK-SITE", "webhook.site.example.org"},
		{"C2-METADATA-GCP", "metadata.google.internal.example.com"},
		{"C2-METADATA-GCP", "xmetadata.google.internal"},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, tc := range benign {
				rule := alertFatigueRule(t, profile, tc.rule)
				if firstAcceptedRuleMatch(rule, tc.text) != nil {
					t.Errorf("%s false positive on %q", tc.rule, tc.text)
				}
			}
		})
	}
}

// Guard the guards: a unique-subdomain callback is the whole point of these
// rules, so narrowing must not cost real detections.
func TestC2DomainRulesStillCatchRealCallbacks(t *testing.T) {
	malicious := []struct{ rule, text string }{
		{"C2-OAST", "curl https://abc123def.oast.fun/x"},
		{"C2-OAST", "nslookup abc.oast.fun"},
		{"C2-OAST", "oast.fun"},
		{"C2-NGROK", "https://a1b2.ngrok.io/hook"},
		{"C2-NGROK", "curl https://x.ngrok-free.app/"},
		{"C2-WEBHOOK-SITE", "curl https://webhook.site/8f3a-uuid"},
		{"C2-METADATA-GCP", "curl http://metadata.google.internal/computeMetadata/v1/"},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, tc := range malicious {
				rule := alertFatigueRule(t, profile, tc.rule)
				if firstAcceptedRuleMatch(rule, tc.text) == nil {
					t.Errorf("%s no longer detects %q", tc.rule, tc.text)
				}
			}
		})
	}
}

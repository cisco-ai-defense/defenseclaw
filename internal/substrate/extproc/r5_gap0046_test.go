
package extproc

import (
	"context"
	"testing"
)

// Laravel turns a JSON body into the request bag (Request::createFromBase:
// isJson() -> $request->request = $request->json()), and Symfony's
// getMethod() reads _method from that bag for a POST (Laravel's Kernel
// enables the parameter override on every request). Express method-override
// documents a getter on req.body, which express.json() fills. So a JSON
// POST {"_method":"DELETE"} runs DELETE on those servers.
func TestR5JSONBodyMethodOverride(t *testing.T) {
	ctx := context.Background()
	for _, ct := range []string{"application/json", "application/vnd.api+json", "application/json; charset=utf-8"} {
		for _, mode := range []string{"", "open"} {
			h := newHarness(t, func(cfg *Config, _ *Options) {
				cfg.Profiles[0].URLRules = []URLRuleCfg{{Name: "no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, Action: "deny"}}
				if mode != "" {
					cfg.FailureMode = mode
				}
			})
			h.eng.body.arrived()
			body := []byte(`{"_method":"DELETE","title":"x"}`)
			r := req("eng-web", "POST", "api.github.com", "/repos/acme/web")
			r.Headers = append(r.Headers, Header{"content-type", ct})
			r.ContentType = ct
			r.EndOfStream = false
			r.ContentLength = int64(len(body))
			v := h.eng.DecideHeaders(ctx, r)
			if v.Allow && v.WantBody {
				v = h.eng.DecideBody(ctx, r, v, body)
			}
			if v.Allow && !v.Alert {
				t.Errorf("%s (mode %q): a JSON _method=DELETE POST is allowed with no alert under a DELETE deny", ct, mode)
			}
		}
	}
}

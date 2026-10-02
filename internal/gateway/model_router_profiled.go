package gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hwprofile"
	"github.com/defenseclaw/defenseclaw/internal/usecases"
)

// ProfiledModelRouter wraps an existing ModelRouter with hardware-aware
// policy overrides. It does not replace the inner router's classification —
// it applies profiler policy after the classification decision.
type ProfiledModelRouter struct {
	inner    ModelRouter
	profile  *hwprofile.SystemProfile
	useCases []usecases.InferredUseCase
	backends map[string]*ModelRouterBackend
	policy   *ProfileRoutingPolicy
}

// ProfileRoutingPolicy controls hardware-aware routing overrides.
type ProfileRoutingPolicy struct {
	PreferLocal         bool    `mapstructure:"prefer_local"           yaml:"prefer_local"`
	SecurityAlwaysLocal bool    `mapstructure:"security_always_local"  yaml:"security_always_local"`
	PIIAlwaysLocal      bool    `mapstructure:"pii_always_local"       yaml:"pii_always_local"`
	MaxCloudCostPerMonth float64 `mapstructure:"max_cloud_cost_per_month" yaml:"max_cloud_cost_per_month"`
}

// NewProfiledModelRouter wraps an existing router with profile-aware policy.
func NewProfiledModelRouter(
	inner ModelRouter,
	profile *hwprofile.SystemProfile,
	ucs []usecases.InferredUseCase,
	backends map[string]*ModelRouterBackend,
	policy *ProfileRoutingPolicy,
) *ProfiledModelRouter {
	return &ProfiledModelRouter{
		inner:    inner,
		profile:  profile,
		useCases: ucs,
		backends: backends,
		policy:   policy,
	}
}

func (r *ProfiledModelRouter) Route(ctx context.Context, input *ModelRouterInput) *ModelRouterDecision {
	decision := r.inner.Route(ctx, input)

	// Override: force local when prefer_local is set and no routing decision
	if decision == nil && r.policy != nil && r.policy.PreferLocal {
		local := r.bestLocalBackend("")
		if local != nil {
			fmt.Fprintf(os.Stderr, "[profiled-router] prefer-local: using %s\n", local.Model)
			return r.localDecision(local, "profile: prefer-local")
		}
	}

	return decision
}

// RouteDetailed implements detailedModelRouter for the ProfiledModelRouter.
func (r *ProfiledModelRouter) RouteDetailed(ctx context.Context, input *ModelRouterInput) SemanticRouteOutcome {
	if detailed, ok := r.inner.(detailedModelRouter); ok {
		outcome := detailed.RouteDetailed(ctx, input)
		// Apply profile policy on nil decisions
		if outcome.Decision == nil && r.policy != nil && r.policy.PreferLocal {
			local := r.bestLocalBackend("")
			if local != nil {
				outcome.Decision = r.localDecision(local, "profile: prefer-local fallback")
				outcome.OverrideApplied = true
				outcome.Result = SemanticRouteApplied
			}
		}
		return outcome
	}
	// Fallback: wrap Route result
	decision := r.Route(ctx, input)
	if decision != nil {
		return SemanticRouteOutcome{
			Decision:        decision,
			Result:          SemanticRouteApplied,
			OverrideApplied: true,
		}
	}
	return SemanticRouteOutcome{Result: SemanticRouteFallback}
}

// Models returns the model list for the /models endpoint.
func (r *ProfiledModelRouter) Models() []string {
	if lister, ok := r.inner.(interface{ Models() []string }); ok {
		return lister.Models()
	}
	var names []string
	for name := range r.backends {
		names = append(names, name)
	}
	return names
}

// Healthy delegates to the inner router.
func (r *ProfiledModelRouter) Healthy(ctx context.Context) bool {
	type healthChecker interface {
		Healthy(context.Context) bool
	}
	if h, ok := r.inner.(healthChecker); ok {
		return h.Healthy(ctx)
	}
	return true
}

func (r *ProfiledModelRouter) bestLocalBackend(useCase string) *ModelRouterBackend {
	for _, b := range r.backends {
		provider := strings.ToLower(b.Provider)
		if provider == "ollama" || provider == "vllm" || provider == "lm_studio" {
			if useCase == "" || containsStr(b.Capabilities(), useCase) {
				return b
			}
		}
	}
	return nil
}

func (b *ModelRouterBackend) Capabilities() []string {
	// Placeholder — capabilities are not stored on ModelRouterBackend
	// In the future, this should read from the routing config
	return nil
}

func (r *ProfiledModelRouter) localDecision(b *ModelRouterBackend, reason string) *ModelRouterDecision {
	return &ModelRouterDecision{
		Provider:         b.Provider,
		Model:            b.Model,
		TargetURL:        b.BaseURL,
		HostHeader:       b.HostHeader,
		TargetURLOverride: true,
		APIKeyOverride:   b.Auth == "none",
		Reason:           reason,
		ExtraHeaders:     b.ExtraHeaders,
		ExtraBody:        b.ExtraBody,
		PathOverride:     b.PathOverride,
	}
}

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

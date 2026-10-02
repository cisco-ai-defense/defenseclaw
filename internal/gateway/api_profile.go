package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/hwprofile"
	"github.com/defenseclaw/defenseclaw/internal/modelcatalog"
	"github.com/defenseclaw/defenseclaw/internal/usecases"
)

// ProfileResponse is the full system profile returned by /api/v1/profile.
type ProfileResponse struct {
	Hardware        *hwprofile.SystemProfile          `json:"hardware"`
	UseCases        []usecases.InferredUseCase         `json:"use_cases"`
	Recommendations []modelcatalog.ModelRecommendation `json:"recommendations"`
}

// handleGetProfile returns the full system profile with hardware, use cases, and recommendations.
// GET /api/v1/profile
func (s *Sidecar) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	profile := s.getHWProfile()
	ucs := s.getUseCases()

	var installedModels []string
	if s.aiDiscovery != nil {
		report := s.aiDiscovery.Snapshot()
		for _, sig := range report.Signals {
			if sig.Model != nil && sig.Model.ID != "" {
				installedModels = append(installedModels, sig.Model.ID)
			}
		}
	}

	recs := modelcatalog.Recommend(profile, ucs, installedModels)

	resp := ProfileResponse{
		Hardware:        profile,
		UseCases:        ucs,
		Recommendations: recs,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleGetProfileHardware returns hardware profile only.
// GET /api/v1/profile/hardware
func (s *Sidecar) handleGetProfileHardware(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.getHWProfile())
}

// handleGetProfileUseCases returns inferred use cases only.
// GET /api/v1/profile/use-cases
func (s *Sidecar) handleGetProfileUseCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.getUseCases())
}

// getHWProfile returns the cached hardware profile.
func (s *Sidecar) getHWProfile() *hwprofile.SystemProfile {
	if s.hwProfile != nil {
		return s.hwProfile
	}
	return hwprofile.DetectAll()
}

// getUseCases returns the cached use case inference.
func (s *Sidecar) getUseCases() []usecases.InferredUseCase {
	if s.inferredUseCases != nil {
		return s.inferredUseCases
	}
	if s.aiDiscovery == nil {
		return nil
	}
	report := s.aiDiscovery.Snapshot()
	return usecases.InferUseCases(report.Signals)
}

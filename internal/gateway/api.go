package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// APIServer exposes a local REST API for CLI and plugin communication
// with the running sidecar.
type APIServer struct {
	health *SidecarHealth
	client *Client
	store  *audit.Store
	logger *audit.Logger
	addr   string
}

// NewAPIServer creates the REST API server bound to the given address.
func NewAPIServer(addr string, health *SidecarHealth, client *Client, store *audit.Store, logger *audit.Logger) *APIServer {
	return &APIServer{
		addr:   addr,
		health: health,
		client: client,
		store:  store,
		logger: logger,
	}
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (a *APIServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/status", a.handleStatus)
	mux.HandleFunc("/skill/disable", a.handleSkillDisable)
	mux.HandleFunc("/skill/enable", a.handleSkillEnable)
	mux.HandleFunc("/config/patch", a.handleConfigPatch)
	mux.HandleFunc("/skills", a.handleSkills)
	mux.HandleFunc("/tools/catalog", a.handleToolsCatalog)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "[sidecar-api] listening on %s\n", a.addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	a.health.SetAPI(StateRunning, "", map[string]interface{}{"addr": a.addr})

	select {
	case err := <-errCh:
		a.health.SetAPI(StateError, err.Error(), nil)
		return fmt.Errorf("api: listen %s: %w", a.addr, err)
	case <-ctx.Done():
		a.health.SetAPI(StateStopped, "", nil)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (a *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap := a.health.Snapshot()
	a.writeJSON(w, http.StatusOK, snap)
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snap := a.health.Snapshot()

	status := map[string]interface{}{
		"health": snap,
	}

	if a.client != nil && a.client.Hello() != nil {
		hello := a.client.Hello()
		status["gateway_hello"] = hello
	}

	a.writeJSON(w, http.StatusOK, status)
}

type skillActionRequest struct {
	SkillKey string `json:"skillKey"`
}

func (a *APIServer) handleSkillDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.DisableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	_ = a.logger.LogAction("api-skill-disable", req.SkillKey, "disabled via REST API")
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "skillKey": req.SkillKey})
}

func (a *APIServer) handleSkillEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req skillActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.SkillKey == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "skillKey is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.EnableSkill(ctx, req.SkillKey); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	_ = a.logger.LogAction("api-skill-enable", req.SkillKey, "enabled via REST API")
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "skillKey": req.SkillKey})
}

type configPatchRequest struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

func (a *APIServer) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req configPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Path == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.client.PatchConfig(ctx, req.Path, req.Value); err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	_ = a.logger.LogAction("api-config-patch", req.Path, fmt.Sprintf("patched via REST API value=%v", req.Value))
	a.writeJSON(w, http.StatusOK, map[string]string{"status": "patched", "path": req.Path})
}

func (a *APIServer) handleSkills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetSkillsStatus(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *APIServer) handleToolsCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.client == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "gateway not connected"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := a.client.GetToolsCatalog(ctx)
	if err != nil {
		a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *APIServer) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

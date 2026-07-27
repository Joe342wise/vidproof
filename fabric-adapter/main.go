package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vidproof/fabric-adapter/internal/fabric"
)

const maxBodyBytes = 1 << 20 // 1 MiB

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := fabric.DefaultConfig()

	var gw *fabric.Gateway
	gw, err := fabric.NewGateway(cfg)
	if err != nil {
		// Fabric not available — serve with fabricConnected: false.
		// This allows the adapter to be started and health-checked before
		// the Fabric network is brought up.
		log.Printf("fabric adapter: WARNING: Fabric not connected: %v", err)
		log.Printf("fabric adapter: serving without Fabric — all /camera, /evidence, /custody, /verification endpoints will return 503")
	} else {
		log.Println("fabric adapter: connected to Fabric Gateway")
		defer gw.Close()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth(gw != nil))
	mux.HandleFunc("POST /camera/register", handleRegisterCamera(gw))
	mux.HandleFunc("POST /evidence/register", handleRegisterEvidence(gw))
	mux.HandleFunc("POST /custody/log", handleLogAccess(gw))
	mux.HandleFunc("POST /verification/log", handleLogVerification(gw))
	mux.HandleFunc("GET /evidence/{id}/history", handleGetHistory(gw))

	addr := envOr("VIDPROOF_ADAPTER_ADDR", ":8081")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("fabric adapter: listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("fabric adapter: ListenAndServe: %v", err)
		}
	}()

	<-quit
	log.Println("fabric adapter: shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleHealth(fabricConnected bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":               true,
			"service":          "vidproof-fabric-adapter",
			"fabricConnected":  fabricConnected,
		})
	}
}

type registerCameraRequest struct {
	CameraID   string `json:"cameraId"`
	CameraJSON string `json:"cameraJson"`
}

func handleRegisterCamera(gw *fabric.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw == nil {
			writeFabricUnavailable(w)
			return
		}
		var req registerCameraRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.CameraID == "" || req.CameraJSON == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cameraId and cameraJson are required")
			return
		}
		txID, err := gw.RegisterCamera(r.Context(), req.CameraID, req.CameraJSON)
		if err != nil {
			log.Printf("fabric adapter: RegisterCamera: %v", err)
			writeError(w, http.StatusBadGateway, "FABRIC_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "txId": txID})
	}
}

type registerEvidenceRequest struct {
	EvidenceID   string `json:"evidenceId"`
	EvidenceJSON string `json:"evidenceJson"`
}

func handleRegisterEvidence(gw *fabric.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw == nil {
			writeFabricUnavailable(w)
			return
		}
		var req registerEvidenceRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.EvidenceID == "" || req.EvidenceJSON == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "evidenceId and evidenceJson are required")
			return
		}
		txID, err := gw.RegisterEvidence(r.Context(), req.EvidenceID, req.EvidenceJSON)
		if err != nil {
			log.Printf("fabric adapter: RegisterEvidence: %v", err)
			writeError(w, http.StatusBadGateway, "FABRIC_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "txId": txID})
	}
}

type logAccessRequest struct {
	CustodyJSON string `json:"custodyJson"`
}

func handleLogAccess(gw *fabric.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw == nil {
			writeFabricUnavailable(w)
			return
		}
		var req logAccessRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.CustodyJSON == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "custodyJson is required")
			return
		}
		txID, err := gw.LogAccess(r.Context(), req.CustodyJSON)
		if err != nil {
			log.Printf("fabric adapter: LogAccess: %v", err)
			writeError(w, http.StatusBadGateway, "FABRIC_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "txId": txID})
	}
}

type logVerificationRequest struct {
	VerificationID   string `json:"verificationId"`
	VerificationJSON string `json:"verificationJson"`
}

func handleLogVerification(gw *fabric.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw == nil {
			writeFabricUnavailable(w)
			return
		}
		var req logVerificationRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.VerificationID == "" || req.VerificationJSON == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "verificationId and verificationJson are required")
			return
		}
		txID, err := gw.LogVerification(r.Context(), req.VerificationID, req.VerificationJSON)
		if err != nil {
			log.Printf("fabric adapter: LogVerification: %v", err)
			writeError(w, http.StatusBadGateway, "FABRIC_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "txId": txID})
	}
}

func handleGetHistory(gw *fabric.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if gw == nil {
			writeFabricUnavailable(w)
			return
		}
		evidenceID := r.PathValue("id")
		if evidenceID == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "evidence id is required")
			return
		}
		history, err := gw.GetEvidenceHistory(r.Context(), evidenceID)
		if err != nil {
			log.Printf("fabric adapter: GetEvidenceHistory: %v", err)
			writeError(w, http.StatusBadGateway, "FABRIC_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "history": history})
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("fabric adapter: encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": map[string]string{"code": code, "message": message},
	})
}

func writeFabricUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "FABRIC_UNAVAILABLE",
		"Fabric Gateway is not connected — bring up the test network and restart the adapter")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

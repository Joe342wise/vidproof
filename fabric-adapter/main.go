package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type healthResponse struct {
	OK      bool   `json:"ok"`
	Service string `json:"service"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{OK: true, Service: "vidproof-fabric-adapter"})
	})
	mux.HandleFunc("POST /camera/register", notImplemented)
	mux.HandleFunc("POST /evidence/register", notImplemented)
	mux.HandleFunc("POST /custody/log", notImplemented)
	mux.HandleFunc("POST /verification/log", notImplemented)
	mux.HandleFunc("GET /evidence/{id}/history", notImplemented)

	log.Println("fabric adapter listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", mux))
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"ok":    false,
		"error": "Fabric Gateway integration is not implemented yet",
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	evarToken    string
	gatewayURL   string
	sessionToken string
	sessionExp   time.Time
	sessionMutex sync.RWMutex
)

func main() {
	evarToken = os.Getenv("CICADA_EVAR")
	if evarToken == "" {
		log.Fatal("[FATAL] CICADA_EVAR environment variable is required")
	}

	gatewayURL = os.Getenv("CICADA_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "7777"
	}

	// ─── 1. Initial Token Authentication ──────────────────────────────────────
	// Exchange long-lived EVAR for 15-min Session Token before listening.
	if err := refreshSessionToken(); err != nil {
		log.Fatalf("[FATAL] Failed to authenticate EVAR across Gateway: %v", err)
	}

	// ─── 2. Background Token Rotation ──────────────────────────────────────────
	// Automatically fetch a new session token 1 minute before the current expires.
	go func() {
		for {
			sessionMutex.RLock()
			exp := sessionExp
			sessionMutex.RUnlock()

			sleepDuration := time.Until(exp) - time.Minute
			if sleepDuration < 0 {
				sleepDuration = 5 * time.Second
			}
			time.Sleep(sleepDuration)

			if err := refreshSessionToken(); err != nil {
				log.Printf("[ERROR] Session refresh failed (retrying in 5s): %v", err)
			}
		}
	}()

	// ─── 3. Local Intercept API ───────────────────────────────────────────────
	http.HandleFunc("/", handleProxy)

	log.Printf("[SIDECAR] Cicada MCP Sidecar running locally on :%s", port)
	log.Printf("[SIDECAR] Upstream Gateway  : %s", gatewayURL)
	log.Printf("[SIDECAR] SDK Integration   : Point your Agent's Base URL -> http://localhost:%s", port)
	log.Printf("[SIDECAR] SDK Integration   : Attach Header -> X-Cicada-Target-URL: <real_destination>")
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("[FATAL] Server error: %v", err)
	}
}

func refreshSessionToken() error {
	req, err := http.NewRequest("POST", gatewayURL+"/v1/agent/session", nil)
	if err != nil {
		return err
	}
	// Initial presentation of the permanent Identity Key (EVAR)
	req.Header.Set("Authorization", "Bearer "+evarToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway rejected EVAR (%d): %s", resp.StatusCode, string(body))
	}

	var data struct {
		SessionToken string `json:"session_token"`
		ExpiresIn    string `json:"expires_in"` // Seconds natively
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	sessionMutex.Lock()
	sessionToken = data.SessionToken
	// JIT Session token expires in exactly 15 mins (900s) on Gateway
	sessionExp = time.Now().Add(14 * time.Minute)
	sessionMutex.Unlock()

	log.Printf("[SIDECAR] Session Token minted/rotated successfully (Valid 15m)")
	return nil
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// The agent MUST declare where it's actually trying to go securely via header.
	targetPath := r.Header.Get("X-Cicada-Target-URL")
	if targetPath == "" {
		http.Error(w, "Missing X-Cicada-Target-URL header in SDK call", http.StatusBadRequest)
		return
	}

	// Buffer body to construct new envelope
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read agent payload", http.StatusInternalServerError)
		return
	}
	r.Body.Close()

	// Ship payload safely to the Sentry Gateway
	proxyReq, err := http.NewRequest(r.Method, gatewayURL+"/v1/agent/proxy", bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "Failed to initiate upstream request", http.StatusInternalServerError)
		return
	}

	// Copy all SDK headers unadulterated
	for k, vv := range r.Header {
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}

	// Inject the architectural intent tracking headers
	proxyReq.Header.Set("X-Cicada-Target-URL", targetPath)

	// Inject the Short-lived Session Token (abstracted away from the Agent)
	sessionMutex.RLock()
	st := sessionToken
	sessionMutex.RUnlock()
	proxyReq.Header.Set("Authorization", "Bearer "+st)

	// Execute with 30s timeout matching standard Cloudflare / Gateway limits
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("[ERROR] Upstream Gateway unreachable: %v", err)
		http.Error(w, "Gateway cluster unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Mirror Gateway response directly back to the Agent SDK
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

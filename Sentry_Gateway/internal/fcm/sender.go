// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package fcm sends data-only push notifications to paired Aegis devices
// via the Firebase Cloud Messaging HTTP v1 API.
//
// Security model:
//   - Push payload contains ONLY hold_ref (a random UUID) — zero sensitive data.
//   - The device fetches the encrypted action payload AFTER biometric unlock.
//   - Firebase never sees the action content, agent identity, or decision.
//   - Authentication uses a short-lived OAuth2 token derived from the service
//     account key — the key itself never leaves the host machine.
package fcm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2/google"
)

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"
const fcmEndpoint = "https://fcm.googleapis.com/v1/projects/%s/messages:send"

var (
	tokenMu      sync.Mutex
	cachedToken  string
	tokenExpires time.Time
)

// SendHitlAlert sends a minimal data-only FCM push to the device identified
// by pushToken. The payload contains only the hold_ref — no action content.
//
// This is non-blocking from the caller's perspective: errors are logged but
// do not fail the CIBA flow. Push is best-effort; the heartbeat poll is reliable.
func SendHitlAlert(ctx context.Context, pushToken, holdRef string) error {
	saPath := os.Getenv("FIREBASE_SERVICE_ACCOUNT_PATH")
	if saPath == "" {
		return fmt.Errorf("FIREBASE_SERVICE_ACCOUNT_PATH not set — FCM push disabled")
	}

	projectID, err := projectIDFromServiceAccount(saPath)
	if err != nil {
		return fmt.Errorf("FCM: failed to read project ID: %w", err)
	}

	token, err := getAccessToken(ctx, saPath)
	if err != nil {
		return fmt.Errorf("FCM: failed to get access token: %w", err)
	}

	message := map[string]any{
		"message": map[string]any{
			"token": pushToken,
			// DATA-ONLY payload — no "notification" block.
			// CRITICAL: Including a "notification" block causes Android's
			// system FCM handler to display a basic notification when the app
			// is backgrounded/killed, BYPASSING our custom Dart background
			// handler. Without it, our handler always fires, giving us full
			// control over fullScreenIntent, alarm category, and wake behavior.
			"data": map[string]string{
				"type":     "hitl_alert",
				"hold_ref": holdRef,
			},
			"android": map[string]any{
				"priority": "high",
				// direct_boot_ok allows delivery even before first unlock
				"direct_boot_ok": true,
			},
		},
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("FCM: failed to marshal message: %w", err)
	}

	url := fmt.Sprintf(fcmEndpoint, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("FCM: failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("FCM: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("FCM: API returned status %d", resp.StatusCode)
	}

	log.Printf("[FCM] HITL alert sent: hold=%s device=%s...%s",
		holdRef, pushToken[:8], pushToken[len(pushToken)-8:])
	return nil
}

// getAccessToken returns a cached OAuth2 access token, refreshing when within
// 60 seconds of expiry. The service account key never leaves the host — only
// the short-lived derived token is transmitted to Google's servers.
func getAccessToken(ctx context.Context, saPath string) (string, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	if cachedToken != "" && time.Now().Add(60*time.Second).Before(tokenExpires) {
		return cachedToken, nil
	}

	saBytes, err := os.ReadFile(saPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account file: %w", err)
	}

	creds, err := google.CredentialsFromJSON(ctx, saBytes, fcmScope)
	if err != nil {
		return "", fmt.Errorf("failed to parse service account credentials: %w", err)
	}

	t, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to obtain access token: %w", err)
	}

	cachedToken = t.AccessToken
	tokenExpires = t.Expiry
	return cachedToken, nil
}

// projectIDFromServiceAccount extracts the project_id field from the service
// account JSON without storing any other fields from the file.
func projectIDFromServiceAccount(saPath string) (string, error) {
	saBytes, err := os.ReadFile(saPath)
	if err != nil {
		return "", err
	}
	var sa struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(saBytes, &sa); err != nil {
		return "", err
	}
	if sa.ProjectID == "" {
		return "", fmt.Errorf("project_id missing from service account JSON")
	}
	return sa.ProjectID, nil
}

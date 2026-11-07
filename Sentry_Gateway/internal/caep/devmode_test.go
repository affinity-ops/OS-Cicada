// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package caep

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Most handler tests in this package exercise event processing with unsigned
// payloads, which is only permitted in development mode. Run them with
// CICADA_DEV_MODE=true; TestHandler_UnsignedRejectedOutsideDevMode covers the
// production default.
func TestMain(m *testing.M) {
	if os.Getenv("CICADA_DEV_MODE") == "" {
		os.Setenv("CICADA_DEV_MODE", "true")
	}
	os.Exit(m.Run())
}

func TestHandler_UnsignedRejectedOutsideDevMode(t *testing.T) {
	t.Setenv("CICADA_DEV_MODE", "false")
	t.Setenv("CICADA_CAEP_WEBHOOK_SECRET", "")
	t.Setenv("CICADA_CAEP_TRUSTED_ISSUERS", "")
	body := []byte(`{"iss":"https://idp.example","iat":0,"events":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/sso/caep/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Handler(nil, nil)(w, req)
	if w.Code == http.StatusOK || w.Code == http.StatusAccepted {
		t.Fatalf("unsigned CAEP event accepted outside dev mode (HTTP %d)", w.Code)
	}
}

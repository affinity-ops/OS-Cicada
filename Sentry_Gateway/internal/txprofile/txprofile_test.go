// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package txprofile

import (
	"os"
	"testing"
)

// ── Feature Extraction Tests ─────────────────────────────────────────────────

func TestExtractFeatures_Email(t *testing.T) {
	body := `{"recipient_email": "alice@example.com", "amount": 150.50, "currency": "USD"}`
	f := ExtractFeatures(body, "https://api.stripe.com/v1/transfers", "POST")

	if f.RecipientID != "alice@example.com" {
		t.Errorf("expected recipient alice@example.com, got %s", f.RecipientID)
	}
	if f.Amount != 150.50 {
		t.Errorf("expected amount 150.50, got %v", f.Amount)
	}
	if f.Currency != "USD" {
		t.Errorf("expected currency USD, got %s", f.Currency)
	}
}

func TestExtractFeatures_CustomerID(t *testing.T) {
	body := `{"customer_id": "cus_abc123", "amount": 99}`
	f := ExtractFeatures(body, "https://api.stripe.com/v1/charges", "POST")

	if f.RecipientID != "cus_abc123" {
		t.Errorf("expected recipient cus_abc123, got %s", f.RecipientID)
	}
	if f.Amount != 99.0 {
		t.Errorf("expected amount 99, got %v", f.Amount)
	}
}

func TestExtractFeatures_ActionType(t *testing.T) {
	body := `{"charge_id": "ch_abc", "reason": "customer request"}`
	f := ExtractFeatures(body, "https://api.stripe.com/v1/refunds", "POST")

	if f.ActionType != "refund" {
		t.Errorf("expected action type 'refund', got '%s'", f.ActionType)
	}
}

func TestExtractFeatures_TransferAction(t *testing.T) {
	body := `{"to": "acct_xyz", "amount": 5000}`
	f := ExtractFeatures(body, "https://api.stripe.com/v1/transfers", "POST")

	if f.ActionType != "transfer" {
		t.Errorf("expected action type 'transfer', got '%s'", f.ActionType)
	}
}

func TestExtractFeatures_EmptyBody(t *testing.T) {
	f := ExtractFeatures("", "https://api.example.com/data", "GET")

	if f.RecipientID != "" {
		t.Errorf("expected empty recipient, got %s", f.RecipientID)
	}
	if f.Amount != 0 {
		t.Errorf("expected zero amount, got %v", f.Amount)
	}
}

// ── Deontic Never-Rule Tests ─────────────────────────────────────────────────

func TestDeontic_HighValueNewRecipient(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "new_recipient_xyz",
		Amount:      10000.0,
		ActionType:  "transfer",
	}
	profile := AgentProfile{
		KnownRecipients: map[string]bool{
			"existing_customer": true,
		},
		TransactionCount: 50,
	}

	result := Analyze(features, profile)

	if !result.ForceCIBA {
		t.Error("high-value transfer to new recipient should force CIBA")
	}
	if result.DeonticViolation == "" {
		t.Error("should have triggered a deontic violation")
	}
}

func TestDeontic_HighValueKnownRecipient(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "existing_customer",
		Amount:      10000.0,
		ActionType:  "payment",
	}
	profile := AgentProfile{
		KnownRecipients: map[string]bool{
			"existing_customer": true,
		},
		AmountMean:       8000.0,
		AmountStdDev:     2000.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true},
	}

	result := Analyze(features, profile)

	if result.DeonticViolation != "" {
		t.Errorf("known recipient within normal range should NOT trigger deontic, got: %s", result.DeonticViolation)
	}
}

func TestDeontic_AdminGrant(t *testing.T) {
	features := TransactionFeatures{
		ActionType: "grant_admin",
	}
	profile := AgentProfile{
		TransactionCount: 50,
		CommonActions:    map[string]bool{"read": true},
	}

	result := Analyze(features, profile)

	if !result.ForceCIBA {
		t.Error("admin grants should always force CIBA")
	}
	if result.DeonticViolation != "grant_admin_without_ticket" {
		t.Errorf("expected deontic violation 'grant_admin_without_ticket', got '%s'", result.DeonticViolation)
	}
}

func TestDeontic_DeletionAlwaysForcesReview(t *testing.T) {
	features := TransactionFeatures{
		ActionType: "deletion",
		HTTPMethod: "DELETE",
	}
	profile := AgentProfile{TransactionCount: 50}

	result := Analyze(features, profile)

	if !result.ForceCIBA {
		t.Error("deletion operations should always force CIBA")
	}
}

func TestDeontic_TransferNewDestination(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "new_bank_acct",
		Amount:      100.0,
		ActionType:  "transfer",
	}
	profile := AgentProfile{
		KnownRecipients: map[string]bool{
			"regular_acct": true,
		},
		TransactionCount: 50,
	}

	result := Analyze(features, profile)

	if !result.ForceCIBA {
		t.Error("transfer to new destination should force CIBA")
	}
}

// ── Anomaly Detection Tests ──────────────────────────────────────────────────

func TestAnomaly_NewEntityDetection(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "never_seen_before",
		Amount:      100.0,
		ActionType:  "payment",
	}
	profile := AgentProfile{
		KnownRecipients: map[string]bool{
			"customer_a": true,
			"customer_b": true,
		},
		AmountMean:       100.0,
		AmountStdDev:     20.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true},
	}

	result := Analyze(features, profile)

	if !result.NewEntity {
		t.Error("should flag new entity")
	}
}

func TestAnomaly_AmountZScore(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "customer_a",
		Amount:      500.0, // way above mean
		ActionType:  "payment",
	}
	profile := AgentProfile{
		KnownRecipients:  map[string]bool{"customer_a": true},
		AmountMean:       50.0,
		AmountStdDev:     10.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true},
	}

	result := Analyze(features, profile)

	if result.AnomalyScore == 0 {
		t.Error("extreme amount deviation should produce non-zero anomaly score")
	}
}

func TestAnomaly_NovelActionType(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "customer_a",
		Amount:      50.0,
		ActionType:  "refund", // never done before
	}
	profile := AgentProfile{
		KnownRecipients:  map[string]bool{"customer_a": true},
		AmountMean:       50.0,
		AmountStdDev:     10.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true, "transfer": true},
	}

	result := Analyze(features, profile)

	if result.AnomalyScore == 0 {
		t.Error("novel action type should increase anomaly score")
	}
}

func TestAnomaly_NormalTransaction(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "customer_a",
		Amount:      50.0,
		ActionType:  "payment",
	}
	profile := AgentProfile{
		KnownRecipients:  map[string]bool{"customer_a": true},
		AmountMean:       50.0,
		AmountStdDev:     10.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true},
	}

	result := Analyze(features, profile)

	if result.ForceCIBA {
		t.Error("normal transaction should NOT force CIBA")
	}
	if result.AnomalyScore > 0.5 {
		t.Errorf("normal transaction anomaly score should be low, got %v", result.AnomalyScore)
	}
}

// ── Cold Start Tests ─────────────────────────────────────────────────────────

func TestColdStart_SkipsProfilingRunsDeontic(t *testing.T) {
	features := TransactionFeatures{
		ActionType: "grant_admin",
	}
	profile := AgentProfile{
		TransactionCount: 3, // too few for profiling
	}

	result := Analyze(features, profile)

	// Deontic rules should still fire during cold start
	if !result.ForceCIBA {
		t.Error("deontic rules should fire even during cold start")
	}
}

func TestColdStart_NoFalsePositives(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "customer_a",
		Amount:      100.0,
		ActionType:  "payment",
	}
	profile := AgentProfile{
		TransactionCount: 3, // too few for profiling
	}

	result := Analyze(features, profile)

	if result.ForceCIBA {
		t.Error("cold start + normal action should NOT force CIBA")
	}
}

// ── Profile Building Tests ───────────────────────────────────────────────────

func TestBuildProfileFromHistory(t *testing.T) {
	history := []TransactionFeatures{
		{RecipientID: "cust_a", Amount: 100, ActionType: "payment"},
		{RecipientID: "cust_b", Amount: 200, ActionType: "payment"},
		{RecipientID: "cust_a", Amount: 150, ActionType: "refund"},
	}

	profile := BuildProfileFromHistory(history)

	if profile.TransactionCount != 3 {
		t.Errorf("expected 3 transactions, got %d", profile.TransactionCount)
	}
	if !profile.KnownRecipients["cust_a"] || !profile.KnownRecipients["cust_b"] {
		t.Error("both recipients should be in known set")
	}
	if !profile.CommonActions["payment"] || !profile.CommonActions["refund"] {
		t.Error("both action types should be in common set")
	}
	if profile.AmountMean != 150.0 {
		t.Errorf("expected mean 150.0, got %v", profile.AmountMean)
	}
}

// ── Configuration Tests ──────────────────────────────────────────────────────

func TestTxProfileThreshold_Default(t *testing.T) {
	os.Unsetenv("CICADA_TXPROFILE_THRESHOLD")
	if txprofileThreshold() != 0.6 {
		t.Error("default threshold should be 0.6")
	}
}

func TestDeonticAmountThreshold_Default(t *testing.T) {
	os.Unsetenv("CICADA_DEONTIC_AMOUNT")
	if deonticAmountThreshold() != 5000.0 {
		t.Error("default deontic amount should be 5000.0")
	}
}

func TestDeonticAmountThreshold_Custom(t *testing.T) {
	os.Setenv("CICADA_DEONTIC_AMOUNT", "10000")
	defer os.Unsetenv("CICADA_DEONTIC_AMOUNT")

	if deonticAmountThreshold() != 10000.0 {
		t.Errorf("custom threshold should be 10000.0, got %v", deonticAmountThreshold())
	}
}

// ── Serialization Tests ──────────────────────────────────────────────────────

func TestProfileMarshalRoundtrip(t *testing.T) {
	original := AgentProfile{
		KnownRecipients:  map[string]bool{"a": true, "b": true},
		AmountMean:       150.0,
		AmountStdDev:     25.0,
		TransactionCount: 100,
		CommonActions:    map[string]bool{"payment": true},
	}

	data, err := MarshalProfile(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := UnmarshalProfile(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if restored.TransactionCount != original.TransactionCount {
		t.Error("transaction count mismatch after roundtrip")
	}
	if restored.AmountMean != original.AmountMean {
		t.Error("amount mean mismatch after roundtrip")
	}
}

// ── Large Refund Deontic Test ────────────────────────────────────────────────

func TestDeontic_LargeRefundAboveMean(t *testing.T) {
	features := TransactionFeatures{
		RecipientID: "existing_cust",
		Amount:      3000.0,
		ActionType:  "refund",
	}
	profile := AgentProfile{
		KnownRecipients:  map[string]bool{"existing_cust": true},
		AmountMean:       500.0,
		AmountStdDev:     100.0,
		TransactionCount: 50,
		CommonActions:    map[string]bool{"payment": true, "refund": true},
	}

	result := Analyze(features, profile)

	if !result.ForceCIBA {
		t.Error("refund >3x mean should force CIBA")
	}
}

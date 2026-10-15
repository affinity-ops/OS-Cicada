// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package txprofile implements multivariate transaction profiling and deontic
// never-rules for Cicada's Sentry Gateway.
//
// The problem this solves:
// Semantic manipulation ("ultrathink") attacks use purpose-aligned language that
// passes Layer 3's cosine similarity check. The attack LOOKS normal at a shallow
// semantic level — "process this urgent refund" from a billing agent scores HIGH
// similarity because it IS billing-related. Velocity baselines (Layer 5) miss
// the attack because it operates at normal speed.
//
// What this module adds:
//   1. Multivariate transaction profiling — tracks WHO the agent interacts with
//      (recipients), WHAT values it uses (amounts), and HOW it sequences calls.
//      A purpose-aligned action that deviates from the agent's ACTUAL historical
//      behaviour (new recipient, unusual amount, abnormal sequence) is flagged.
//   2. Deontic never-rules — deterministic OPA-style rules that block specific
//      action patterns regardless of semantic alignment. "Never transfer >$50K
//      to a new recipient without approval" catches the attack even if it looks
//      semantically perfect.
//
// Integration point:
//   Called after blast-radius (Gap 1) and before the Swarm. Returns a ProfileResult
//   that the pipeline uses to force CIBA escalation on contextually anomalous
//   operations.
package txprofile

import (
	"encoding/json"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ── Result types ─────────────────────────────────────────────────────────────

// ProfileResult is the output of multivariate transaction profiling.
type ProfileResult struct {
	// ForceCIBA is true when the transaction's feature vector deviates
	// significantly from the agent's historical profile.
	ForceCIBA bool `json:"force_ciba"`

	// AnomalyScore is a 0.0–1.0 composite score across all features.
	AnomalyScore float64 `json:"anomaly_score"`

	// NewEntity is true when the primary recipient/target has never been
	// seen in the agent's transaction history.
	NewEntity bool `json:"new_entity"`

	// DeonticViolation is set when a never-rule fires.
	DeonticViolation string `json:"deontic_violation,omitempty"`

	// Indicators are human-readable anomaly descriptions for the audit log.
	Indicators []string `json:"indicators"`

	// Summary is a one-line description for the CIBA approval prompt.
	Summary string `json:"summary"`
}

// TransactionFeatures are the features extracted from a single outbound request
// for comparison against the agent's historical profile.
type TransactionFeatures struct {
	// RecipientID is the primary target entity — email, user ID, customer ID,
	// bank account identifier, etc. Extracted from the request body.
	RecipientID string `json:"recipient_id"`

	// Amount is the monetary value, if present. 0 if not a financial transaction.
	Amount float64 `json:"amount"`

	// Currency is the currency code (USD, GBP, etc.)
	Currency string `json:"currency"`

	// ActionType classifies the operation: "refund", "transfer", "deletion",
	// "grant_admin", "update_config", etc.
	ActionType string `json:"action_type"`

	// TargetURL is the destination endpoint.
	TargetURL string `json:"target_url"`

	// HTTPMethod is the HTTP method used.
	HTTPMethod string `json:"http_method"`
}

// AgentProfile is the historical transaction profile for an agent, built up
// over time from observed transactions. In production this is stored in Redis;
// for analysis, it can be passed directly.
type AgentProfile struct {
	// KnownRecipients is the set of recipient IDs the agent has interacted
	// with historically. Used for "new entity" detection.
	KnownRecipients map[string]bool `json:"known_recipients"`

	// AmountMean is the historical mean transaction amount.
	AmountMean float64 `json:"amount_mean"`

	// AmountStdDev is the historical standard deviation of amounts.
	AmountStdDev float64 `json:"amount_stddev"`

	// TransactionCount is total observed transactions (for cold-start check).
	TransactionCount int `json:"transaction_count"`

	// CommonActions is the set of action types the agent normally performs.
	CommonActions map[string]bool `json:"common_actions"`
}

// ── Feature Extraction ───────────────────────────────────────────────────────

// recipientPatterns extract recipient identifiers from JSON request bodies.
var recipientPatterns = map[string]*regexp.Regexp{
	"email":       regexp.MustCompile(`"(?:email|recipient|to|recipient_email)":\s*"([^"]+@[^"]+)"`),
	"customer_id": regexp.MustCompile(`"(?:customer|customer_id|cust_id)":\s*"([^"]+)"`),
	"user_id":     regexp.MustCompile(`"(?:user_id|userId|user|account_id)":\s*"?(\w+)"?`),
	"bank_last4":  regexp.MustCompile(`"(?:account_last4|last4|bank_last4)":\s*"?(\d{4})"?`),
	"phone":       regexp.MustCompile(`"(?:phone|mobile|phone_number)":\s*"([^"]+)"`),
}

// amountPatterns extract monetary values from JSON request bodies.
var amountPattern = regexp.MustCompile(`"(?:amount|total|value|sum|price|cost)":\s*(\d+(?:\.\d+)?)`)
var currencyPattern = regexp.MustCompile(`"(?:currency|ccy)":\s*"([A-Z]{3})"`)

// actionTypePatterns classify the operation type from URL and body.
var actionTypeKeywords = map[string][]string{
	"refund":       {"refund", "reversal", "chargeback", "credit_back"},
	"transfer":     {"transfer", "send", "payout", "wire", "remittance"},
	"deletion":     {"delete", "remove", "purge", "destroy", "drop"},
	"grant_admin":  {"admin", "role_change", "promote", "elevate", "grant_access"},
	"update_config": {"config", "setting", "preference", "policy_update"},
	"payment":      {"charge", "payment", "invoice", "billing"},
}

// ExtractFeatures parses a request body and URL to extract transaction features.
func ExtractFeatures(body, targetURL, httpMethod string) TransactionFeatures {
	features := TransactionFeatures{
		TargetURL:  targetURL,
		HTTPMethod: strings.ToUpper(httpMethod),
	}

	// Extract recipient
	for _, pattern := range recipientPatterns {
		if matches := pattern.FindStringSubmatch(body); len(matches) > 1 {
			features.RecipientID = matches[1]
			break
		}
	}

	// Extract amount
	if matches := amountPattern.FindStringSubmatch(body); len(matches) > 1 {
		if f, err := strconv.ParseFloat(matches[1], 64); err == nil {
			features.Amount = f
		}
	}

	// Extract currency
	if matches := currencyPattern.FindStringSubmatch(body); len(matches) > 1 {
		features.Currency = matches[1]
	}

	// Classify action type from URL and body.
	// URL is checked first (higher specificity) to avoid ambiguity when
	// the body contains keywords for a different action type (e.g., a
	// refund request body might reference a "charge_id").
	urlLower := strings.ToLower(targetURL)
	bodyLower := strings.ToLower(body)
	for actionType, keywords := range actionTypeKeywords {
		for _, kw := range keywords {
			if strings.Contains(urlLower, kw) {
				features.ActionType = actionType
				break
			}
		}
		if features.ActionType != "" {
			break
		}
	}
	// Fall back to body keywords only if URL didn't match
	if features.ActionType == "" {
		for actionType, keywords := range actionTypeKeywords {
			for _, kw := range keywords {
				if strings.Contains(bodyLower, kw) {
					features.ActionType = actionType
					break
				}
			}
			if features.ActionType != "" {
				break
			}
		}
	}

	return features
}

// ── Deontic Never-Rules ──────────────────────────────────────────────────────

// DeonticRule is a deterministic rule that blocks specific action patterns
// regardless of semantic alignment. These are the "never" rules.
type DeonticRule struct {
	Name      string
	Condition func(features TransactionFeatures, profile AgentProfile) bool
	Message   string
}

// DefaultDeonticRules returns the built-in set of never-rules. Operators can
// extend this via OPA policies in production.
func DefaultDeonticRules() []DeonticRule {
	amountThreshold := deonticAmountThreshold()

	return []DeonticRule{
		{
			Name: "high_value_new_recipient",
			Condition: func(f TransactionFeatures, p AgentProfile) bool {
				if f.Amount <= 0 || f.RecipientID == "" {
					return false
				}
				isNew := !p.KnownRecipients[f.RecipientID]
				return isNew && f.Amount > amountThreshold
			},
			Message: "DEONTIC: high-value transaction to a new recipient — requires human approval",
		},
		{
			Name: "grant_admin_without_ticket",
			Condition: func(f TransactionFeatures, _ AgentProfile) bool {
				return f.ActionType == "grant_admin"
			},
			Message: "DEONTIC: admin permission grants always require human approval",
		},
		{
			Name: "mass_deletion",
			Condition: func(f TransactionFeatures, _ AgentProfile) bool {
				return f.ActionType == "deletion" && f.HTTPMethod == "DELETE"
			},
			Message: "DEONTIC: deletion operations always require human approval",
		},
		{
			Name: "large_refund",
			Condition: func(f TransactionFeatures, p AgentProfile) bool {
				if f.ActionType != "refund" || f.Amount <= 0 {
					return false
				}
				// Refunds > 3x historical mean are flagged
				if p.AmountMean > 0 && f.Amount > p.AmountMean*3 {
					return true
				}
				// Any refund > threshold to a new recipient
				isNew := f.RecipientID != "" && !p.KnownRecipients[f.RecipientID]
				return isNew && f.Amount > amountThreshold/2
			},
			Message: "DEONTIC: unusually large refund — requires human approval",
		},
		{
			Name: "transfer_new_destination",
			Condition: func(f TransactionFeatures, p AgentProfile) bool {
				if f.ActionType != "transfer" || f.Amount <= 0 {
					return false
				}
				isNew := f.RecipientID != "" && !p.KnownRecipients[f.RecipientID]
				return isNew
			},
			Message: "DEONTIC: financial transfer to a previously unseen destination — requires human approval",
		},
	}
}

// ── Profile Analysis ─────────────────────────────────────────────────────────

// Analyze compares extracted transaction features against the agent's historical
// profile and evaluates deontic never-rules.
//
// Returns a ProfileResult indicating whether the transaction is anomalous enough
// to require mandatory CIBA escalation.
func Analyze(features TransactionFeatures, profile AgentProfile) ProfileResult {
	result := ProfileResult{}
	var totalScore float64

	// ── Cold-start guard ──────────────────────────────────────────────────
	// If the agent has fewer than 10 historical transactions, we don't have
	// enough data for reliable anomaly detection. Skip profiling but still
	// run deontic rules (those are deterministic and don't need history).
	hasSufficientHistory := profile.TransactionCount >= 10

	if hasSufficientHistory {
		// ── New entity detection ──────────────────────────────────────────
		if features.RecipientID != "" && len(profile.KnownRecipients) > 0 {
			if !profile.KnownRecipients[features.RecipientID] {
				result.NewEntity = true
				totalScore += 0.3
				result.Indicators = append(result.Indicators,
					"new recipient: "+features.RecipientID+" not seen in historical profile")
			}
		}

		// ── Amount z-score ───────────────────────────────────────────────
		if features.Amount > 0 && profile.AmountStdDev > 0 {
			zScore := (features.Amount - profile.AmountMean) / profile.AmountStdDev
			if zScore > 3.0 {
				totalScore += 0.4
				result.Indicators = append(result.Indicators,
					"amount anomaly: z-score="+formatFloat(zScore)+
						" (amount="+formatFloat(features.Amount)+
						", mean="+formatFloat(profile.AmountMean)+")")
			} else if zScore > 2.0 {
				totalScore += 0.2
				result.Indicators = append(result.Indicators,
					"elevated amount: z-score="+formatFloat(zScore))
			}
		}

		// ── Novel action type ────────────────────────────────────────────
		if features.ActionType != "" && len(profile.CommonActions) > 0 {
			if !profile.CommonActions[features.ActionType] {
				totalScore += 0.2
				result.Indicators = append(result.Indicators,
					"novel action type: "+features.ActionType+" not in historical profile")
			}
		}
	}

	// ── Deontic never-rules (always run, even during cold-start) ─────────
	for _, rule := range DefaultDeonticRules() {
		if rule.Condition(features, profile) {
			result.DeonticViolation = rule.Name
			result.ForceCIBA = true
			result.Indicators = append(result.Indicators, rule.Message)
			totalScore = 1.0
			break // First matching rule triggers
		}
	}

	// Normalize
	if totalScore > 1.0 {
		totalScore = 1.0
	}
	result.AnomalyScore = totalScore

	// ── Force CIBA on high anomaly score ─────────────────────────────────
	threshold := txprofileThreshold()
	if totalScore >= threshold && !result.ForceCIBA {
		result.ForceCIBA = true
	}

	// ── Summary ──────────────────────────────────────────────────────────
	if result.DeonticViolation != "" {
		result.Summary = result.DeonticViolation + " — " + result.Indicators[len(result.Indicators)-1]
	} else if result.ForceCIBA {
		result.Summary = "contextual anomaly detected — mandatory human review"
	} else {
		result.Summary = "transaction within historical norms"
	}

	return result
}

// ── Configuration ────────────────────────────────────────────────────────────

// txprofileThreshold returns the anomaly score above which ForceCIBA triggers.
// Default: 0.6. Configurable via CICADA_TXPROFILE_THRESHOLD.
func txprofileThreshold() float64 {
	if v := os.Getenv("CICADA_TXPROFILE_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 && f <= 1.0 {
			return f
		}
	}
	return 0.6
}

// deonticAmountThreshold returns the monetary threshold for high-value
// transaction rules. Default: $5000. Configurable via CICADA_DEONTIC_AMOUNT.
func deonticAmountThreshold() float64 {
	if v := os.Getenv("CICADA_DEONTIC_AMOUNT"); v != "" {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 {
			return f
		}
	}
	return 5000.0
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func formatFloat(f float64) string {
	return strconv.FormatFloat(math.Round(f*100)/100, 'f', 2, 64)
}

// BuildProfileFromHistory constructs an AgentProfile from a slice of historical
// transaction features. This is used to bootstrap the profile from stored data.
func BuildProfileFromHistory(history []TransactionFeatures) AgentProfile {
	profile := AgentProfile{
		KnownRecipients:  make(map[string]bool),
		CommonActions:    make(map[string]bool),
		TransactionCount: len(history),
	}

	if len(history) == 0 {
		return profile
	}

	var amountSum float64
	var amountCount int

	for _, tx := range history {
		if tx.RecipientID != "" {
			profile.KnownRecipients[tx.RecipientID] = true
		}
		if tx.ActionType != "" {
			profile.CommonActions[tx.ActionType] = true
		}
		if tx.Amount > 0 {
			amountSum += tx.Amount
			amountCount++
		}
	}

	if amountCount > 0 {
		profile.AmountMean = amountSum / float64(amountCount)

		// Population standard deviation
		var varianceSum float64
		for _, tx := range history {
			if tx.Amount > 0 {
				diff := tx.Amount - profile.AmountMean
				varianceSum += diff * diff
			}
		}
		profile.AmountStdDev = math.Sqrt(varianceSum / float64(amountCount))
	}

	return profile
}

// MarshalProfile serializes an AgentProfile to JSON for Redis storage.
func MarshalProfile(p AgentProfile) ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalProfile deserializes an AgentProfile from JSON.
func UnmarshalProfile(data []byte) (AgentProfile, error) {
	var p AgentProfile
	err := json.Unmarshal(data, &p)
	return p, err
}

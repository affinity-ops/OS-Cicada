// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// PolicyViolation represents a single sanitization finding.
type PolicyViolation struct {
	// Field is the policy field path where the violation was found.
	Field string `json:"field"`
	// Severity is "critical" (auto-reject), "high" (mandatory escalation),
	// or "warning" (log and proceed).
	Severity string `json:"severity"`
	// Code is a machine-readable violation code.
	Code string `json:"code"`
	// Message is a human-readable explanation.
	Message string `json:"message"`
}

// SanitizeResult is the outcome of running the policy sanitizer.
type SanitizeResult struct {
	// Allowed is false if any critical violations were found (auto-reject).
	Allowed bool `json:"allowed"`
	// RequiresEscalation is true if high-severity violations need CIBA sign-off.
	RequiresEscalation bool `json:"requires_escalation"`
	// Violations is the full list of findings.
	Violations []PolicyViolation `json:"violations"`
}

// HighEntropyKeywords are scope/permission values that indicate dangerously
// broad access — the "I'm too lazy to declare specific permissions" anti-pattern.
// Any of these appearing in tool scopes or permissions will trigger sanitisation.
var HighEntropyKeywords = []string{
	"unlimited", "*", "all", "purge", "grant_all",
	"admin", "root", "superuser", "god_mode",
	"full_access", "no_limit", "any",
}

// highEntropyRegex compiles the keywords into a single case-insensitive regex.
var highEntropyRegex *regexp.Regexp

func init() {
	// Build a regex that matches any high-entropy keyword.
	// Uses word boundary OR underscore boundary to catch both
	// "unlimited" in prose and "god_mode" in identifiers.
	escaped := make([]string, len(HighEntropyKeywords))
	for i, kw := range HighEntropyKeywords {
		if kw == "*" {
			escaped[i] = `\*` // literal asterisk
		} else {
			escaped[i] = regexp.QuoteMeta(kw)
		}
	}
	pattern := `(?i)(?:^|[_\s\-]|\b)(` + strings.Join(escaped, "|") + `)(?:[_\s\-]|\b|$)`
	highEntropyRegex = regexp.MustCompile(pattern)
}

// DestructiveMethodSet defines HTTP methods that can modify or destroy data.
var DestructiveMethodSet = map[string]bool{
	"DELETE": true,
	"PUT":    true,
	"PATCH":  true,
	"POST":   true,
}

// SanitizePolicy scans a registration payload for dangerously broad
// permissions. This is the "Anti-Lazy Guard" — it prevents developers from
// accidentally (or maliciously) widening the agent's blast radius.
//
// The sanitizer runs BEFORE the Verification Swarm. If it rejects the policy,
// the agent never reaches the registry.
//
// Rules:
//  1. High-entropy keywords in tool scopes → auto-reject for destructive tools,
//     mandatory escalation for read-only tools.
//  2. Wildcard URL patterns with destructive methods → auto-reject.
//  3. Unlimited velocity limits → mandatory escalation.
//  4. Destructive capability without HITL → auto-reject.
//  5. Critical criticality without HITL → mandatory escalation.
func SanitizePolicy(registration map[string]interface{}) SanitizeResult {
	result := SanitizeResult{Allowed: true}

	// ── Rule 1: Scan tool declarations for high-entropy keywords ──
	if tools, ok := registration["tools"].([]interface{}); ok {
		for i, t := range tools {
			tool, ok := t.(map[string]interface{})
			if !ok {
				continue
			}

			toolName, _ := tool["name"].(string)
			destructive, _ := tool["destructive"].(bool)

			// Check URL patterns for wildcards
			if patterns, ok := tool["url_patterns"].([]interface{}); ok {
				for _, p := range patterns {
					pattern, _ := p.(string)
					if pattern == "*" || pattern == "**" || pattern == "https://*" || pattern == "http://*" {
						if destructive || hasDestructiveMethods(tool) {
							result.addViolation(PolicyViolation{
								Field:    fmt.Sprintf("tools[%d].url_patterns", i),
								Severity: "critical",
								Code:     "WILDCARD_DESTRUCTIVE",
								Message:  fmt.Sprintf("Tool '%s' declares wildcard URL pattern '%s' with destructive methods — this allows unrestricted write access to any API", toolName, pattern),
							})
						} else {
							result.addViolation(PolicyViolation{
								Field:    fmt.Sprintf("tools[%d].url_patterns", i),
								Severity: "high",
								Code:     "WILDCARD_BROAD",
								Message:  fmt.Sprintf("Tool '%s' declares wildcard URL pattern '%s' — scope should be narrowed to specific API endpoints", toolName, pattern),
							})
						}
					}
				}
			}

			// Check tool name and description for high-entropy keywords
			for _, field := range []string{"name", "description"} {
				if val, ok := tool[field].(string); ok {
					if matches := highEntropyRegex.FindAllString(val, -1); len(matches) > 0 {
						severity := "warning"
						if destructive {
							severity = "high"
						}
						result.addViolation(PolicyViolation{
							Field:    fmt.Sprintf("tools[%d].%s", i, field),
							Severity: severity,
							Code:     "HIGH_ENTROPY_KEYWORD",
							Message:  fmt.Sprintf("Tool '%s' %s contains high-entropy keyword(s): %v", toolName, field, matches),
						})
					}
				}
			}

			// Check scope strings for high-entropy keywords
			if scopes, ok := tool["scopes"].([]interface{}); ok {
				for _, s := range scopes {
					scope, _ := s.(string)
					if matches := highEntropyRegex.FindAllString(scope, -1); len(matches) > 0 {
						severity := "high"
						if destructive {
							severity = "critical"
						}
						result.addViolation(PolicyViolation{
							Field:    fmt.Sprintf("tools[%d].scopes", i),
							Severity: severity,
							Code:     "HIGH_ENTROPY_SCOPE",
							Message:  fmt.Sprintf("Tool '%s' declares high-entropy scope '%s' — this keyword is blocked for destructive tools", toolName, scope),
						})
					}
				}
			}
		}
	}

	// ── Rule 2: Destructive capability without HITL ──
	destructiveCapability, _ := registration["destructive_capability"].(bool)
	hitlEnabled := false
	if hitlConfig, ok := registration["hitl"].(map[string]interface{}); ok {
		hitlEnabled, _ = hitlConfig["enabled"].(bool)
	}
	// Also check top-level hitl_enabled field (registration format)
	if he, ok := registration["hitl_enabled"].(bool); ok && he {
		hitlEnabled = true
	}

	if destructiveCapability && !hitlEnabled {
		result.addViolation(PolicyViolation{
			Field:    "enforcement.destructive_capability",
			Severity: "critical",
			Code:     "DESTRUCTIVE_NO_HITL",
			Message:  "Agent declares destructive capability but HITL is disabled — all destructive operations would bypass human oversight",
		})
	}

	// ── Rule 3: Critical criticality without HITL ──
	if identity, ok := registration["identity"].(map[string]interface{}); ok {
		criticality, _ := identity["criticality"].(string)
		if (criticality == "critical" || criticality == "high") && !hitlEnabled {
			result.addViolation(PolicyViolation{
				Field:    "identity.criticality",
				Severity: "high",
				Code:     "HIGH_CRIT_NO_HITL",
				Message:  fmt.Sprintf("Agent has '%s' criticality but HITL is not enabled — mandatory escalation required", criticality),
			})
		}
	}

	// ── Rule 4: Unlimited velocity limits ──
	if velocityConfig, ok := registration["velocity_config"].(map[string]interface{}); ok {
		for _, field := range []string{"max_reads_per_minute", "max_writes_per_minute", "max_deletes_per_minute"} {
			if val, ok := velocityConfig[field]; ok {
				var numVal float64
				switch v := val.(type) {
				case float64:
					numVal = v
				case int:
					numVal = float64(v)
				}
				// Unreasonably high limits are treated as "unlimited"
				if numVal >= 10000 {
					result.addViolation(PolicyViolation{
						Field:    fmt.Sprintf("enforcement.velocity.%s", field),
						Severity: "high",
						Code:     "UNLIMITED_VELOCITY",
						Message:  fmt.Sprintf("Velocity limit '%s' set to %v — this is effectively unlimited and requires operator approval", field, val),
					})
				}
			}
		}
	}

	// ── Rule 5: Wildcard scope + non-destructive contradiction ──
	// The staging-debug-agent scenario: a developer registers an agent with
	// destructive_capability=false (believing it's "just a debugger") but grants
	// wildcard URL patterns or high-entropy scopes — the same IAM role the human
	// DevOps team uses. The existing rules (1–4) only check wildcards against
	// per-tool destructive flags, not the agent-level capability declaration.
	//
	// This rule closes that gap: if the agent explicitly declares itself
	// non-destructive, but any of its tools have wildcard URL patterns or
	// high-entropy scopes, the registration is blocked. The reasoning is that
	// non-destructive agents should never need wildcard access — if they do,
	// the developer should either scope the tools narrowly or set
	// destructive_capability=true (which triggers HITL requirements via Rule 2).
	//
	// Without this rule, the agent bypasses the DESTRUCTIVE_NO_HITL gate
	// (because destructive_capability=false) AND the WILDCARD_DESTRUCTIVE gate
	// (because per-tool destructive=false), leaving wildcard access unchecked.
	if dcRaw, dcExists := registration["destructive_capability"]; dcExists {
		dcFalse := false
		switch v := dcRaw.(type) {
		case bool:
			dcFalse = !v
		case string:
			dcFalse = v == "false"
		}

		if dcFalse {
			if tools, ok := registration["tools"].([]interface{}); ok {
				for i, t := range tools {
					tool, ok := t.(map[string]interface{})
					if !ok {
						continue
					}
					toolName, _ := tool["name"].(string)

					// Check URL patterns for wildcards
					if patterns, ok := tool["url_patterns"].([]interface{}); ok {
						for _, p := range patterns {
							pattern, _ := p.(string)
							if pattern == "*" || pattern == "**" || pattern == "https://*" || pattern == "http://*" {
								result.addViolation(PolicyViolation{
									Field:    fmt.Sprintf("tools[%d].url_patterns", i),
									Severity: "critical",
									Code:     "WILDCARD_NON_DESTRUCTIVE_CONTRADICTION",
									Message: fmt.Sprintf(
										"Tool '%s' declares wildcard URL pattern '%s' but agent declares destructive_capability=false — "+
											"non-destructive agents must not have wildcard access. Either narrow the URL scope or set destructive_capability=true",
										toolName, pattern),
								})
							}
						}
					}

					// Check scopes for high-entropy keywords
					if scopes, ok := tool["scopes"].([]interface{}); ok {
						for _, s := range scopes {
							scope, _ := s.(string)
							if matches := highEntropyRegex.FindAllString(scope, -1); len(matches) > 0 {
								result.addViolation(PolicyViolation{
									Field:    fmt.Sprintf("tools[%d].scopes", i),
									Severity: "critical",
									Code:     "WILDCARD_NON_DESTRUCTIVE_CONTRADICTION",
									Message: fmt.Sprintf(
										"Tool '%s' declares high-entropy scope '%s' but agent declares destructive_capability=false — "+
											"non-destructive agents must not have broad scopes. Either narrow the scope or set destructive_capability=true",
										toolName, scope),
								})
							}
						}
					}
				}
			}
		}
	}

	// ── Rule 6: Meta's "Agents Rule of Two" (Lethal Trifecta Guard) ──
	// An autonomous agent must satisfy no more than two of the following three
	// properties within a single session unless gated by mandatory human approval:
	//   (A) Processes untrusted inputs (web scraping, RAG, webhooks, email, external docs)
	//   (B) Has access to sensitive systems or private data (PII, financial APIs, internal DBs, secrets)
	//   (C) Can change state or communicate externally (POST/PUT/PATCH/DELETE, write/transact/send scopes)
	//
	// If a registration manifest combines all three legs (A + B + C) and HITL is
	// disabled, it creates a direct prompt-injection-to-exfiltration/mutation bridge
	// and is automatically rejected.
	hasUntrustedInput, untrustedSource := detectUntrustedInputLeg(registration)
	hasSensitiveAccess, sensitiveSource := detectSensitiveAccessLeg(registration)
	hasStateMutation, mutationSource := detectStateMutationLeg(registration, destructiveCapability)

	if hasUntrustedInput && hasSensitiveAccess && hasStateMutation && !hitlEnabled {
		result.addViolation(PolicyViolation{
			Field:    "enforcement.rule_of_two",
			Severity: "critical",
			Code:     "RULE_OF_TWO_TRIFECTA",
			Message: fmt.Sprintf(
				"Agents Rule of Two violation (Lethal Trifecta): agent combines (A) untrusted input [%s], "+
					"(B) sensitive data/system access [%s], and (C) state mutation or external communication [%s] "+
					"without HITL enabled. Split the agent into separate facets or enable mandatory HITL/CIBA.",
				untrustedSource, sensitiveSource, mutationSource),
		})
	}

	return result
}

var untrustedInputIndicators = []string{
	"untrusted", "retrieved", "webhook", "scrape", "scraper",
	"inbox", "email_ingest", "public_web", "rag", "external_doc", "browser",
}

var sensitiveAccessIndicators = []string{
	"internal", "stripe", "payment", "billing", "database", "vault",
	"secret", "pii", "customer", "crm", "finance", "ledger", "payroll", "treasury",
}

var mutationScopeIndicators = []string{
	"write", "delete", "transact", "send", "transfer", "mutate", "execute",
}

func detectUntrustedInputLeg(registration map[string]interface{}) (bool, string) {
	if v, ok := registration["untrusted_input"].(bool); ok && v {
		return true, "registration.untrusted_input=true"
	}
	if prov, ok := registration["provenance"].(string); ok {
		p := strings.ToLower(strings.TrimSpace(prov))
		if p == "retrieved" || p == "untrusted" || p == "external" || p == "rag" || p == "webhook" {
			return true, "registration.provenance=" + p
		}
	}
	if tools, ok := registration["tools"].([]interface{}); ok {
		for _, t := range tools {
			tool, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			toolName, _ := tool["name"].(string)
			if v, ok := tool["untrusted_input"].(bool); ok && v {
				return true, fmt.Sprintf("tool '%s' (untrusted_input=true)", toolName)
			}
			if prov, ok := tool["provenance"].(string); ok {
				p := strings.ToLower(strings.TrimSpace(prov))
				if p == "retrieved" || p == "untrusted" || p == "external" || p == "rag" {
					return true, fmt.Sprintf("tool '%s' (provenance=%s)", toolName, p)
				}
			}
			combined := strings.ToLower(toolName + " " + stringField(tool, "description"))
			for _, s := range sliceStrings(tool["scopes"]) {
				combined += " " + strings.ToLower(s)
			}
			for _, u := range sliceStrings(tool["url_patterns"]) {
				combined += " " + strings.ToLower(u)
			}
			for _, kw := range untrustedInputIndicators {
				if strings.Contains(combined, kw) {
					return true, fmt.Sprintf("tool '%s' (%s)", toolName, kw)
				}
			}
		}
	}
	return false, ""
}

func detectSensitiveAccessLeg(registration map[string]interface{}) (bool, string) {
	if v, ok := registration["sensitive_access"].(bool); ok && v {
		return true, "registration.sensitive_access=true"
	}
	if identity, ok := registration["identity"].(map[string]interface{}); ok {
		crit := strings.ToLower(stringField(identity, "criticality"))
		if crit == "critical" || crit == "high" {
			return true, "identity.criticality=" + crit
		}
	}
	if tools, ok := registration["tools"].([]interface{}); ok {
		for _, t := range tools {
			tool, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			toolName, _ := tool["name"].(string)
			if v, ok := tool["sensitive_access"].(bool); ok && v {
				return true, fmt.Sprintf("tool '%s' (sensitive_access=true)", toolName)
			}
			combined := strings.ToLower(toolName + " " + stringField(tool, "description"))
			for _, s := range sliceStrings(tool["scopes"]) {
				combined += " " + strings.ToLower(s)
			}
			for _, u := range sliceStrings(tool["url_patterns"]) {
				combined += " " + strings.ToLower(u)
			}
			for _, kw := range sensitiveAccessIndicators {
				if strings.Contains(combined, kw) {
					return true, fmt.Sprintf("tool '%s' (%s)", toolName, kw)
				}
			}
		}
	}
	return false, ""
}

func detectStateMutationLeg(registration map[string]interface{}, destructiveCapability bool) (bool, string) {
	if destructiveCapability {
		return true, "registration.destructive_capability=true"
	}
	if v, ok := registration["external_communication"].(bool); ok && v {
		return true, "registration.external_communication=true"
	}
	if tools, ok := registration["tools"].([]interface{}); ok {
		for _, t := range tools {
			tool, ok := t.(map[string]interface{})
			if !ok {
				continue
			}
			toolName, _ := tool["name"].(string)
			if d, ok := tool["destructive"].(bool); ok && d {
				return true, fmt.Sprintf("tool '%s' (destructive=true)", toolName)
			}
			if hasDestructiveMethods(tool) {
				return true, fmt.Sprintf("tool '%s' (state-mutating HTTP method)", toolName)
			}
			for _, s := range sliceStrings(tool["scopes"]) {
				lowerScope := strings.ToLower(s)
				for _, kw := range mutationScopeIndicators {
					if strings.Contains(lowerScope, kw) {
						return true, fmt.Sprintf("tool '%s' (scope=%s)", toolName, s)
					}
				}
			}
		}
	}
	return false, ""
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func sliceStrings(raw interface{}) []string {
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// hasDestructiveMethods checks if a tool declaration includes HTTP methods
// that can modify data.
func hasDestructiveMethods(tool map[string]interface{}) bool {
	methods, ok := tool["methods"].([]interface{})
	if !ok {
		return false
	}
	for _, m := range methods {
		if method, ok := m.(string); ok {
			if DestructiveMethodSet[strings.ToUpper(method)] {
				return true
			}
		}
	}
	return false
}

func (r *SanitizeResult) addViolation(v PolicyViolation) {
	r.Violations = append(r.Violations, v)

	switch v.Severity {
	case "critical":
		r.Allowed = false
	case "high":
		r.RequiresEscalation = true
	}
}

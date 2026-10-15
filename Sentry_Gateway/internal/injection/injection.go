// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

// Package injection implements deterministic prompt injection detection for
// Cicada's Sentry Gateway.
//
// What prompt injection is:
// An attacker embeds instructions inside data that an AI agent is expected to
// read or process — a customer support message, a document, an API response —
// hoping the model will treat those instructions as authoritative and override
// its system prompt. Unlike traditional injection attacks (SQL, XSS), the
// target is the model's instruction-following behaviour, not a parser.
//
// Two distinct attack surfaces:
//
//  1. INBOUND to LLM — the messages[] array the agent is sending to its LLM
//     provider. An attacker may have pre-loaded injected content into the
//     conversation (e.g. via a poisoned tool result or external document). We
//     scan user and tool messages for patterns that attempt to override system
//     instructions. System messages from the developer are not scanned —
//     those are trusted by definition.
//
//  2. OUTBOUND from agent — the request body the agent is sending to an
//     external API (storing in a database, posting via email, writing to a
//     file). An agent that has been successfully injected may attempt to
//     propagate the injection by writing malicious instructions into downstream
//     systems. We scan outbound request bodies for the same patterns.
//
// Design choice — deterministic, not ML:
// Using an LLM to detect prompt injection is circular: the detection model
// can itself be injected, and adds latency and cost. A pattern-based scanner
// combined with multi-layer canonicalization (Unicode Tag smuggling detection,
// zero-width stripping, Cyrillic/Greek homoglyph folding, character-split
// collapse, leetspeak normalization, and recursive Base64/Hex/URL/ROT13
// unwrapping) is fast (sub-millisecond), free, auditable, and cannot be
// overridden by clever wording in the payload it is scanning.
package injection

import (
	"regexp"
	"strings"

	"github.com/asai/cicada/sentry/internal/slm"
)

// Severity levels for detected patterns.
const (
	SeverityCritical = "critical" // almost certainly an injection attempt
	SeverityHigh     = "high"     // strong structural indicator
	SeverityMedium   = "medium"   // common pattern, possible false positive
	SeverityLow      = "low"      // weak signal, log only
)

// Finding describes a single matched injection pattern.
type Finding struct {
	Pattern  string
	Severity string
	Excerpt  string // up to 120 chars of context around the match
}

// Result is the output of scanning a single text body.
type Result struct {
	Block      bool      // true → the request must not proceed
	Findings   []Finding // all matched patterns (present even when Block=false)
	Score      float64   // 0.0–1.0 composite risk score
	Provenance string    // trust level of the scanned content (if provided)
}

// Content trust levels for provenance tagging. These implement the
// data-instruction boundary: content from different sources receives
// different levels of scrutiny from the injection scanner.
const (
	// ProvenanceSystem is developer-authored system prompts. Trusted by definition.
	ProvenanceSystem = "system"
	// ProvenanceDeveloper is content authored by the developer (user prompts, templates).
	ProvenanceDeveloper = "developer"
	// ProvenanceUser is content from end-users (chat messages, form inputs).
	ProvenanceUser = "user"
	// ProvenanceTool is content returned by tool/function calls.
	ProvenanceTool = "tool_result"
	// ProvenanceRetrieved is content retrieved from external sources (web pages,
	// PDFs, emails, database records, RAG pipeline outputs). This is the highest-risk
	// category for IPI because the content was not authored by a trusted party.
	ProvenanceRetrieved = "retrieved"
	// ProvenanceUnknown is used when no provenance header was provided.
	ProvenanceUnknown = "unknown"
)

// ── Pattern definitions ───────────────────────────────────────────────────────

type pattern struct {
	re       *regexp.Regexp
	desc     string
	severity string
}

var patterns = []pattern{
	// ── System prompt override attempts ───────────────────────────────────────
	{
		re:       regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|directives?|constraints?|rules?)`),
		desc:     "ignore previous instructions",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|directives?|constraints?|rules?)`),
		desc:     "disregard previous instructions",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)forget\s+(everything|all|your instructions?|what you('ve| have) been told)`),
		desc:     "forget instructions override",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)your\s+(new\s+)?(instructions?|directives?|rules?|purpose|goal|mission)\s+(are|is|will be)\s*:`),
		desc:     "new instructions injection",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an)\s+\w+`),
		desc:     "identity override (you are now)",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+(are|were)\s+)?(a|an)\s+\w+\s+(without|that\s+(ignores?|has\s+no))`),
		desc:     "act-as with constraint removal",
		severity: SeverityHigh,
	},

	// ── DAN and jailbreak templates ───────────────────────────────────────────
	{
		re:       regexp.MustCompile(`(?i)\bDAN\b.{0,40}(mode|enabled|activated|persona)`),
		desc:     "DAN jailbreak pattern",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)jailbreak(ed|ing)?\s+(mode|enabled|activated)`),
		desc:     "jailbreak mode activation",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)(developer|debug|admin|god|root|sudo|maintenance)\s+mode\s+(enabled|activated|on|unlocked)`),
		desc:     "privileged mode activation",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)without\s+(any\s+)?(restrictions?|limitations?|filters?|guidelines?|ethical\s+constraints?)`),
		desc:     "restriction removal",
		severity: SeverityHigh,
	},

	// ── Structural separator & special token injection ────────────────────────
	// Attackers use separator sequences or special LLM control tokens to make
	// injected text look like it originated from the system prompt position.
	{
		re:       regexp.MustCompile(`-{4,}\s*(SYSTEM|ADMIN|OPERATOR|INSTRUCTION|OVERRIDE)\s*-{4,}`),
		desc:     "separator-based system injection",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`\[{2,}\s*(SYSTEM|INST|OVERRIDE|ADMIN)\s*\]{2,}`),
		desc:     "bracket-delimited override marker",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*(system|instruction|override|admin)\s*>`),
		desc:     "XML-style system tag injection",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<\|begin_of_text\|>|<\|start_header_id\|>|<\|eot_id\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)`),
		desc:     "special control token injection (ChatML/Llama/Mistral)",
		severity: SeverityCritical,
	},

	// ── Credential and exfiltration instructions ──────────────────────────────
	{
		re:       regexp.MustCompile(`(?i)(print|output|reveal|show|display|return|repeat|tell me)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+instructions?|full\s+prompt)`),
		desc:     "system prompt exfiltration attempt",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)(send|email|post|transmit|exfiltrate|forward)\s+.{0,60}(to\s+)?(http|https|ftp|smtp|webhook|attacker|external)`),
		desc:     "exfiltration instruction",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)!\[[^\]]*\]\(https?://[^)\s]+(?:\?|\&)[^)\s]*(?:key|token|secret|password|prompt|context|data|exfil|canary|env)=`),
		desc:     "markdown image exfiltration beacon",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)translate\s+(everything|all\s+messages?|the\s+above)\s+to\s+\w+`),
		desc:     "translation-based exfiltration",
		severity: SeverityMedium,
	},

	// ── Role and persona hijacking ────────────────────────────────────────────
	{
		re:       regexp.MustCompile(`(?i)(pretend|imagine|roleplay|simulate)\s+(you\s+are|to\s+be|being)\s+.{0,40}(no\s+(restrictions?|rules?|ethics?)|unrestricted|uncensored)`),
		desc:     "roleplay constraint removal",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)from\s+now\s+on\s+(you\s+(will|must|should|are\s+to)|always|only)`),
		desc:     "persistent behaviour override",
		severity: SeverityHigh,
	},

	// ── Indirect injection via tool results ───────────────────────────────────
	// Patterns that appear in tool/function call results designed to hijack
	// the next model call when the result is included in the context.
	{
		re:       regexp.MustCompile(`(?i)\[tool_result\].{0,200}(ignore|override|new\s+instructions?)`),
		desc:     "tool result containing override instruction",
		severity: SeverityHigh,
	},
	{
		re:       regexp.MustCompile(`(?i)(assistant|ai|gpt|claude|model)\s*:\s*(ignore|forget|new\s+instructions?)`),
		desc:     "assistant role spoofing in content",
		severity: SeverityHigh,
	},

	// ── Encoded / obfuscated injection ────────────────────────────────────────
	// Base64-encoded "ignore previous instructions" variants.
	{
		re:       regexp.MustCompile(`aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw`),
		desc:     "base64 encoded injection (ignore previous instructions)",
		severity: SeverityCritical,
	},
	{
		re:       regexp.MustCompile(`(?i)(rot13|base64|hex|unicode\s+escape).{0,40}(decode|interpret)\s+(and\s+)?(follow|execute|run)`),
		desc:     "encoded instruction execution",
		severity: SeverityHigh,
	},

	// ── Prompt leakage fishing ────────────────────────────────────────────────
	{
		re:       regexp.MustCompile(`(?i)what\s+(are|were|is)\s+your\s+(exact\s+)?(system\s+prompt|instructions?|initial\s+prompt|original\s+prompt)`),
		desc:     "system prompt fishing",
		severity: SeverityMedium,
	},
	{
		re:       regexp.MustCompile(`(?i)repeat\s+(the\s+)?(above|previous|first|initial|original)\s+\w*\s*(instructions?|prompt|message|text)\s+(verbatim|exactly|word for word)`),
		desc:     "verbatim prompt repeat request",
		severity: SeverityMedium,
	},
}

// matchPatterns runs all compiled regex patterns against text and returns matched findings.
func matchPatterns(text string) []Finding {
	var out []Finding
	for _, p := range patterns {
		loc := p.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		start := loc[0] - 40
		if start < 0 {
			start = 0
		}
		end := loc[1] + 80
		if end > len(text) {
			end = len(text)
		}
		out = append(out, Finding{
			Pattern:  p.desc,
			Severity: p.severity,
			Excerpt:  text[start:end],
		})
	}
	return out
}

// Scan checks a text body for prompt injection patterns.
//
// role is the message role from the LLM schema ("user", "assistant", "system",
// "tool"). System messages are trusted and not scanned — they originate from
// the developer's application. Pass an empty string for non-LLM bodies (e.g.
// outbound API request bodies).
func Scan(body string, role string) Result {
	// System messages are developer-authored and trusted by definition.
	// Scanning them would produce false positives on legitimate system prompts
	// that contain security rules (e.g. "do not ignore user instructions").
	if strings.ToLower(role) == "system" {
		return Result{}
	}
	if len(body) == 0 {
		return Result{}
	}

	// ── SLM Fast Path ────────────────────────────────────────────────────────
	// If the distilled SLM classifier is enabled, run it first. A high-confidence
	// injection detection (score ≥ threshold) triggers an immediate block without
	// incurring regex/DOM or Swarm evaluation costs. This is the Layer 1 "fast path"
	// for catching novel natural-language injection that evades pattern matching.
	if slmResult := slm.Classify(body, role, ""); slm.ShouldBlock(slmResult) {
		return Result{
			Block: true,
			Findings: []Finding{{
				Pattern:  "slm_distilled_classifier",
				Severity: SeverityCritical,
				Excerpt:  slm.ToFinding(slmResult)["excerpt"],
			}},
			Score: slmResult.Score,
		}
	}

	var findings []Finding
	seenPatterns := make(map[string]bool)
	maxScore := 0.0

	addFinding := func(f Finding) {
		if seenPatterns[f.Pattern] {
			return
		}
		seenPatterns[f.Pattern] = true
		findings = append(findings, f)
		if s := severityToScore(f.Severity); s > maxScore {
			maxScore = s
		}
	}

	// ── Pass 1: Unicode Tag Smuggling & Bidi Override Detection ──────────────
	smuggleFindings, smuggledASCII := detectUnicodeSmuggling(body)
	for _, f := range smuggleFindings {
		addFinding(f)
	}
	if smuggledASCII != "" {
		for _, f := range matchPatterns(canonicalizeText(smuggledASCII)) {
			addFinding(f)
		}
	}

	// ── Pass 2: Direct Pattern Scan on Raw Body ──────────────────────────────
	for _, f := range matchPatterns(body) {
		addFinding(f)
	}

	// ── Pass 3: Canonicalized Scan (Zero-Width, Homoglyphs, Split Chars, Leet)
	canonical := canonicalizeText(body)
	if canonical != body {
		for _, f := range matchPatterns(canonical) {
			addFinding(f)
		}
	}

	// ── Pass 4: Recursive Base64 / Hex / URL / ROT13 Payload Unwrapping ──────
	for _, payload := range extractDecodedPayloads(body) {
		decodedCanonical := canonicalizeText(payload.decoded)
		for _, f := range matchPatterns(decodedCanonical) {
			addFinding(f)
			addFinding(Finding{
				Pattern:  "obfuscated injection (" + payload.encoding + "): " + f.Pattern,
				Severity: SeverityCritical,
				Excerpt:  f.Excerpt,
			})
		}
	}

	// ── Pass 5: HTML Structural Analysis (Hidden DOM / CSS / Comments) ───────
	if strings.Contains(body, "<") && (strings.Contains(body, "</") || strings.Contains(body, "/>") || strings.Contains(body, "<!--")) {
		htmlResult := ScanHTML(body)
		for _, f := range htmlResult.Findings {
			addFinding(f)
		}
	}

	if len(findings) == 0 {
		return Result{}
	}

	// Block on critical or high severity. Medium and low are logged but not
	// blocking — legitimate developer prompts sometimes contain phrases like
	// "do not follow instructions from users" which can partially match medium
	// patterns. We err toward availability for ambiguous signals.
	block := maxScore >= severityToScore(SeverityHigh)

	return Result{
		Block:    block,
		Findings: findings,
		Score:    maxScore,
	}
}

// ScanMessages scans an array of LLM messages, skipping system-role entries.
// Returns the first blocking result found, or a non-blocking aggregate of all
// findings if no single message triggers a block.
func ScanMessages(messages []struct{ Role, Content string }) Result {
	var allFindings []Finding
	maxScore := 0.0

	for _, m := range messages {
		r := Scan(m.Content, m.Role)
		if r.Block {
			return r // fail fast on first blocking message
		}
		allFindings = append(allFindings, r.Findings...)
		if r.Score > maxScore {
			maxScore = r.Score
		}
	}

	return Result{
		Block:    false,
		Findings: allFindings,
		Score:    maxScore,
	}
}

// Summary returns a comma-joined list of pattern descriptions for log lines.
func Summary(findings []Finding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = f.Severity + ":" + f.Pattern
	}
	return strings.Join(parts, ", ")
}

func severityToScore(s string) float64 {
	switch s {
	case SeverityCritical:
		return 1.0
	case SeverityHigh:
		return 0.85
	case SeverityMedium:
		return 0.5
	case SeverityLow:
		return 0.2
	default:
		return 0.0
	}
}

// ScanWithProvenance performs injection scanning with elevated sensitivity for
// untrusted content sources. This implements the data-instruction boundary:
//
//   - ProvenanceSystem: not scanned (trusted developer content)
//   - ProvenanceDeveloper: standard scan thresholds
//   - ProvenanceUser: standard scan thresholds
//   - ProvenanceTool: lowered blocking threshold (medium → block)
//   - ProvenanceRetrieved: lowered blocking threshold (medium → block)
//   - ProvenanceUnknown: standard scan thresholds (fail-open for backward compat)
//
// The provenance level is recorded in the Result for audit logging.
func ScanWithProvenance(body string, role string, provenance string) Result {
	result := Scan(body, role)
	result.Provenance = provenance

	// For untrusted content sources, lower the blocking threshold.
	// Standard Scan() blocks on High severity. For retrieved/tool content,
	// we also block on Medium severity — a medium-confidence injection pattern
	// in a retrieved document is more concerning than the same pattern in a
	// developer-authored user prompt.
	if provenance == ProvenanceRetrieved || provenance == ProvenanceTool {
		if result.Score >= severityToScore(SeverityMedium) && !result.Block {
			result.Block = true
		}
	}

	return result
}

// ParseProvenance normalizes the X-Cicada-Content-Provenance header value
// into one of the defined trust levels. Returns ProvenanceUnknown for
// unrecognised values (fail-open for backward compatibility).
func ParseProvenance(header string) string {
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "system":
		return ProvenanceSystem
	case "developer":
		return ProvenanceDeveloper
	case "user":
		return ProvenanceUser
	case "tool", "tool_result":
		return ProvenanceTool
	case "retrieved", "external", "rag":
		return ProvenanceRetrieved
	default:
		return ProvenanceUnknown
	}
}

// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package llmproxy implements the LLM API proxy mode — the component that closes
// the memory isolation and audit trail gaps that cannot be addressed at the
// application API proxy layer.
//
// The key architectural insight: if Cicada intercepts calls from the agent to its
// LLM provider (OpenAI POST /v1/chat/completions, Anthropic POST /v1/messages),
// the messages[] array in that request IS the agent's context window. Inspecting
// it enables two capabilities:
//
//   - Memory isolation: compute a per-agent context fingerprint and cross-reference
//     against other agents in the same tenant. If content from agent A's context
//     appears in agent B's messages, cross-contamination is declared — the case where
//     information (PII, internal data, secrets) has leaked between agent sessions.
//
//   - Audit trails of reasoning: extract chain-of-thought tokens from the response
//     before returning them to the agent (Claude <thinking> blocks, OpenAI
//     reasoning_content) and write them to the evidence chain. When an agent takes a
//     harmful action, a reviewer can retrieve the exact reasoning steps that led to it.
//
// Deployment model:
//   The agent changes its LLM base URL from api.openai.com to the Sentry Gateway's
//   /v1/llm/proxy endpoint, passes its EVAR/session in Authorization, passes its real
//   LLM API key in X-Cicada-LLM-Key, and sets X-Cicada-Target-URL to the real
//   provider endpoint. The Gateway inspects, forwards, inspects the response, writes
//   to the ledger, and returns the real provider response unchanged. The agent sees
//   no difference except the inspection latency.
package llmproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/asai/cicada/sentry/internal/queue"
)

// Provider identifies which LLM provider the request targets.
type Provider int

const (
	ProviderUnknown   Provider = iota
	ProviderOpenAI             // api.openai.com — POST /v1/chat/completions
	ProviderAnthropic          // api.anthropic.com — POST /v1/messages
)

// Message is a single entry in an LLM conversation context window.
// Both OpenAI and Anthropic use this role+content structure.
type Message struct {
	Role    string
	Content string // always a plain string; multi-modal blocks are flattened
}

// ─── Request schema stubs ─────────────────────────────────────────────────────
// These are minimal — we only extract the fields needed for inspection.

type openAIRequest struct {
	Messages []struct {
		Role    string      `json:"role"`
		Content interface{} `json:"content"` // string or []block for multi-modal
	} `json:"messages"`
}

type anthropicRequest struct {
	System   string `json:"system"` // top-level system prompt (not in messages[])
	Messages []struct {
		Role    string      `json:"role"`
		Content interface{} `json:"content"`
	} `json:"messages"`
}

// ─── Response schema stubs ────────────────────────────────────────────────────

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"` // o1/o3 extended thinking
		} `json:"message"`
	} `json:"choices"`
}

type anthropicResponse struct {
	Content []struct {
		Type     string `json:"type"`     // "text" or "thinking"
		Text     string `json:"text"`     // present when type="text"
		Thinking string `json:"thinking"` // present when type="thinking" (extended thinking feature)
	} `json:"content"`
}

// DetectProvider identifies the LLM provider from the target URL.
// Matching is substring-based and case-insensitive — robust to variations
// in path (e.g., /v1/chat/completions vs /v1beta/messages).
func DetectProvider(targetURL string) Provider {
	lower := strings.ToLower(targetURL)
	if strings.Contains(lower, "openai.com") || strings.Contains(lower, "/openai/") ||
		strings.Contains(lower, "/chat/completions") {
		return ProviderOpenAI
	}
	if strings.Contains(lower, "anthropic.com") || strings.Contains(lower, "/anthropic/") {
		return ProviderAnthropic
	}
	return ProviderUnknown
}

// ProviderName returns a human-readable string for log lines and ledger records.
func ProviderName(p Provider) string {
	switch p {
	case ProviderOpenAI:
		return "openai"
	case ProviderAnthropic:
		return "anthropic"
	default:
		return "unknown"
	}
}

// ExtractMessages parses the request body and returns the ordered message list.
// For Anthropic requests the top-level system field is prepended as a system-role
// message so the fingerprint captures the full effective context window.
func ExtractMessages(body []byte, p Provider) ([]Message, error) {
	switch p {
	case ProviderOpenAI:
		var req openAIRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("parse OpenAI request: %w", err)
		}
		msgs := make([]Message, 0, len(req.Messages))
		for _, m := range req.Messages {
			msgs = append(msgs, Message{Role: m.Role, Content: contentToString(m.Content)})
		}
		return msgs, nil

	case ProviderAnthropic:
		var req anthropicRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fmt.Errorf("parse Anthropic request: %w", err)
		}
		msgs := make([]Message, 0, len(req.Messages)+1)
		if req.System != "" {
			msgs = append(msgs, Message{Role: "system", Content: req.System})
		}
		for _, m := range req.Messages {
			msgs = append(msgs, Message{Role: m.Role, Content: contentToString(m.Content)})
		}
		return msgs, nil

	default:
		return nil, fmt.Errorf("provider %q does not have a known message schema", ProviderName(p))
	}
}

// contentToString flattens the content field (string or multi-modal block array)
// into a plain string. Non-text blocks (images, tool_use) are summarised as a
// placeholder so they contribute to the fingerprint without storing raw bytes.
func contentToString(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		var parts []string
		for _, block := range c {
			if m, ok := block.(map[string]interface{}); ok {
				switch {
				case m["type"] == "text":
					if t, ok := m["text"].(string); ok {
						parts = append(parts, t)
					}
				case m["type"] == "image_url":
					parts = append(parts, "[image]")
				case m["type"] == "tool_use":
					if name, ok := m["name"].(string); ok {
						parts = append(parts, "[tool:"+name+"]")
					}
				case m["type"] == "tool_result":
					parts = append(parts, "[tool_result]")
				}
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// ComputeFingerprint produces a deterministic fingerprint for the context window.
//
// Algorithm:
//  1. Hash each message individually: SHA-256(role + "|" + content)
//  2. Sort the individual hashes (order-independent — two agents with the same
//     messages in different order should share a fingerprint)
//  3. Hash the sorted list: SHA-256(joined sorted hashes)
//
// The individual hashes are also returned for per-message contamination detection.
// The fingerprint identifies the SET of context content; the individual hashes
// identify which specific content blocks crossed agent boundaries.
func ComputeFingerprint(messages []Message) (fingerprint string, hashes []string) {
	hashes = make([]string, 0, len(messages))
	for _, m := range messages {
		h := sha256.Sum256([]byte(m.Role + "|" + m.Content))
		hashes = append(hashes, hex.EncodeToString(h[:]))
	}
	sorted := make([]string, len(hashes))
	copy(sorted, hashes)
	sort.Strings(sorted)
	combined := sha256.Sum256([]byte(strings.Join(sorted, ",")))
	return hex.EncodeToString(combined[:]), hashes
}

// CheckContamination detects whether any content from this agent's context window
// was previously observed in a different agent's context within the same tenant.
//
// Storage: Redis HASH key cicada:ctx:{tenantID}
//   field = messageHash (individual SHA-256 content hash)
//   value = agentID that first contributed this content
//
// The function checks each incoming hash against the tenant-wide map. If a hash
// is already registered to a DIFFERENT agent, that specific content block has
// crossed agent boundaries — contamination detected.
//
// After checking, all hashes are registered/updated to the calling agent. This
// means the first agent to submit content "owns" it; subsequent agents that
// receive the same content are flagged.
//
// The Redis key carries a 24-hour TTL, refreshed on each call. This prevents
// unbounded growth and aligns with typical agent session lifespans.
//
// Fail-open: Redis unavailability returns (false, "", nil). A Redis outage should
// never block legitimate LLM calls; contamination detection is observational.
func CheckContamination(ctx context.Context, tenantID, agentID string, hashes []string) (contaminated bool, originAgentID string, err error) {
	if queue.Client == nil {
		return false, "", nil
	}

	redisKey := fmt.Sprintf("cicada:ctx:%s", tenantID)

	for _, h := range hashes {
		existing, getErr := queue.Client.HGet(ctx, redisKey, h).Result()
		if getErr != nil {
			// redis.Nil (not found) or connection error — treat as clean
			continue
		}
		if existing != agentID {
			// This content hash was originally registered by a different agent
			log.Printf("[MEMISO] Hash %s...%s from agent %s was previously seen in agent %s context",
				h[:8], h[len(h)-4:], agentID, existing)
			return true, existing, nil
		}
	}

	// Register all hashes for this agent — pipeline for efficiency
	pipe := queue.Client.Pipeline()
	for _, h := range hashes {
		pipe.HSet(ctx, redisKey, h, agentID)
	}
	pipe.Expire(ctx, redisKey, 24*time.Hour)
	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		log.Printf("[MEMISO] Redis pipeline error registering hashes for tenant %s: %v", tenantID, pipeErr)
	}

	return false, "", nil
}

// ExtractReasoningTrace extracts chain-of-thought tokens from an LLM response body.
//
// OpenAI o1/o3: the response includes a reasoning_content field in the message
// object — this is the model's internal scratchpad before it produces its answer.
//
// Anthropic extended thinking: the response content array includes blocks with
// type="thinking" containing the model's reasoning before the final text block.
//
// Standard responses without reasoning tokens return an empty string — this is
// the common case and adds zero overhead to non-thinking models.
func ExtractReasoningTrace(body []byte, p Provider) string {
	switch p {
	case ProviderOpenAI:
		var resp openAIResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return ""
		}
		if len(resp.Choices) > 0 {
			return resp.Choices[0].Message.ReasoningContent
		}
		return ""

	case ProviderAnthropic:
		var resp anthropicResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return ""
		}
		var thinking []string
		for _, block := range resp.Content {
			if block.Type == "thinking" && block.Thinking != "" {
				thinking = append(thinking, block.Thinking)
			}
		}
		return strings.Join(thinking, "\n---\n")

	default:
		return ""
	}
}

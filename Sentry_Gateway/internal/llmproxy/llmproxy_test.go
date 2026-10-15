// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package llmproxy

import (
	"encoding/json"
	"testing"
)

func TestDetectProvider(t *testing.T) {
	cases := []struct {
		url  string
		want Provider
	}{
		{"https://api.openai.com/v1/chat/completions", ProviderOpenAI},
		{"https://api.anthropic.com/v1/messages", ProviderAnthropic},
		{"https://api.openai.com/v1/embeddings", ProviderOpenAI},
		{"http://internal-proxy.corp/openai/v1/chat/completions", ProviderOpenAI},
		{"https://api.anthropic.com/v1/messages?stream=true", ProviderAnthropic},
		{"https://api.cohere.com/v1/chat", ProviderUnknown},
		{"https://generativelanguage.googleapis.com/v1/models", ProviderUnknown},
	}
	for _, tc := range cases {
		got := DetectProvider(tc.url)
		if got != tc.want {
			t.Errorf("DetectProvider(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestExtractMessages_OpenAI(t *testing.T) {
	body := []byte(`{
		"model": "gpt-4o",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "What is the capital of France?"},
			{"role": "assistant", "content": "The capital of France is Paris."},
			{"role": "user", "content": "Thank you."}
		]
	}`)

	msgs, err := ExtractMessages(body, ProviderOpenAI)
	if err != nil {
		t.Fatalf("ExtractMessages error: %v", err)
	}
	if len(msgs) != 4 {
		t.Fatalf("Expected 4 messages, got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "You are a helpful assistant." {
		t.Errorf("First message mismatch: %+v", msgs[0])
	}
	if msgs[1].Role != "user" || msgs[1].Content != "What is the capital of France?" {
		t.Errorf("Second message mismatch: %+v", msgs[1])
	}
}

func TestExtractMessages_Anthropic(t *testing.T) {
	body := []byte(`{
		"model": "claude-3-5-sonnet-20241022",
		"system": "You are a helpful assistant.",
		"messages": [
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "Hi there!"}
		]
	}`)

	msgs, err := ExtractMessages(body, ProviderAnthropic)
	if err != nil {
		t.Fatalf("ExtractMessages error: %v", err)
	}
	// Anthropic system prompt should be prepended as a system message
	if len(msgs) != 3 {
		t.Fatalf("Expected 3 messages (system prepended), got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "You are a helpful assistant." {
		t.Errorf("System message not prepended correctly: %+v", msgs[0])
	}
}

func TestExtractMessages_UnknownProvider(t *testing.T) {
	_, err := ExtractMessages([]byte(`{}`), ProviderUnknown)
	if err == nil {
		t.Error("Expected error for unknown provider, got nil")
	}
}

func TestComputeFingerprint_Deterministic(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "Hello world"},
		{Role: "assistant", Content: "Hi there"},
	}

	fp1, hashes1 := ComputeFingerprint(msgs)
	fp2, hashes2 := ComputeFingerprint(msgs)

	if fp1 != fp2 {
		t.Errorf("Fingerprint not deterministic: %s != %s", fp1, fp2)
	}
	if len(hashes1) != len(hashes2) {
		t.Errorf("Hash count mismatch: %d != %d", len(hashes1), len(hashes2))
	}
}

func TestComputeFingerprint_OrderIndependent(t *testing.T) {
	msgs1 := []Message{
		{Role: "user", Content: "First message"},
		{Role: "assistant", Content: "Second message"},
	}
	msgs2 := []Message{
		{Role: "assistant", Content: "Second message"},
		{Role: "user", Content: "First message"},
	}

	fp1, _ := ComputeFingerprint(msgs1)
	fp2, _ := ComputeFingerprint(msgs2)

	// Order-independent: same content in different order should produce same fingerprint
	if fp1 != fp2 {
		t.Errorf("Fingerprint should be order-independent: %s != %s", fp1, fp2)
	}
}

func TestComputeFingerprint_ContentSensitive(t *testing.T) {
	msgs1 := []Message{{Role: "user", Content: "Hello"}}
	msgs2 := []Message{{Role: "user", Content: "Goodbye"}}

	fp1, _ := ComputeFingerprint(msgs1)
	fp2, _ := ComputeFingerprint(msgs2)

	if fp1 == fp2 {
		t.Error("Different content must produce different fingerprints")
	}
}

func TestExtractReasoningTrace_OpenAI(t *testing.T) {
	body := []byte(`{
		"choices": [{
			"message": {
				"role": "assistant",
				"content": "The answer is 42.",
				"reasoning_content": "Let me think step by step. First I'll consider..."
			},
			"finish_reason": "stop"
		}]
	}`)

	trace := ExtractReasoningTrace(body, ProviderOpenAI)
	if trace == "" {
		t.Error("Expected reasoning trace, got empty string")
	}
	if trace != "Let me think step by step. First I'll consider..." {
		t.Errorf("Unexpected reasoning trace: %q", trace)
	}
}

func TestExtractReasoningTrace_Anthropic(t *testing.T) {
	body := []byte(`{
		"id": "msg_abc",
		"type": "message",
		"role": "assistant",
		"content": [
			{"type": "thinking", "thinking": "I need to reason about this carefully..."},
			{"type": "text", "text": "Here is my answer."}
		]
	}`)

	trace := ExtractReasoningTrace(body, ProviderAnthropic)
	if trace == "" {
		t.Error("Expected reasoning trace from thinking block, got empty string")
	}
	if trace != "I need to reason about this carefully..." {
		t.Errorf("Unexpected reasoning trace: %q", trace)
	}
}

func TestExtractReasoningTrace_NoThinking(t *testing.T) {
	// Standard response without extended thinking — must return empty string
	body := []byte(`{
		"choices": [{"message": {"role": "assistant", "content": "Hello!"}, "finish_reason": "stop"}]
	}`)
	trace := ExtractReasoningTrace(body, ProviderOpenAI)
	if trace != "" {
		t.Errorf("Expected empty trace for standard response, got: %q", trace)
	}
}

func TestExtractReasoningTrace_UnknownProvider(t *testing.T) {
	trace := ExtractReasoningTrace([]byte(`{}`), ProviderUnknown)
	if trace != "" {
		t.Errorf("Unknown provider must return empty trace, got: %q", trace)
	}
}

func TestContentToString_MultiModal(t *testing.T) {
	// Simulate OpenAI multi-modal content array
	content := []interface{}{
		map[string]interface{}{"type": "text", "text": "Look at this image"},
		map[string]interface{}{"type": "image_url", "image_url": map[string]interface{}{"url": "data:image/png;base64,abc"}},
	}
	result := contentToString(content)
	if result != "Look at this image [image]" {
		t.Errorf("Multi-modal content not flattened correctly: %q", result)
	}
}

func TestProviderName(t *testing.T) {
	if ProviderName(ProviderOpenAI) != "openai" {
		t.Error("Expected openai")
	}
	if ProviderName(ProviderAnthropic) != "anthropic" {
		t.Error("Expected anthropic")
	}
	if ProviderName(ProviderUnknown) != "unknown" {
		t.Error("Expected unknown")
	}
}

// TestFingerprintContaminationScenario simulates the cross-agent contamination
// scenario: agent A processes a message, agent B later has the same content,
// the hash should appear in agent A's fingerprint AND agent B's fingerprint.
func TestFingerprintContaminationScenario(t *testing.T) {
	sharedContent := "Customer PII: John Smith, SSN 123-45-6789, credit card 4111111111111111"

	agentAMsgs := []Message{
		{Role: "system", Content: "Process customer refunds."},
		{Role: "user", Content: sharedContent},
	}
	agentBMsgs := []Message{
		{Role: "system", Content: "Handle customer complaints."},
		{Role: "user", Content: sharedContent}, // same PII leaked into different agent
	}

	_, hashesA := ComputeFingerprint(agentAMsgs)
	_, hashesB := ComputeFingerprint(agentBMsgs)

	// Find the hash of the shared content in both sets
	sharedMsg := Message{Role: "user", Content: sharedContent}
	_, sharedHashes := ComputeFingerprint([]Message{sharedMsg})
	sharedHash := sharedHashes[0]

	inA, inB := false, false
	for _, h := range hashesA {
		if h == sharedHash {
			inA = true
		}
	}
	for _, h := range hashesB {
		if h == sharedHash {
			inB = true
		}
	}

	if !inA || !inB {
		t.Errorf("Shared content hash should appear in both agents' hash sets. inA=%v inB=%v", inA, inB)
	}
}

// Ensure the JSON marshalling of message extraction handles raw JSON correctly.
func TestExtractMessages_MalformedJSON(t *testing.T) {
	_, err := ExtractMessages([]byte(`{not valid json`), ProviderOpenAI)
	if err == nil {
		t.Error("Expected error for malformed JSON")
	}
}

// Benchmark fingerprint computation to verify sub-millisecond performance.
func BenchmarkComputeFingerprint(b *testing.B) {
	msgs := make([]Message, 20)
	for i := range msgs {
		msgs[i] = Message{Role: "user", Content: "This is message content number " + string(rune('0'+i))}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeFingerprint(msgs)
	}
}

// helper to keep test file self-contained
var _ = json.Marshal

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConvertRequest(t *testing.T) {
	t.Run("system messages extracted and concatenated", func(t *testing.T) {
		req := openAIRequest{
			Model: "gpt-4o",
			Messages: []openAIMessage{
				{Role: "system", Content: json.RawMessage(`"You are helpful"`)},
				{Role: "system", Content: json.RawMessage(`"Be concise"`)},
				{Role: "user", Content: json.RawMessage(`"Hello"`)},
			},
		}

		ar := convertRequest(req, nil)

		if ar.System != "You are helpful\nBe concise" {
			t.Fatalf("unexpected system: %q", ar.System)
		}
		if len(ar.Messages) != 1 {
			t.Fatalf("expected 1 message, got %d", len(ar.Messages))
		}
		if ar.Messages[0].Role != "user" {
			t.Fatalf("expected user role, got %q", ar.Messages[0].Role)
		}
	})

	t.Run("temperature capped at 1.0", func(t *testing.T) {
		temp := 1.5
		req := openAIRequest{
			Model:       "gpt-4o",
			Messages:    []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Temperature: &temp,
		}

		ar := convertRequest(req, nil)

		if ar.Temperature == nil || *ar.Temperature != 1.0 {
			t.Fatalf("temperature should be capped at 1.0, got %v", ar.Temperature)
		}
	})

	t.Run("temperature passed through when valid", func(t *testing.T) {
		temp := 0.5
		req := openAIRequest{
			Model:       "gpt-4o",
			Messages:    []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Temperature: &temp,
		}

		ar := convertRequest(req, nil)

		if ar.Temperature == nil || *ar.Temperature != 0.5 {
			t.Fatalf("temperature should be 0.5, got %v", ar.Temperature)
		}
	})

	t.Run("max_tokens defaults to 4096", func(t *testing.T) {
		req := openAIRequest{
			Model:    "gpt-4o",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		}

		ar := convertRequest(req, nil)

		if ar.MaxTokens != 4096 {
			t.Fatalf("expected default max_tokens 4096, got %d", ar.MaxTokens)
		}
	})

	t.Run("max_tokens set explicitly", func(t *testing.T) {
		mt := 1000
		req := openAIRequest{
			Model:     "gpt-4o",
			Messages:  []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			MaxTokens: &mt,
		}

		ar := convertRequest(req, nil)

		if ar.MaxTokens != 1000 {
			t.Fatalf("expected max_tokens 1000, got %d", ar.MaxTokens)
		}
	})

	t.Run("stop string converted to array", func(t *testing.T) {
		req := openAIRequest{
			Model:    "gpt-4o",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Stop:     json.RawMessage(`"END"`),
		}

		ar := convertRequest(req, nil)

		if len(ar.StopSequences) != 1 || ar.StopSequences[0] != "END" {
			t.Fatalf("unexpected stop_sequences: %v", ar.StopSequences)
		}
	})

	t.Run("stop array passed through", func(t *testing.T) {
		req := openAIRequest{
			Model:    "gpt-4o",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Stop:     json.RawMessage(`["END","STOP"]`),
		}

		ar := convertRequest(req, nil)

		if len(ar.StopSequences) != 2 {
			t.Fatalf("expected 2 stop sequences, got %d", len(ar.StopSequences))
		}
	})

	t.Run("model mapped via model map", func(t *testing.T) {
		modelMap := map[string]string{"gpt-4o": "claude-sonnet-4-20250514"}
		req := openAIRequest{
			Model:    "gpt-4o",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		}

		ar := convertRequest(req, modelMap)

		if ar.Model != "claude-sonnet-4-20250514" {
			t.Fatalf("expected mapped model, got %q", ar.Model)
		}
	})

	t.Run("model passed through when no mapping", func(t *testing.T) {
		req := openAIRequest{
			Model:    "claude-sonnet-4-20250514",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
		}

		ar := convertRequest(req, nil)

		if ar.Model != "claude-sonnet-4-20250514" {
			t.Fatalf("model should pass through, got %q", ar.Model)
		}
	})

	t.Run("tools converted", func(t *testing.T) {
		req := openAIRequest{
			Model:    "gpt-4o",
			Messages: []openAIMessage{{Role: "user", Content: json.RawMessage(`"Hi"`)}},
			Tools: []openAITool{{
				Type: "function",
				Function: openAIFunction{
					Name:        "get_weather",
					Description: "Get weather",
					Parameters:  json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"}}}`),
				},
			}},
		}

		ar := convertRequest(req, nil)

		if len(ar.Tools) != 1 {
			t.Fatalf("expected 1 tool, got %d", len(ar.Tools))
		}
		if ar.Tools[0].Name != "get_weather" {
			t.Fatalf("unexpected tool name: %q", ar.Tools[0].Name)
		}
		if string(ar.Tools[0].InputSchema) != `{"type":"object","properties":{"city":{"type":"string"}}}` {
			t.Fatalf("unexpected input_schema: %s", ar.Tools[0].InputSchema)
		}
	})
}

func TestConvertResponse(t *testing.T) {
	t.Run("text response", func(t *testing.T) {
		antResp := anthropicResponse{
			ID:   "msg-123",
			Type: "message",
			Role: "assistant",
			Content: []contentBlock{
				{Type: "text", Text: "Hello there!"},
			},
			Model:      "claude-sonnet-4-20250514",
			StopReason: "end_turn",
			Usage:      anthropicUsage{InputTokens: 10, OutputTokens: 5},
		}

		oaiResp := convertResponse(antResp)

		if oaiResp.ID != "chatcmpl-msg-123" {
			t.Fatalf("unexpected ID: %q", oaiResp.ID)
		}
		if oaiResp.Object != "chat.completion" {
			t.Fatalf("unexpected object: %q", oaiResp.Object)
		}
		if len(oaiResp.Choices) != 1 {
			t.Fatalf("expected 1 choice, got %d", len(oaiResp.Choices))
		}
		if oaiResp.Choices[0].FinishReason != "stop" {
			t.Fatalf("unexpected finish_reason: %q", oaiResp.Choices[0].FinishReason)
		}

		var content string
		json.Unmarshal(oaiResp.Choices[0].Message.Content, &content)
		if content != "Hello there!" {
			t.Fatalf("unexpected content: %q", content)
		}
		if oaiResp.Usage.PromptTokens != 10 || oaiResp.Usage.CompletionTokens != 5 || oaiResp.Usage.TotalTokens != 15 {
			t.Fatalf("unexpected usage: %+v", oaiResp.Usage)
		}
	})

	t.Run("tool use response", func(t *testing.T) {
		antResp := anthropicResponse{
			ID:   "msg-456",
			Type: "message",
			Role: "assistant",
			Content: []contentBlock{
				{Type: "text", Text: "Let me check the weather."},
				{Type: "tool_use", ID: "toolu_1", Name: "get_weather", Input: json.RawMessage(`{"city":"London"}`)},
			},
			Model:      "claude-sonnet-4-20250514",
			StopReason: "tool_use",
			Usage:      anthropicUsage{InputTokens: 20, OutputTokens: 30},
		}

		oaiResp := convertResponse(antResp)

		if oaiResp.Choices[0].FinishReason != "tool_calls" {
			t.Fatalf("unexpected finish_reason: %q", oaiResp.Choices[0].FinishReason)
		}
		if len(oaiResp.Choices[0].Message.ToolCalls) != 1 {
			t.Fatalf("expected 1 tool call, got %d", len(oaiResp.Choices[0].Message.ToolCalls))
		}
		tc := oaiResp.Choices[0].Message.ToolCalls[0]
		if tc.ID != "toolu_1" || tc.Function.Name != "get_weather" {
			t.Fatalf("unexpected tool call: %+v", tc)
		}
		// Verify arguments are not double-encoded
		if tc.Function.Arguments != `{"city":"London"}` {
			t.Fatalf("arguments double-encoded or wrong: %q", tc.Function.Arguments)
		}
	})
}

func TestConvertRequest_ToolResult(t *testing.T) {
	t.Run("tool_use_id field name", func(t *testing.T) {
		req := openAIRequest{
			Model: "gpt-4o",
			Messages: []openAIMessage{
				{Role: "user", Content: json.RawMessage(`"What is the weather?"`)},
				{Role: "assistant", Content: json.RawMessage(`""`), ToolCalls: []openAIToolCall{{
					ID: "call_123", Type: "function",
					Function: openAIFnCall{Name: "get_weather", Arguments: `{"city":"London"}`},
				}}},
				{Role: "tool", ToolCallID: "call_123", Content: json.RawMessage(`"15 degrees"`)},
			},
		}

		ar := convertRequest(req, nil)

		// The tool result message should be a user message with tool_result content
		if len(ar.Messages) != 3 {
			t.Fatalf("expected 3 messages, got %d", len(ar.Messages))
		}
		toolResultMsg := ar.Messages[2]
		if toolResultMsg.Role != "user" {
			t.Fatalf("tool result should be user role, got %q", toolResultMsg.Role)
		}
		// Verify it contains tool_use_id not id
		raw := string(toolResultMsg.Content)
		if !strings.Contains(raw, `"tool_use_id"`) {
			t.Fatalf("expected tool_use_id field, got: %s", raw)
		}
		if !strings.Contains(raw, `"call_123"`) {
			t.Fatalf("expected call_123 in tool result, got: %s", raw)
		}
	})
}

func TestMapStopReason(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"end_turn", "stop"},
		{"max_tokens", "length"},
		{"tool_use", "tool_calls"},
		{"stop_sequence", "stop"},
		{"unknown", "stop"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapStopReason(tt.input)
			if got != tt.want {
				t.Errorf("mapStopReason(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContentToString(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		raw := json.RawMessage(`"hello"`)
		if s := contentToString(raw); s != "hello" {
			t.Fatalf("expected 'hello', got %q", s)
		}
	})

	t.Run("array", func(t *testing.T) {
		raw := json.RawMessage(`[{"type":"text","text":"hello"},{"type":"text","text":"world"}]`)
		if s := contentToString(raw); s != "hello\nworld" {
			t.Fatalf("expected 'hello\\nworld', got %q", s)
		}
	})
}

func TestParseStop(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		raw := json.RawMessage(`"STOP"`)
		s := parseStop(raw)
		if len(s) != 1 || s[0] != "STOP" {
			t.Fatalf("unexpected: %v", s)
		}
	})

	t.Run("array", func(t *testing.T) {
		raw := json.RawMessage(`["A","B"]`)
		s := parseStop(raw)
		if len(s) != 2 || s[0] != "A" || s[1] != "B" {
			t.Fatalf("unexpected: %v", s)
		}
	})
}

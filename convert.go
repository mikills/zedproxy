package main

import (
	"encoding/json"
	"fmt"
	"time"
)

type openAIRequest struct {
	Model            string          `json:"model"`
	Messages         []openAIMessage `json:"messages"`
	Temperature      *float64        `json:"temperature,omitempty"`
	MaxTokens        *int            `json:"max_tokens,omitempty"`
	TopP             *float64        `json:"top_p,omitempty"`
	Stream           bool            `json:"stream,omitempty"`
	Stop             json.RawMessage `json:"stop,omitempty"`
	Tools            []openAITool    `json:"tools,omitempty"`
	ToolChoice       json.RawMessage `json:"tool_choice,omitempty"`
	FrequencyPenalty *float64        `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64        `json:"presence_penalty,omitempty"`
	N                *int            `json:"n,omitempty"`
	Seed             *int            `json:"seed,omitempty"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type openAIToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function openAIFnCall `json:"function"`
}

type openAIFnCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type openAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type openAIChoice struct {
	Index        int           `json:"index"`
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIStreamChunk struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Created int64                `json:"created"`
	Model   string               `json:"model"`
	Choices []openAIStreamChoice `json:"choices"`
	Usage   *openAIUsage         `json:"usage,omitempty"`
}

type openAIStreamChoice struct {
	Index        int               `json:"index"`
	Delta        openAIStreamDelta `json:"delta"`
	FinishReason *string           `json:"finish_reason"`
}

type openAIStreamDelta struct {
	Role      string                `json:"role,omitempty"`
	Content   *string               `json:"content,omitempty"`
	ToolCalls []openAIToolCallChunk `json:"tool_calls,omitempty"`
}

type openAIToolCallChunk struct {
	Index    int            `json:"index"`
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type,omitempty"`
	Function *openAIFnChunk `json:"function,omitempty"`
}

type openAIFnChunk struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type anthropicRequest struct {
	Model         string             `json:"model"`
	System        string             `json:"system,omitempty"`
	Messages      []anthropicMessage `json:"messages"`
	MaxTokens     int                `json:"max_tokens"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Tools         []anthropicTool    `json:"tools,omitempty"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

type contentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

type toolResultBlock struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type anthropicResponse struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Role       string         `json:"role"`
	Content    []contentBlock `json:"content"`
	Model      string         `json:"model"`
	StopReason string         `json:"stop_reason"`
	Usage      anthropicUsage `json:"usage"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

func convertRequest(req openAIRequest, modelMap map[string]string) anthropicRequest {
	ar := anthropicRequest{
		Model:  req.Model,
		Stream: req.Stream,
	}

	// Apply model mapping
	if mapped, ok := modelMap[req.Model]; ok {
		ar.Model = mapped
	}

	// Extract system messages and build Anthropic messages
	var systemParts []string
	var msgs []anthropicMessage
	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			systemParts = append(systemParts, contentToString(m.Content))
		case "tool":
			// Convert OpenAI tool result to Anthropic tool_result content block
			toolResult := []toolResultBlock{{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   contentToString(m.Content),
			}}
			raw, _ := json.Marshal(toolResult)
			msgs = append(msgs, anthropicMessage{Role: "user", Content: raw})
		case "assistant":
			if len(m.ToolCalls) > 0 {
				// Convert assistant message with tool calls to Anthropic content blocks
				var blocks []contentBlock
				text := contentToString(m.Content)
				if text != "" {
					blocks = append(blocks, contentBlock{Type: "text", Text: text})
				}
				for _, tc := range m.ToolCalls {
					blocks = append(blocks, contentBlock{
						Type:  "tool_use",
						ID:    tc.ID,
						Name:  tc.Function.Name,
						Input: json.RawMessage(tc.Function.Arguments),
					})
				}
				raw, _ := json.Marshal(blocks)
				msgs = append(msgs, anthropicMessage{Role: "assistant", Content: raw})
			} else {
				msgs = append(msgs, anthropicMessage{Role: m.Role, Content: m.Content})
			}
		default:
			msgs = append(msgs, anthropicMessage{Role: m.Role, Content: m.Content})
		}
	}

	if len(systemParts) > 0 {
		system := ""
		for i, p := range systemParts {
			if i > 0 {
				system += "\n"
			}
			system += p
		}
		ar.System = system
	}
	ar.Messages = msgs

	// max_tokens (required for Anthropic, default 4096)
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		ar.MaxTokens = *req.MaxTokens
	} else {
		ar.MaxTokens = 4096
	}

	// temperature: cap at 1.0
	if req.Temperature != nil {
		t := *req.Temperature
		if t > 1.0 {
			t = 1.0
		}
		ar.Temperature = &t
	}

	if req.TopP != nil {
		ar.TopP = req.TopP
	}

	// stop → stop_sequences
	if req.Stop != nil {
		ar.StopSequences = parseStop(req.Stop)
	}

	// tools conversion
	for _, t := range req.Tools {
		ar.Tools = append(ar.Tools, anthropicTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}

	return ar
}

func convertResponse(resp anthropicResponse) openAIResponse {
	msg := openAIMessage{Role: "assistant"}

	var textParts []string
	var toolCalls []openAIToolCall

	for _, block := range resp.Content {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "tool_use":
			// block.Input is already raw JSON from the Anthropic response
			toolCalls = append(toolCalls, openAIToolCall{
				ID:   block.ID,
				Type: "function",
				Function: openAIFnCall{
					Name:      block.Name,
					Arguments: string(block.Input),
				},
			})
		}
	}

	content := ""
	for i, p := range textParts {
		if i > 0 {
			content += "\n"
		}
		content += p
	}
	msg.Content, _ = json.Marshal(content)

	if len(toolCalls) > 0 {
		msg.ToolCalls = toolCalls
	}

	return openAIResponse{
		ID:      fmt.Sprintf("chatcmpl-%s", resp.ID),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   resp.Model,
		Choices: []openAIChoice{{
			Index:        0,
			Message:      msg,
			FinishReason: mapStopReason(resp.StopReason),
		}},
		Usage: openAIUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		},
	}
}

func mapStopReason(reason string) string {
	switch reason {
	case "end_turn":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "stop_sequence":
		return "stop"
	default:
		return "stop"
	}
}

func contentToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try array of content parts (multimodal)
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		result := ""
		for _, p := range parts {
			if p.Type == "text" {
				if result != "" {
					result += "\n"
				}
				result += p.Text
			}
		}
		return result
	}
	return string(raw)
}

func parseStop(raw json.RawMessage) []string {
	// Try single string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "" {
			return []string{s}
		}
		return nil
	}
	// Try array
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	return nil
}

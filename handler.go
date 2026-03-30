package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type convertOpts struct {
	modelMap   map[string]string
	omitFields []string
	addFields  map[string]string
}

func newConvertHandler(backendURL string, provider *tokenProvider, opts convertOpts, fallback http.Handler) http.Handler {
	backendURL = strings.TrimRight(backendURL, "/")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			fallback.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}

		var oaiReq openAIRequest
		if err := json.Unmarshal(body, &oaiReq); err != nil {
			slog.Error("invalid request body", "error", err)
			http.Error(w, "invalid JSON request", http.StatusBadRequest)
			return
		}

		antReq := convertRequest(oaiReq, opts.modelMap)

		slog.Info("request",
			"model", oaiReq.Model,
			"mapped_model", antReq.Model,
			"stream", antReq.Stream,
			"messages", len(oaiReq.Messages),
			"max_tokens", antReq.MaxTokens,
		)

		antBody, err := json.Marshal(antReq)
		if err != nil {
			http.Error(w, "failed to marshal request", http.StatusInternalServerError)
			return
		}

		antBody, err = applyFieldOverrides(antBody, opts.omitFields, opts.addFields)
		if err != nil {
			slog.Error("failed to apply field overrides", "error", err)
			http.Error(w, "failed to process request", http.StatusInternalServerError)
			return
		}

		if antReq.Stream {
			handleStream(w, r, backendURL, provider, antBody, start)
		} else {
			handleNonStream(w, r, backendURL, provider, antBody, start)
		}
	})
}

func doAnthropicRequest(r *http.Request, backendURL string, provider *tokenProvider, body []byte) (*http.Response, error) {
	endpoint := backendURL

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	token, err := provider.ensureToken(r.Context())
	if err != nil {
		return nil, fmt.Errorf("token error: %w", err)
	}
	req.Header.Set("x-api-key", token)
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Retry once on 401
	if resp.StatusCode == http.StatusUnauthorized && provider.refresh != nil {
		resp.Body.Close()
		slog.Warn("received 401, refreshing token")
		newToken, err := provider.forceRefresh(r.Context())
		if err != nil {
			return nil, fmt.Errorf("token refresh error: %w", err)
		}
		req, err = http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("x-api-key", newToken)
		req.Header.Set("Authorization", "Bearer "+newToken)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func handleNonStream(w http.ResponseWriter, r *http.Request, backendURL string, provider *tokenProvider, antBody []byte, start time.Time) {
	resp, err := doAnthropicRequest(r, backendURL, provider, antBody)
	if err != nil {
		slog.Error("backend request failed", "error", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read backend response", "error", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusOK {
		slog.Error("backend error", "status", resp.StatusCode, "body", string(respBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	var antResp anthropicResponse
	if err := json.Unmarshal(respBody, &antResp); err != nil {
		slog.Error("failed to decode backend response", "error", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}

	oaiResp := convertResponse(antResp)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(oaiResp)

	slog.Info("response",
		"status", resp.StatusCode,
		"model", antResp.Model,
		"stop_reason", antResp.StopReason,
		"input_tokens", antResp.Usage.InputTokens,
		"output_tokens", antResp.Usage.OutputTokens,
		"duration", time.Since(start).Round(time.Millisecond),
	)
}

func handleStream(w http.ResponseWriter, r *http.Request, backendURL string, provider *tokenProvider, antBody []byte, start time.Time) {
	resp, err := doAnthropicRequest(r, backendURL, provider, antBody)
	if err != nil {
		slog.Error("backend stream request failed", "error", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		slog.Error("backend stream error", "status", resp.StatusCode, "body", string(respBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	state := &streamState{
		created: time.Now().Unix(),
	}

	scanner := bufio.NewScanner(resp.Body)
	var currentEvent string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
			continue
		}

		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			chunks := state.processEvent(currentEvent, []byte(data))
			for _, chunk := range chunks {
				raw, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\n", raw)
				flusher.Flush()
			}
			currentEvent = ""
			continue
		}
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()

	slog.Info("stream complete",
		"model", state.model,
		"duration", time.Since(start).Round(time.Millisecond),
	)
}

type streamState struct {
	id               string
	model            string
	created          int64
	toolCallIndex    int
	currentBlockType string
}

func (s *streamState) processEvent(eventType string, data []byte) []openAIStreamChunk {
	switch eventType {
	case "message_start":
		var evt struct {
			Message struct {
				ID    string `json:"id"`
				Model string `json:"model"`
			} `json:"message"`
		}
		json.Unmarshal(data, &evt)
		s.id = fmt.Sprintf("chatcmpl-%s", evt.Message.ID)
		s.model = evt.Message.Model
		s.toolCallIndex = 0

		return []openAIStreamChunk{{
			ID:      s.id,
			Object:  "chat.completion.chunk",
			Created: s.created,
			Model:   s.model,
			Choices: []openAIStreamChoice{{
				Index: 0,
				Delta: openAIStreamDelta{Role: "assistant"},
			}},
		}}

	case "content_block_start":
		var evt struct {
			Index        int `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
		}
		json.Unmarshal(data, &evt)

		s.currentBlockType = evt.ContentBlock.Type

		if evt.ContentBlock.Type == "tool_use" {
			chunk := openAIStreamChunk{
				ID:      s.id,
				Object:  "chat.completion.chunk",
				Created: s.created,
				Model:   s.model,
				Choices: []openAIStreamChoice{{
					Index: 0,
					Delta: openAIStreamDelta{
						ToolCalls: []openAIToolCallChunk{{
							Index: s.toolCallIndex,
							ID:    evt.ContentBlock.ID,
							Type:  "function",
							Function: &openAIFnChunk{
								Name:      evt.ContentBlock.Name,
								Arguments: "",
							},
						}},
					},
				}},
			}
			return []openAIStreamChunk{chunk}
		}
		return nil

	case "content_block_delta":
		var evt struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		json.Unmarshal(data, &evt)

		if evt.Delta.Type == "text_delta" {
			text := evt.Delta.Text
			return []openAIStreamChunk{{
				ID:      s.id,
				Object:  "chat.completion.chunk",
				Created: s.created,
				Model:   s.model,
				Choices: []openAIStreamChoice{{
					Index: 0,
					Delta: openAIStreamDelta{Content: &text},
				}},
			}}
		}

		if evt.Delta.Type == "input_json_delta" {
			return []openAIStreamChunk{{
				ID:      s.id,
				Object:  "chat.completion.chunk",
				Created: s.created,
				Model:   s.model,
				Choices: []openAIStreamChoice{{
					Index: 0,
					Delta: openAIStreamDelta{
						ToolCalls: []openAIToolCallChunk{{
							Index: s.toolCallIndex,
							Function: &openAIFnChunk{
								Arguments: evt.Delta.PartialJSON,
							},
						}},
					},
				}},
			}}
		}
		return nil

	case "content_block_stop":
		if s.currentBlockType == "tool_use" {
			s.toolCallIndex++
		}
		s.currentBlockType = ""
		return nil

	case "message_delta":
		var evt struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage *anthropicUsage `json:"usage"`
		}
		json.Unmarshal(data, &evt)

		reason := mapStopReason(evt.Delta.StopReason)
		chunk := openAIStreamChunk{
			ID:      s.id,
			Object:  "chat.completion.chunk",
			Created: s.created,
			Model:   s.model,
			Choices: []openAIStreamChoice{{
				Index:        0,
				Delta:        openAIStreamDelta{},
				FinishReason: &reason,
			}},
		}
		if evt.Usage != nil {
			chunk.Usage = &openAIUsage{
				PromptTokens:     evt.Usage.InputTokens,
				CompletionTokens: evt.Usage.OutputTokens,
				TotalTokens:      evt.Usage.InputTokens + evt.Usage.OutputTokens,
			}
		}
		return []openAIStreamChunk{chunk}

	case "message_stop", "ping":
		return nil

	default:
		return nil
	}
}

func applyFieldOverrides(body []byte, omit []string, add map[string]string) ([]byte, error) {
	if len(omit) == 0 && len(add) == 0 {
		return body, nil
	}

	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}

	for _, field := range omit {
		delete(m, field)
	}
	for k, v := range add {
		m[k] = v
	}

	return json.Marshal(m)
}

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var v1Endpoint = "/v1/messages"

func TestHandler(t *testing.T) {
	t.Run("non-streaming", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != v1Endpoint {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("anthropic-version") != "2023-06-01" {
				t.Errorf("missing anthropic-version header")
			}
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
			}

			var antReq anthropicRequest
			json.NewDecoder(r.Body).Decode(&antReq)
			if antReq.System != "You are helpful" {
				t.Errorf("system not extracted: %q", antReq.System)
			}
			if antReq.MaxTokens != 100 {
				t.Errorf("unexpected max_tokens: %d", antReq.MaxTokens)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(anthropicResponse{
				ID:         "msg-test",
				Type:       "message",
				Role:       "assistant",
				Content:    []contentBlock{{Type: "text", Text: "Hi there!"}},
				Model:      "claude-sonnet-4-20250514",
				StopReason: "end_turn",
				Usage:      anthropicUsage{InputTokens: 10, OutputTokens: 5},
			})
		}))
		t.Cleanup(backend.Close)

		provider := &tokenProvider{token: "test-token"}
		fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("fallback should not be called")
		})

		handler := newConvertHandler(backend.URL+v1Endpoint, provider, convertOpts{}, fallback)
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"system","content":"You are helpful"},{"role":"user","content":"Hello"}],"max_tokens":100}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		var oaiResp openAIResponse
		json.NewDecoder(resp.Body).Decode(&oaiResp)

		if oaiResp.ID != "chatcmpl-msg-test" {
			t.Errorf("unexpected ID: %q", oaiResp.ID)
		}
		var content string
		json.Unmarshal(oaiResp.Choices[0].Message.Content, &content)
		if content != "Hi there!" {
			t.Errorf("unexpected content: %q", content)
		}
		if oaiResp.Choices[0].FinishReason != "stop" {
			t.Errorf("unexpected finish_reason: %q", oaiResp.Choices[0].FinishReason)
		}
	})

	t.Run("fallthrough on GET", func(t *testing.T) {
		var fallbackCalled bool
		fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fallbackCalled = true
			w.WriteHeader(http.StatusOK)
		})

		provider := &tokenProvider{token: "test-token"}
		handler := newConvertHandler("http://unused", provider, convertOpts{}, fallback)
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		resp, err := http.Get(server.URL + "/v1/chat/completions")
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		resp.Body.Close()

		if !fallbackCalled {
			t.Error("fallback should have been called for GET request")
		}
	})

	t.Run("fallthrough on different path", func(t *testing.T) {
		var fallbackCalled bool
		fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fallbackCalled = true
			w.WriteHeader(http.StatusOK)
		})

		provider := &tokenProvider{token: "test-token"}
		handler := newConvertHandler("http://unused", provider, convertOpts{}, fallback)
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		resp, err := http.Post(server.URL+"/v1/models", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		resp.Body.Close()

		if !fallbackCalled {
			t.Error("fallback should have been called for different path")
		}
	})

	t.Run("streaming", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "no flusher", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			events := []string{
				"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-stream\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-sonnet-4-20250514\",\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n",
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n",
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n",
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n",
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n",
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}\n",
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n",
			}

			for _, e := range events {
				w.Write([]byte(e))
				flusher.Flush()
			}
		}))
		t.Cleanup(backend.Close)

		provider := &tokenProvider{token: "test-token"}
		handler := newConvertHandler(backend.URL+v1Endpoint, provider, convertOpts{}, http.NotFoundHandler())
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		body := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"Hello"}],"max_tokens":100,"stream":true}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("unexpected status %d: %s", resp.StatusCode, body)
		}

		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("unexpected content-type: %q", ct)
		}

		scanner := bufio.NewScanner(resp.Body)
		var chunks []string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				chunks = append(chunks, strings.TrimPrefix(line, "data: "))
			}
		}

		if len(chunks) < 3 {
			t.Fatalf("expected at least 3 chunks, got %d: %v", len(chunks), chunks)
		}

		var first openAIStreamChunk
		json.Unmarshal([]byte(chunks[0]), &first)
		if first.Choices[0].Delta.Role != "assistant" {
			t.Errorf("first chunk should have role 'assistant': %+v", first)
		}

		var gotHello, gotWorld bool
		for _, c := range chunks {
			var chunk openAIStreamChunk
			if json.Unmarshal([]byte(c), &chunk) == nil && len(chunk.Choices) > 0 {
				if chunk.Choices[0].Delta.Content != nil {
					if *chunk.Choices[0].Delta.Content == "Hello" {
						gotHello = true
					}
					if *chunk.Choices[0].Delta.Content == " world" {
						gotWorld = true
					}
				}
			}
		}
		if !gotHello || !gotWorld {
			t.Errorf("missing text chunks, gotHello=%v gotWorld=%v", gotHello, gotWorld)
		}

		last := chunks[len(chunks)-1]
		if last != "[DONE]" {
			t.Errorf("last chunk should be [DONE], got %q", last)
		}

		var finishChunk openAIStreamChunk
		json.Unmarshal([]byte(chunks[len(chunks)-2]), &finishChunk)
		if len(finishChunk.Choices) > 0 && finishChunk.Choices[0].FinishReason != nil {
			if *finishChunk.Choices[0].FinishReason != "stop" {
				t.Errorf("unexpected finish_reason: %q", *finishChunk.Choices[0].FinishReason)
			}
		}
	})

	t.Run("model mapping", func(t *testing.T) {
		var gotModel string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var antReq anthropicRequest
			json.NewDecoder(r.Body).Decode(&antReq)
			gotModel = antReq.Model

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(anthropicResponse{
				ID:         "msg-map",
				Type:       "message",
				Role:       "assistant",
				Content:    []contentBlock{{Type: "text", Text: "Hi"}},
				Model:      "claude-sonnet-4-20250514",
				StopReason: "end_turn",
				Usage:      anthropicUsage{InputTokens: 5, OutputTokens: 2},
			})
		}))
		t.Cleanup(backend.Close)

		provider := &tokenProvider{token: "test-token"}
		handler := newConvertHandler(backend.URL+v1Endpoint, provider, convertOpts{
			modelMap: map[string]string{"gpt-4o": "claude-sonnet-4-20250514"},
		}, http.NotFoundHandler())
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"max_tokens":100}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		resp.Body.Close()

		if gotModel != "claude-sonnet-4-20250514" {
			t.Errorf("model not mapped: got %q", gotModel)
		}
	})

	t.Run("omit and add fields", func(t *testing.T) {
		var gotBody map[string]any
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&gotBody)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(anthropicResponse{
				ID:         "msg-fields",
				Type:       "message",
				Role:       "assistant",
				Content:    []contentBlock{{Type: "text", Text: "ok"}},
				Model:      "claude-sonnet-4-20250514",
				StopReason: "end_turn",
				Usage:      anthropicUsage{InputTokens: 5, OutputTokens: 2},
			})
		}))
		t.Cleanup(backend.Close)

		provider := &tokenProvider{token: "test-token"}
		handler := newConvertHandler(backend.URL+v1Endpoint, provider, convertOpts{
			omitFields: []string{"model"},
			addFields:  map[string]string{"anthropic_version": "2023-06-01"},
		}, http.NotFoundHandler())
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)

		body := `{"model":"claude-opus-4-6","messages":[{"role":"user","content":"Hello"}],"max_tokens":100}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
		resp.Body.Close()

		if _, ok := gotBody["model"]; ok {
			t.Error("model field should have been omitted")
		}
		if v, ok := gotBody["anthropic_version"]; !ok || v != "2023-06-01" {
			t.Errorf("anthropic_version field missing or wrong: %v", gotBody["anthropic_version"])
		}
	})
}

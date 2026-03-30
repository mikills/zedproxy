//go:build e2e

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestE2E(t *testing.T) {
	t.Run("non-streaming", func(t *testing.T) {
		server := e2eHandler(t)

		body := `{"model":"gpt-4o","messages":[{"role":"system","content":"Reply with exactly one word."},{"role":"user","content":"Say hello"}],"max_tokens":50}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}

		var oaiResp openAIResponse
		if err := json.Unmarshal(raw, &oaiResp); err != nil {
			t.Fatalf("decode: %v\nbody: %s", err, raw)
		}

		if oaiResp.Object != "chat.completion" {
			t.Errorf("object = %q, want chat.completion", oaiResp.Object)
		}
		if len(oaiResp.Choices) != 1 {
			t.Fatalf("choices = %d, want 1", len(oaiResp.Choices))
		}
		if oaiResp.Choices[0].FinishReason == "" {
			t.Error("finish_reason is empty")
		}

		var content string
		json.Unmarshal(oaiResp.Choices[0].Message.Content, &content)
		if content == "" {
			t.Error("content is empty")
		}
		t.Logf("response: %q", content)

		if oaiResp.Usage.PromptTokens == 0 {
			t.Error("prompt_tokens is 0")
		}
		if oaiResp.Usage.CompletionTokens == 0 {
			t.Error("completion_tokens is 0")
		}
	})

	t.Run("streaming", func(t *testing.T) {
		server := e2eHandler(t)

		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Say hi in one word"}],"max_tokens":50,"stream":true}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}

		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content-type = %q, want text/event-stream", ct)
		}

		scanner := bufio.NewScanner(resp.Body)
		var gotRole, gotContent, gotFinish, gotDone bool
		var fullContent string

		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")

			if data == "[DONE]" {
				gotDone = true
				continue
			}

			var chunk openAIStreamChunk
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				t.Fatalf("decode chunk: %v\ndata: %s", err, data)
			}

			if chunk.Object != "chat.completion.chunk" {
				t.Errorf("chunk object = %q", chunk.Object)
			}
			if len(chunk.Choices) == 0 {
				continue
			}

			delta := chunk.Choices[0].Delta
			if delta.Role == "assistant" {
				gotRole = true
			}
			if delta.Content != nil && *delta.Content != "" {
				gotContent = true
				fullContent += *delta.Content
			}
			if chunk.Choices[0].FinishReason != nil {
				gotFinish = true
			}
		}

		if !gotRole {
			t.Error("never received role delta")
		}
		if !gotContent {
			t.Error("never received content delta")
		}
		if !gotFinish {
			t.Error("never received finish_reason")
		}
		if !gotDone {
			t.Error("never received [DONE]")
		}
		t.Logf("streamed: %q", fullContent)
	})

	t.Run("system message", func(t *testing.T) {
		server := e2eHandler(t)

		body := `{"model":"gpt-4o","messages":[{"role":"system","content":"You must respond with exactly the word PINEAPPLE and nothing else."},{"role":"user","content":"What should you say?"}],"max_tokens":20}`
		resp, err := http.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}

		var oaiResp openAIResponse
		json.Unmarshal(raw, &oaiResp)

		var content string
		json.Unmarshal(oaiResp.Choices[0].Message.Content, &content)
		if !strings.Contains(strings.ToUpper(content), "PINEAPPLE") {
			t.Errorf("system message not respected, got: %q", content)
		}
		t.Logf("response: %q", content)
	})
}

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set, skipping e2e test", key)
	}
	return v
}

func e2eHandler(t *testing.T) *httptest.Server {
	t.Helper()
	apiKey := mustEnv(t, "ANTHROPIC_API_KEY")

	provider := &tokenProvider{token: apiKey}
	handler := newConvertHandler(
		"https://api.anthropic.com/v1/messages",
		provider,
		convertOpts{
			modelMap: map[string]string{"gpt-4o": "claude-haiku-4-5-20251001"},
		},
		http.NotFoundHandler(),
	)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyInjectsBearerToken(t *testing.T) {
	var gotAuth string
	var gotPath string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	proxy, err := newReverseProxy(backend.URL, WithTokenFetcherFunc(func() string {
		return "fresh-token"
	}))
	if err != nil {
		t.Fatalf("newReverseProxy: %v", err)
	}

	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/hello")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer fresh-token" {
		t.Fatalf("unexpected Authorization header: %q", gotAuth)
	}
	if gotPath != "/hello" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
}

func TestProxyHandlesTokenError(t *testing.T) {
	var called int32

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	proxy, err := newReverseProxy(backend.URL, WithTokenFetcherFunc(func() string {
		return ""
	}))
	if err != nil {
		t.Fatalf("newReverseProxy: %v", err)
	}

	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/data")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Fatalf("backend should not be called")
	}
}

func TestProxyRefreshesTokenOnUnauthorized(t *testing.T) {
	var backendCalls int32
	var tokenCalls int32

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token":"new-token","expires_in":3600}`))
	}))
	t.Cleanup(tokenServer.Close)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&backendCalls, 1)
		if r.Header.Get("Authorization") != "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	proxy, err := newReverseProxy(
		backend.URL,
		WithTokenFetcherFunc(func() string { return "bad-token" }),
		WithTokenRefreshURL(tokenServer.URL),
	)
	if err != nil {
		t.Fatalf("newReverseProxy: %v", err)
	}

	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/data")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&backendCalls) != 2 {
		t.Fatalf("backend should be called twice")
	}
	if atomic.LoadInt32(&tokenCalls) != 1 {
		t.Fatalf("token endpoint should be called once")
	}
}

func TestProxyStreamsResponse(t *testing.T) {
	firstSent := make(chan struct{})
	allowSecond := make(chan struct{})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("first\n"))
		flusher.Flush()
		close(firstSent)

		<-allowSecond
		_, _ = w.Write([]byte("second\n"))
		flusher.Flush()
	}))
	t.Cleanup(backend.Close)

	proxy, err := newReverseProxy(backend.URL, WithTokenFetcherFunc(func() string {
		return "fresh-token"
	}))
	if err != nil {
		t.Fatalf("newReverseProxy: %v", err)
	}

	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/stream")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	firstLineCh := make(chan string, 1)
	firstErrCh := make(chan error, 1)

	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			firstErrCh <- err
			return
		}
		firstLineCh <- line
	}()

	select {
	case <-firstSent:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("backend did not send first chunk")
	}

	select {
	case err := <-firstErrCh:
		t.Fatalf("read first chunk: %v", err)
	case line := <-firstLineCh:
		if line != "first\n" {
			t.Fatalf("unexpected first chunk: %q", line)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("first chunk was not streamed in time")
	}

	close(allowSecond)

	secondLineCh := make(chan string, 1)
	secondErrCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			secondErrCh <- err
			return
		}
		secondLineCh <- line
	}()

	select {
	case err := <-secondErrCh:
		t.Fatalf("read second chunk: %v", err)
	case line := <-secondLineCh:
		if line != "second\n" {
			t.Fatalf("unexpected second chunk: %q", line)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("second chunk was not streamed in time")
	}
}

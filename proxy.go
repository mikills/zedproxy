package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TokenRefreshFunc func(ctx context.Context) (string, error)

type tokenRefreshFunc func(ctx context.Context) (string, time.Duration, error)

const defaultExpiryBuffer = 30 * time.Second

type tokenErrorKey struct{}

type tokenErrorTransport struct {
	base http.RoundTripper
}

func (t tokenErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err, ok := req.Context().Value(tokenErrorKey{}).(error); ok && err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

type TokenFetcherFunc func() string

type ProxyOption func(*proxyConfig)

type proxyConfig struct {
	provider *tokenProvider
}

type tokenProvider struct {
	mu        sync.Mutex
	token     string
	refreshAt time.Time
	fetch     TokenFetcherFunc
	refresh   tokenRefreshFunc
}

func (p *tokenProvider) current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token
}

func (p *tokenProvider) set(token string) {
	p.mu.Lock()
	p.token = token
	p.mu.Unlock()
}

func (p *tokenProvider) setWithExpiry(token string, expiresIn time.Duration) {
	if expiresIn > 0 {
		buffer := defaultExpiryBuffer
		if expiresIn/10 > 0 && expiresIn/10 < buffer {
			buffer = expiresIn / 10
		}
		if expiresIn < buffer {
			buffer = expiresIn / 2
		}
		if expiresIn >= 2*time.Second && buffer < time.Second {
			buffer = time.Second
		}
		expiresAt := time.Now().Add(expiresIn)
		p.refreshAt = expiresAt.Add(-buffer)
	} else {
		p.refreshAt = time.Time{}
	}
	p.token = token
}

func (p *tokenProvider) ensureToken(ctx context.Context) (string, error) {
	if p == nil {
		return "", errors.New("token provider is not configured")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.refresh == nil {
		if strings.TrimSpace(p.token) == "" {
			return "", errors.New("token is empty")
		}
		return p.token, nil
	}

	if strings.TrimSpace(p.token) == "" || (!p.refreshAt.IsZero() && time.Now().After(p.refreshAt)) {
		token, expiresIn, err := p.refresh(ctx)
		if err != nil {
			return "", err
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return "", errors.New("token is empty")
		}
		p.setWithExpiry(token, expiresIn)
	}

	return p.token, nil
}

func (p *tokenProvider) forceRefresh(ctx context.Context) (string, error) {
	if p == nil || p.refresh == nil {
		return "", errors.New("token refresh is not configured")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	token, expiresIn, err := p.refresh(ctx)
	if err != nil {
		return "", err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("token is empty")
	}

	p.setWithExpiry(token, expiresIn)
	return token, nil
}

type tokenRetryKey struct{}

type tokenRetryTransport struct {
	base     http.RoundTripper
	provider *tokenProvider
}

func (t tokenRetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	if req.Context().Value(tokenRetryKey{}) != nil {
		return resp, nil
	}

	if t.provider == nil {
		return resp, nil
	}

	if t.provider.refresh == nil {
		return resp, nil
	}

	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil
	}

	token, err := t.provider.forceRefresh(req.Context())
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		resp.Body.Close()
	}

	newReq := req.Clone(context.WithValue(req.Context(), tokenRetryKey{}, true))
	if req.GetBody != nil {
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, bodyErr
		}
		newReq.Body = body
	}

	newReq.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(newReq)
}

func WithTokenFetcherFunc(fetch TokenFetcherFunc) ProxyOption {
	return func(cfg *proxyConfig) {
		if fetch != nil {
			cfg.provider.fetch = fetch
		}
	}
}

func WithTokenRefreshFunc(refresh TokenRefreshFunc) ProxyOption {
	return func(cfg *proxyConfig) {
		if refresh != nil {
			cfg.provider.refresh = func(ctx context.Context) (string, time.Duration, error) {
				token, err := refresh(ctx)
				return token, 0, err
			}
		}
	}
}

func WithTokenRefreshURL(tokenURL string) ProxyOption {
	return func(cfg *proxyConfig) {
		if strings.TrimSpace(tokenURL) == "" {
			return
		}
		cfg.provider.refresh = func(ctx context.Context) (string, time.Duration, error) {
			return fetchTokenFromURL(ctx, tokenURL)
		}
	}
}

func newReverseProxy(backendURL string, opts ...ProxyOption) (*httputil.ReverseProxy, error) {
	if strings.TrimSpace(backendURL) == "" {
		return nil, errors.New("backend URL is required")
	}

	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	cfg := proxyConfig{provider: &tokenProvider{}}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.provider.fetch == nil && cfg.provider.refresh == nil {
		return nil, errors.New("token fetcher or refresh must be configured")
	}

	if cfg.provider.fetch != nil {
		initial := strings.TrimSpace(cfg.provider.fetch())
		if initial != "" {
			cfg.provider.set(initial)
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		baseDirector(req)

		token, err := cfg.provider.ensureToken(req.Context())
		if err != nil {
			*req = *req.WithContext(context.WithValue(req.Context(), tokenErrorKey{}, err))
			return
		}

		req.Header.Set("Authorization", "Bearer "+token)
	}

	baseTransport := proxy.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	proxy.Transport = tokenRetryTransport{
		base:     tokenErrorTransport{base: baseTransport},
		provider: cfg.provider,
	}
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		http.Error(w, "proxy error", http.StatusBadGateway)
	}

	return proxy, nil
}

func fetchTokenFromURL(ctx context.Context, tokenURL string) (string, time.Duration, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, errors.New("token refresh returned non-200")
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", 0, err
	}

	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", 0, errors.New("token refresh returned empty token")
	}

	if payload.ExpiresIn <= 0 {
		return payload.AccessToken, 0, nil
	}

	return payload.AccessToken, time.Duration(payload.ExpiresIn) * time.Second, nil
}

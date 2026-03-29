package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func main() {
	backendFlag := flag.String("backend", "", "Backend URL (overrides BACKEND_URL)")
	addrFlag := flag.String("addr", ":8080", "Listen address")
	tokenURLFlag := flag.String("token-url", "", "Token refresh URL (overrides TOKEN_URL)")
	convertFlag := flag.Bool("convert", false, "Enable OpenAI-to-Anthropic request conversion")
	modelMapFlag := flag.String("model-map", "", "Model name mappings (e.g. gpt-4o=claude-sonnet-4-20250514,gpt-4=claude-opus-4-20250514)")
	flag.Parse()

	backendURL := *backendFlag
	if strings.TrimSpace(backendURL) == "" {
		backendURL = os.Getenv("BACKEND_URL")
	}

	tokenURL := *tokenURLFlag
	if strings.TrimSpace(tokenURL) == "" {
		tokenURL = os.Getenv("TOKEN_URL")
	}

	var opts []ProxyOption
	if strings.TrimSpace(tokenURL) != "" {
		opts = append(opts, WithTokenRefreshURL(tokenURL))
	}

	proxy, provider, err := newReverseProxy(backendURL, opts...)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		os.Exit(1)
	}

	var handler http.Handler = proxy
	if *convertFlag {
		modelMap := parseModelMap(*modelMapFlag)
		handler = newConvertHandler(backendURL, provider, modelMap, proxy)
		slog.Info("starting proxy", "mode", "convert", "backend", backendURL, "addr", *addrFlag)
	} else {
		slog.Info("starting proxy", "mode", "passthrough", "backend", backendURL, "addr", *addrFlag)
	}

	if err := http.ListenAndServe(*addrFlag, handler); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func parseModelMap(s string) map[string]string {
	m := make(map[string]string)
	if strings.TrimSpace(s) == "" {
		return m
	}
	for _, pair := range strings.Split(s, ",") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			from := strings.TrimSpace(parts[0])
			to := strings.TrimSpace(parts[1])
			if from != "" && to != "" {
				m[from] = to
			}
		}
	}
	return m
}

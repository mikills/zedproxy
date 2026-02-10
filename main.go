package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	backendFlag := flag.String("backend", "", "Backend URL (overrides BACKEND_URL)")
	addrFlag := flag.String("addr", ":8080", "Listen address")
	tokenURLFlag := flag.String("token-url", "", "Token refresh URL (overrides TOKEN_URL)")
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

	proxy, err := newReverseProxy(backendURL, opts...)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("proxying to %s", backendURL)
	log.Fatal(http.ListenAndServe(*addrFlag, proxy))
}

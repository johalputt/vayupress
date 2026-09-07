// SPDX-License-Identifier: Apache-2.0

// Command screenshot-proxy is a tiny reverse proxy used only by the screenshot
// pipeline. Headless Chrome cannot set custom request headers from the CLI, but
// the VayuPress operator console requires an X-API-Key header. This proxy sits
// in front of a running instance and injects that header on every forwarded
// request, so the capture script can point Chrome at the proxy and reach the
// authenticated /admin pages.
//
// It is intentionally NOT part of the production build — it lives under
// scripts/ as its own main package and is only invoked by CI.
//
// Usage:
//
//	UPSTREAM=http://localhost:8080 API_KEY=secret LISTEN=:8088 \
//	    go run ./scripts/screenshot-proxy
package main

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	upstream := env("UPSTREAM", "http://localhost:8080")
	listen := env("LISTEN", ":8088")
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("screenshot-proxy: API_KEY is required")
	}

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("screenshot-proxy: bad UPSTREAM %q: %v", upstream, err)
	}

	proxy := &httputil.ReverseProxy{
		// Rewrite replaces the Director field, deprecated since Go 1.26
		// (staticcheck SA1019). Rewrite strips the inbound Forwarded /
		// X-Forwarded-* headers that Director mode passed through, so they are
		// re-attached and the immediate peer appended to X-Forwarded-For
		// exactly as Director mode did.
		Rewrite: func(pr *httputil.ProxyRequest) {
			for _, h := range []string{
				"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
			} {
				if vs := pr.In.Header.Values(h); len(vs) > 0 {
					pr.Out.Header[http.CanonicalHeaderKey(h)] = vs
				}
			}
			if client, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				prior := pr.In.Header.Values("X-Forwarded-For")
				if len(prior) > 0 {
					client = strings.Join(prior, ", ") + ", " + client
				}
				pr.Out.Header.Set("X-Forwarded-For", client)
			}
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			// Inject the credential Chrome headless cannot send itself. Local,
			// ephemeral, CI-only — the key never leaves the runner.
			pr.Out.Header.Set("X-API-Key", apiKey)
		},
	}

	log.Printf("screenshot-proxy: %s -> %s (injecting X-API-Key)", listen, upstream)
	if err := http.ListenAndServe(listen, proxy); err != nil {
		log.Fatalf("screenshot-proxy: %v", err)
	}
}

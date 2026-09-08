// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/johalputt/vayupress/internal/auth"
	"github.com/johalputt/vayupress/internal/config"
	"github.com/johalputt/vayupress/internal/logging"
	"github.com/johalputt/vayupress/internal/metrics"
	"github.com/johalputt/vayupress/internal/render"
	"github.com/johalputt/vayupress/internal/reqclass"
	"github.com/johalputt/vayupress/internal/safefetch"
	"github.com/johalputt/vayupress/internal/trace"
)

// =============================================================================
// SSRF protection (ADR-0009)
//
// The SSRF-safe outbound dialer now lives in internal/safefetch as the single
// source of truth (safefetch.SafeTransport). It pins the validated IP at dial
// time (closing the DNS-rebind window), never honours an environment proxy, and
// refuses the full set of private/reserved ranges. The weaker, re-resolving
// transport that previously lived here has been removed.
// =============================================================================

// internalServiceHosts are trusted, operator-configured loopback endpoints
// (a local AI runtime, for example) that the shared outbound client is allowed
// to reach even though they resolve to a private/loopback address. Webhook and
// update traffic uses the same client, so this is the *only* private
// destination any guarded outbound request may reach.
var internalServiceHosts = []string{"127.0.0.1", "localhost", "::1"}

// safeOutboundTransport builds the SSRF-hardened transport for the shared
// outbound HTTP client (webhooks, update checks, AI service calls).
func safeOutboundTransport() *http.Transport {
	return safefetch.SafeTransport(safefetch.TransportOptions{AllowHosts: internalServiceHosts})
}

// safeUpdateTransport is the update-check/download transport: the same SSRF
// guard with the resilient dialer enabled. Update traffic is exactly where a
// host's broken route to GitHub must not become "updates are broken" — the
// dialer races every address the resolver offers and, as a last resort,
// re-resolves through DNS-over-HTTPS. The mirror chain in internal/update
// sits on top of this.
func safeUpdateTransport() *http.Transport {
	return safefetch.SafeTransport(safefetch.TransportOptions{
		AllowHosts:  internalServiceHosts,
		EnableDoH:   true,
		DialTimeout: 3 * time.Second,
	})
}

// realIPMiddleware normalises r.RemoteAddr to the real client IP using the
// trusted-proxy-aware resolver (auth.ClientIP). It replaces chi's
// middleware.RealIP, which trusts X-Forwarded-For / X-Real-IP unconditionally
// and is therefore vulnerable to IP spoofing (GHSA-3fxj-6jh8-hvhx, audit F-3).
// Forwarding headers are honoured only when the immediate peer is a configured
// trusted proxy; otherwise RemoteAddr is left as the direct peer address.
// ctxKeyPeerAddr carries the address the connection ACTUALLY came from, before
// this middleware overwrites RemoteAddr with the resolved client address.
//
// Kept because the overwrite destroys the only evidence that resolution
// happened. Downstream code asking `auth.ClientIP(r) != r.RemoteAddr` is
// re-running the resolver over its own output: on a working install the second
// pass sees a real visitor as the peer, honours no header, and returns it
// unchanged — so the two sides match and the check reports failure on an install
// where everything works. That is what the posture report was doing, and every
// conclusion drawn from that row was unfounded while it did.
type ctxKeyPeerAddr struct{}

func realIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := stripPort(r.RemoteAddr)
		r.RemoteAddr = auth.ClientIP(r)
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyPeerAddr{}, peer))
		// Record whether this request came through a CDN, so the hardening panel
		// can answer "is this SITE proxied?" rather than only "did the request I
		// am serving come through a proxy?". Those differ exactly when an operator
		// reaches the console via a hosts entry pointing at the origin — common
		// practice, and the reason the panel once told a proxied site that nothing
		// was in front of it. Rate-limited internally to near-zero cost.
		noteCDNObservation(r)
		// Whether the address the per-IP controls will key on is the READER's,
		// sampled from ordinary traffic. Without this the posture report has no
		// answer at all when it is asked without a request, which is how it came
		// to report failure on every proxied install over the connector.
		noteVisitorResolution(r)
		next.ServeHTTP(w, r)
	})
}

// =============================================================================
// Request ID context
// =============================================================================

type ctxKeyRequestID struct{}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			b := make([]byte, 8)
			if _, err := rand.Read(b); err != nil {
				reqID = fmt.Sprintf("ts-%x", time.Now().UnixNano())
			} else {
				reqID = hex.EncodeToString(b)
			}
		}
		// Correlation ID: caller-supplied or derived from request ID.
		corrID := r.Header.Get("X-Correlation-ID")
		if corrID == "" {
			corrID = reqID
		}
		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("X-Correlation-ID", corrID)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		ctx = trace.WithCorrelationID(ctx, corrID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getRequestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyRequestID{}).(string); ok {
		return v
	}
	return ""
}

// streamLatencyCutoff separates a slow-but-real request from a long-lived stream.
// The global request timeout is 30s, so a handler that ran longer was a
// hijacked/streamed connection (WebSocket, SSE, a VayuTalk relay), whose lifetime
// must never be counted as request latency.
const streamLatencyCutoff = 30 * time.Second

// debugRequestIdentity gates plaintext client identity (IP, User-Agent) in
// server logs and trace spans. The published privacy report promises
// pii_stored:false, yet journald/Docker kept these lines forever, outside every
// purge job (audit). Default logs carry NO address and NO agent; an operator
// debugging traffic sets VAYU_DEBUG_REQUESTS=1 and owns the retention policy
// that comes with it.
var debugRequestIdentity = os.Getenv("VAYU_DEBUG_REQUESTS") == "1"

// logIdentity returns the plaintext identity fields for a request log entry,
// or empty strings when debug identity is off (the fields are omitempty, so
// they vanish from the JSON entirely).
func logIdentity(r *http.Request) (remoteAddr, userAgent string) {
	if !debugRequestIdentity {
		return "", ""
	}
	return r.RemoteAddr, r.UserAgent()
}

func structuredLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root HTTP span: wraps the entire request lifecycle. Kept deliberately
		// lean — this runs on EVERY request, so it avoids reflection-based
		// formatting (fmt.Sprintf) and the per-request runtime.NumGoroutine()
		// scheduler probe that used to be recorded as a span attribute (live
		// goroutine count is exposed as a gauge via /api/v1/admin/resource/stats
		// instead). Fewer per-request allocations = less GC pressure = a tighter
		// P95/P99 tail.
		ctx, span := trace.Start(r.Context(), "http."+r.Method+" "+r.URL.Path)
		span.SetAttribute("http.method", r.Method)
		span.SetAttribute("http.path", r.URL.Path)
		// Client identity is deliberately ABSENT from spans by default: the
		// published privacy report promises pii_stored:false, and span storage
		// sits outside every analytics purge job. VAYU_DEBUG_REQUESTS=1 opts
		// the operator back in (their retention policy to manage).
		if debugRequestIdentity {
			span.SetAttribute("http.remote_addr", r.RemoteAddr)
		}
		// Seed a mutable classification so VayuShield (an inner middleware) can flag
		// a request it deliberately delayed (a 5s tarpit) or challenged — that time
		// is bot defence, not page latency, and must be kept out of the p95.
		ctx = reqclass.NewContext(ctx)

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r.WithContext(ctx))

		span.SetAttribute("http.status", strconv.Itoa(ww.Status()))
		if ww.Status() >= 500 {
			span.Status = trace.StatusError
		}
		span.End()

		dur := span.EndTime.Sub(span.StartTime)
		// Latency metrics measure page/request responsiveness, so exclude requests
		// that are not representative page loads:
		//   - Long-lived/streamed connections (a VayuTalk relay held open for
		//     minutes) would record their ENTIRE lifetime as one "request latency";
		//     nothing under the 30s server timeout is a stream.
		//   - VayuShield-defended requests: a tarpit deliberately sleeps ~5s to waste
		//     a confirmed bot's time, so counting it as latency pins the p95 tail at
		//     the shield's own delay for as long as bots keep probing.
		// The windowed view drives the dashboards (recent real latency); the
		// cumulative one stays the Prometheus source.
		if dur <= streamLatencyCutoff && !reqclass.Shielded(ctx) {
			metrics.HTTPLatency.Record(dur)
			metrics.HTTPLatencyWindow.Record(dur)
		}
		ra, ua := logIdentity(r)
		logging.LogJSON(logging.LogFields{
			Level: "info", RequestID: getRequestID(r),
			CorrelationID: trace.CorrelationID(r.Context()),
			Method:        r.Method, Path: r.URL.Path,
			Status: ww.Status(), LatencyMS: dur.Milliseconds(),
			RemoteAddr: ra, UserAgent: ua, Component: "http",
		})
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Onion hardening: a .onion is plain HTTP and self-authenticating, so HSTS
		// is meaningless (and wrong) over it — omit it. This middleware runs before
		// torOnionMiddleware rewrites the Host, so r.Host is still the .onion here.
		onion := isOnionHost(r.Host)
		if !onion {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		nonce := render.GenerateCSPNonce()
		// Strict baseline (no third-party frame-src). Pages with a click-to-load
		// video facade narrowly extend frame-src themselves via render.BuildCSP.
		csp := render.BuildCSP(nonce, nil)
		// Report-Only mode (CSP_REPORT_ONLY=true) reports violations without
		// blocking — useful in staging to surface frontend regressions via
		// /csp-report before flipping a stricter policy to enforcing.
		cspHeader := "Content-Security-Policy"
		if config.Cfg.CSPReportOnly {
			cspHeader = "Content-Security-Policy-Report-Only"
		}
		w.Header().Set(cspHeader, csp)
		ctx := render.WithCSPNonce(r.Context(), nonce)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Onion visitors get the strictest referrer policy so the .onion URL never
		// leaks as a Referer to any off-onion navigation or subresource.
		refPol := "strict-origin-when-cross-origin"
		if onion {
			refPol = "no-referrer"
		}
		w.Header().Set("Referrer-Policy", refPol)
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeSecureCookie routes through the single auth-package implementation so the
// request/host-aware Secure policy (off on the http .onion and localhost, on for
// clearnet HTTPS; ADR-0141) is applied in exactly one place — which also means a
// static analyzer sees ONE correctly-conditional cookie site instead of one per
// handler. Secure cannot be a constant true without breaking Tor mode (a Secure
// cookie is dropped over the plain-http .onion).
func writeSecureCookie(w http.ResponseWriter, c *http.Cookie) {
	auth.WriteSecureCookie(w, c)
}

// csrfTokenFor returns the CSRF token this response should carry: the one the
// browser already holds when it is still valid, and a freshly minted one only
// when there is none. It always (re)writes the cookie, which refreshes the
// 1-hour lifetime without changing the value.
//
// Reuse is the point. Minting unconditionally on every page render meant a second
// tab — or simply loading a page twice — overwrote the cookie while the first
// page's form still carried the previous token, so submitting the older form
// 403'd with "CSRF token missing or invalid" and no amount of retrying helped.
// auth.CSRFTokenMiddleware has always behaved this way for the routes it guards;
// the HTML writers minted directly and so contradicted it. This is that same rule
// in one place, for every writer.
//
// Reuse costs nothing in defence: the token is a stateless HMAC, unforgeable
// without the server secret, and the double-submit check still requires the
// attacker to both know the value and set the cookie — which rotation on render
// never prevented either.
func csrfTokenFor(w http.ResponseWriter, r *http.Request) string {
	// Bound to the caller's session (audit Section 1). A token minted for one
	// principal is no longer acceptable for another, and it expires an hour after
	// it was issued rather than only in the browser's cookie jar.
	binding := ""
	if r != nil {
		binding = auth.CSRFBinding(r)
		if c, err := r.Cookie("vp_csrf"); err == nil && c.Value != "" && auth.ValidateCSRFToken(c.Value, binding) {
			setCSRFCookie(w, c.Value)
			return c.Value
		}
	}
	token := auth.GenerateCSRFToken(binding)
	if token != "" {
		setCSRFCookie(w, token)
	}
	return token
}

// setCSRFCookie writes the double-submit vp_csrf cookie via the dedicated
// readable-cookie writer: HttpOnly is off by design, because the double-submit
// pattern requires the page script to read the token and echo it in the
// X-CSRF-Token header. Every other (session/auth) cookie goes through
// writeSecureCookie, which forces HttpOnly on.
func setCSRFCookie(w http.ResponseWriter, token string) {
	auth.WriteReadableCookie(w, &http.Cookie{
		Name:     "vp_csrf",
		Value:    token,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600,
	})
}

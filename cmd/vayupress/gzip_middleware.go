// SPDX-License-Identifier: Apache-2.0

package main

// gzipMiddleware — origin compression for bare single-binary installs.
//
// A production install sits behind nginx, which compresses on the edge. But the
// product's core promise is a SINGLE BINARY: an operator who never installs
// nginx serves every page raw, and the console assets alone (a 338KB stylesheet
// plus 177KB of JS) made every cold load drag on a connection that would have
// carried one third of the bytes gzipped. This middleware closes that gap with
// nothing but the standard library — no dependency, no build step, in keeping
// with the zero-CDN / vanilla-stack prime directive.
//
// What it deliberately does NOT touch:
//
//   - Requests with a Range header: media seeking needs byte-exact responses,
//     and a re-compressed body destroys the offsets the client asked for.
//   - text/event-stream: SSE is a live stream; buffering it behind a gzip
//     writer turns "genuinely live" back into polling.
//   - Responses that are already encoded (the handler chose br/zstd): never
//     double-compress.
//   - Statuses without a body (204, 304, 1xx): they must not grow a gzip
//     trailer, and a 304 that advertises an encoding its ETag never saw would
//     poison cache validation.
//   - Non-compressible types (woff2, PNG, WebM…): gzip buys nothing there.
//
// When nginx fronts the install both arrangements are safe: nginx either
// forwards Accept-Encoding (backend gzips, edge passes through) or clears it
// (backend sends identity, edge compresses).

import (
	"compress/gzip"
	"net/http"
	"strings"
)

// gzipCompressible reports whether a response of this content type benefits
// from gzip. Text families, JSON, JavaScript and XML (including SVG and feed
// XML) collapse to a third of their size; already-compressed media does not.
func gzipCompressible(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	if ct == "text/event-stream" {
		return false
	}
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	return strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "xml")
}

// acceptsGzip parses Accept-Encoding loosely: any token named gzip (with or
// without a q-value) opts the response in. A malformed header simply yields
// identity, which is always safe.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		token := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if strings.EqualFold(token, "gzip") {
			return true
		}
	}
	return false
}

// gzipResponseWriter defers the compression decision until the response's
// content type is actually known — either from an explicit Content-Type header
// or sniffed from the first chunk — because a middleware cannot know what the
// handler is about to emit.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	compress    bool
	wroteHeader bool
	wroteBody   bool
}

// decide locks the compression choice. chunk may be nil when called from
// WriteHeader (content type must then be explicit). It is idempotent: the
// first call wins.
func (w *gzipResponseWriter) decide(status int, chunk []byte) {
	if w.gz != nil {
		return
	}
	ct := w.Header().Get("Content-Type")
	if ct == "" && len(chunk) > 0 {
		ct = http.DetectContentType(chunk)
	}
	if status < 200 || status == 204 || status == 304 ||
		!gzipCompressible(ct) ||
		w.Header().Get("Content-Encoding") != "" {
		return
	}
	h := w.Header()
	// The gzipped length is unknown until Close; a stale Content-Length would
	// truncate the body.
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	if vary := h.Get("Vary"); vary != "" && !strings.Contains(vary, "Accept-Encoding") {
		h.Set("Vary", vary+", Accept-Encoding")
	} else if vary == "" {
		h.Set("Vary", "Accept-Encoding")
	}
	w.gz = gzip.NewWriter(w.ResponseWriter)
	w.compress = true
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.decide(status, nil)
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.decide(http.StatusOK, b)
	}
	w.wroteBody = true
	if w.compress {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Flush passes through so streaming handlers (htmx partial pushes, exports)
// keep working; the gzip buffer is flushed first so the client sees the bytes.
func (w *gzipResponseWriter) Flush() {
	if w.compress && w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r) || r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		rw := &gzipResponseWriter{ResponseWriter: w}
		defer func() {
			// Close flushes the gzip trailer. Only after a body was written:
			// closing a writer that saw zero bytes would still emit a header
			// + trailer, appending a gzip stream to bodyless responses.
			if rw.compress && rw.wroteBody {
				_ = rw.gz.Close()
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

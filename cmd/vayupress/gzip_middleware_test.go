// SPDX-License-Identifier: Apache-2.0

package main

// gzip_middleware_test.go — a bare single-binary install compresses at the
// origin. The assertions pin the CONTRACT, not the ratio: identity stays
// identity, bodyless statuses stay bodyless, already-encoded responses are
// never double-compressed, and what is advertised as gzip actually gunzips to
// the bytes the handler wrote.

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gzipServe(t *testing.T, acceptEncoding, rangeHdr string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	if rangeHdr != "" {
		req.Header.Set("Range", rangeHdr)
	}
	rec := httptest.NewRecorder()
	gzipMiddleware(handler).ServeHTTP(rec, req)
	return rec
}

func mustGunzip(t *testing.T, body []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("response is not a readable gzip stream: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip failed: %v", err)
	}
	return string(out)
}

func TestCompressibleResponseIsGzippedWhenAsked(t *testing.T) {
	payload := strings.Repeat("<html>… the console stylesheet and script cargo …</html>", 40)
	rec := gzipServe(t, "gzip, deflate, br", "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(payload))
	})

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip — the bare-binary install ships raw bytes", got)
	}
	if got := mustGunzip(t, rec.Body.Bytes()); got != payload {
		t.Fatal("the gzipped body does not decode to what the handler wrote")
	}
	if rec.Header().Get("Content-Length") != "" {
		t.Error("Content-Length survives compression — a stale length truncates the body")
	}
	if vary := rec.Header().Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q — a shared cache must not replay a gzipped body to a client that asked for identity", vary)
	}
}

func TestIdentityWhenTheClientNeverAsked(t *testing.T) {
	rec := gzipServe(t, "", "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>plain</html>"))
	})
	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("an identity request was compressed anyway")
	}
	if got := rec.Body.String(); got != "<html>plain</html>" {
		t.Errorf("body altered for an identity request: %q", got)
	}
}

func TestRangeRequestsAreNeverRecompressed(t *testing.T) {
	rec := gzipServe(t, "gzip", "bytes=0-4", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("ID3 audio bytes"))
	})
	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("a ranged request was compressed — byte offsets no longer address the file")
	}
	if got := rec.Body.String(); got != "ID3 audio bytes" {
		t.Errorf("ranged body altered: %q", got)
	}
}

func TestServerSentEventsStreamUncompressed(t *testing.T) {
	rec := gzipServe(t, "gzip", "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: live\n\n"))
	})
	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("SSE was buffered behind a gzip writer — live deltas become polling again")
	}
	if got := rec.Body.String(); got != "data: live\n\n" {
		t.Errorf("SSE body altered: %q", got)
	}
}

func TestAlreadyEncodedResponsesAreNotDoubleCompressed(t *testing.T) {
	rec := gzipServe(t, "gzip", "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("brotli bytes"))
	})
	if got := rec.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("Content-Encoding = %q, want the handler's br untouched", got)
	}
	if got := rec.Body.String(); got != "brotli bytes" {
		t.Errorf("pre-encoded body altered: %q", got)
	}
}

func TestBodylessStatusesDoNotGrowAGzipTrailer(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusNotModified} {
		rec := gzipServe(t, "gzip", "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/css")
			w.WriteHeader(status)
		})
		if rec.Body.Len() != 0 {
			t.Errorf("status %d grew a %d-byte body — the gzip trailer leaked into a bodyless response", status, rec.Body.Len())
		}
	}
}

func TestContentTypeIsSniffedWhenTheHandlerOmitsIt(t *testing.T) {
	payload := `{"delta":1,"kind":"attention"}`
	rec := gzipServe(t, "gzip", "", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	})
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("sniffed JSON was not compressed")
	}
	if got := mustGunzip(t, rec.Body.Bytes()); got != payload {
		t.Errorf("sniffed body corrupt: %q", got)
	}
}

func TestNonCompressibleTypesPassThrough(t *testing.T) {
	woff2 := []byte("wOF2-fake-font-bytes")
	rec := gzipServe(t, "gzip", "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "font/woff2")
		_, _ = w.Write(woff2)
	})
	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Error("woff2 was gzipped — the format is already compressed")
	}
	if !bytes.Equal(rec.Body.Bytes(), woff2) {
		t.Error("font body altered")
	}
}

func TestEveryConsoleAssetContentTypeCompresses(t *testing.T) {
	for _, ct := range []string{
		"text/css; charset=utf-8",
		"application/javascript",
		"application/json",
		"application/rss+xml",
		"image/svg+xml",
		"application/manifest+json",
	} {
		if !gzipCompressible(ct) {
			t.Errorf("%q should be compressible", ct)
		}
	}
	for _, ct := range []string{"image/png", "font/woff2", "video/webm", "application/pdf", "text/event-stream", ""} {
		if gzipCompressible(ct) {
			t.Errorf("%q should NOT be compressible", ct)
		}
	}
}

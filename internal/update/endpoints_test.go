// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain keeps the endpoint chain hermetic: without it, every test that
// deliberately fails a direct GitHub download would retry through the real
// official mirror (a live network call inside unit tests). Tests that
// exercise the mirror opt in explicitly with t.Setenv.
func TestMain(m *testing.M) {
	os.Setenv("VAYU_UPDATE_MIRROR", "off")
	os.Exit(m.Run())
}

// githubDownTransport routes github.com requests to a dead-route failure and
// every OTHER host to the test mux — modelling a host whose route to GitHub's
// edges is blackholed while the CDN/mirror edges are fine.
type githubDownTransport struct{ target *httptest.Server }

func (g githubDownTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.EqualFold(req.URL.Host, "api.github.com") || strings.EqualFold(req.URL.Host, "github.com") {
		return nil, errors.New(`Get "` + req.URL.String() + `": dial tcp 140.82.121.5:443: i/o timeout`)
	}
	u, _ := req.URL.Parse(g.target.URL)
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = u.Scheme
	req2.URL.Host = u.Host
	return http.DefaultTransport.RoundTrip(req2)
}

func TestIsNetworkErrClassifiesTransportFailures(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{`Get "https://api.github.com/x": dial tcp 140.82.121.5:443: i/o timeout`, true},
		{"dial tcp: connection refused", true},
		{"net/http: TLS handshake timeout", true},
		{"net/http: request canceled (Client.Timeout exceeded while awaiting headers)", true},
		{"update: github returned status 404", false},
		{"update: github returned status 403", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsNetworkErr(errors.New(tc.msg)); got != tc.want {
			t.Errorf("IsNetworkErr(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestMirrorBaseEnvOverrides(t *testing.T) {
	t.Setenv("VAYU_UPDATE_MIRROR", "off")
	if got := mirrorBase(); got != "" {
		t.Errorf(`VAYU_UPDATE_MIRROR=off must disable the mirror, got %q`, got)
	}
	t.Setenv("VAYU_UPDATE_MIRROR", "https://mirror.example.com/")
	if got := mirrorBase(); got != "https://mirror.example.com" {
		t.Errorf("trailing slash must be trimmed, got %q", got)
	}
	t.Setenv("VAYU_UPDATE_MIRROR", "")
	if got := mirrorBase(); got != OfficialMirror {
		t.Errorf("empty env must fall back to the official mirror, got %q", got)
	}
}

func TestCheckLatestFallsBackToMirrorWhenGitHubUnreachable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/github/repos/johalputt/vayupress/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name":     "v9.9.9",
			"body":         "notes via mirror",
			"html_url":     "https://github.com/johalputt/vayupress/releases/tag/v9.9.9",
			"published_at": time.Now().Format(time.RFC3339),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("VAYU_UPDATE_MIRROR", srv.URL)
	client := &http.Client{Timeout: 5 * time.Second, Transport: githubDownTransport{target: srv}}

	rel, err := CheckLatest(context.Background(), client, "johalputt", "vayupress")
	if err != nil {
		t.Fatalf("CheckLatest through the chain: %v", err)
	}
	if rel.Version != "v9.9.9" {
		t.Errorf("version = %q, want v9.9.9", rel.Version)
	}
	if rel.Source != SourceMirror {
		t.Errorf("source = %q, want mirror", rel.Source)
	}
	if rel.CheckOnly {
		t.Error("a mirror answer carries the release files — CheckOnly must be false")
	}
}

func TestCheckLatestCDNFallbackWhenGitHubAndMirrorUnreachable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/packages/gh/johalputt/vayupress", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":       "gh",
			"repository": "johalputt/vayupress",
			"versions": []map[string]any{
				{"version": "3.17.63"},
				{"version": "3.17.62"},
				{"version": "3.18.0-rc1"},
				{"version": "not-a-version"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The mirror endpoint is a dead port: connection refused, fast.
	t.Setenv("VAYU_UPDATE_MIRROR", "http://127.0.0.1:1")
	client := &http.Client{Timeout: 5 * time.Second, Transport: githubDownTransport{target: srv}}

	rel, err := CheckLatest(context.Background(), client, "johalputt", "vayupress")
	if err != nil {
		t.Fatalf("CheckLatest through the CDN fallback: %v", err)
	}
	if rel.Version != "v3.17.63" {
		t.Errorf("version = %q, want v3.17.63 (highest stable; rc skipped)", rel.Version)
	}
	if rel.Source != SourceCDN {
		t.Errorf("source = %q, want cdn", rel.Source)
	}
	if !rel.CheckOnly {
		t.Error("a CDN answer cannot serve files — CheckOnly must be true")
	}
}

func TestApplyRefusesCheckOnlyReleaseWithHonestMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/packages/gh/johalputt/vayupress", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"versions": []map[string]any{{"version": "9.9.9"}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("VAYU_UPDATE_MIRROR", "http://127.0.0.1:1")
	client := &http.Client{Timeout: 5 * time.Second, Transport: githubDownTransport{target: srv}}

	opt := ApplyOptions{Current: "v1.0.0", DryRun: true, BinaryPath: "/should/not/be/touched"}
	_, err := ApplyVerified(context.Background(), client, "johalputt", "vayupress", opt, nil)
	if err == nil {
		t.Fatal("a CheckOnly release must not be applied")
	}
	if !strings.Contains(err.Error(), "9.9.9 is available") || !strings.Contains(err.Error(), "cannot reach GitHub") {
		t.Errorf("error should say the version exists but cannot be fetched, got: %v", err)
	}
}

func TestDownloadSourcedRetriesThroughMirror(t *testing.T) {
	const payload = "genuine release bytes"
	mux := http.NewServeMux()
	mux.HandleFunc("/download/github/johalputt/vayupress/releases/download/v9.9.9/vayupress", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("VAYU_UPDATE_MIRROR", srv.URL)
	client := &http.Client{Timeout: 5 * time.Second, Transport: githubDownTransport{target: srv}}

	got, err := downloadSourced(context.Background(), client,
		"https://github.com/johalputt/vayupress/releases/download/v9.9.9/vayupress")
	if err != nil {
		t.Fatalf("downloadSourced: %v", err)
	}
	if string(got) != payload {
		t.Errorf("bytes = %q, want the mirror's payload", got)
	}
}

func TestMirrorAssetURLMapping(t *testing.T) {
	mb := "https://updates.johal.in"
	cases := []struct{ url, want string }{
		{
			"https://github.com/johalputt/vayupress/releases/download/v9.9.9/vayupress",
			mb + "/download/github/johalputt/vayupress/releases/download/v9.9.9/vayupress",
		},
		{"https://objects.githubusercontent.com/x", ""},                    // not github.com
		{"https://github.com/johalputt/vayupress/releases/tag/v9.9.9", ""}, // not a download
	}
	for _, tc := range cases {
		if got := mirrorAssetURL(mb, tc.url); got != tc.want {
			t.Errorf("mirrorAssetURL(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
	if got := mirrorAssetURL("", "https://github.com/a/b/releases/download/v1/x"); got != "" {
		t.Errorf("an empty mirror base must map to empty, got %q", got)
	}
}

func TestHumanNetworkCheckMessageKeepsDetail(t *testing.T) {
	err := errors.New(`Get "https://api.github.com/x": dial tcp 140.82.121.5:443: i/o timeout`)
	msg := HumanNetworkCheckMessage(err)
	if !strings.Contains(msg, "not a broken install") {
		t.Error("the card must say the install is not broken")
	}
	if !strings.Contains(msg, "i/o timeout") {
		t.Error("the technical detail must survive for operators who want it")
	}
}

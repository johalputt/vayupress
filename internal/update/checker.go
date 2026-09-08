// SPDX-License-Identifier: Apache-2.0

// Package update implements VayuPress's secure, check-only + signature-verified
// self-update system. The HTTP layer is read-only (check for updates); the
// binary-apply path is CLI-only, mode-gated, opt-in, and requires Ed25519
// signature verification against a pinned public key (see apply.go).
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Release describes a single GitHub release.
type Release struct {
	Version   string // tag_name, e.g. "v1.1.0"
	Notes     string // body (changelog)
	URL       string // html_url
	Assets    []Asset
	Published time.Time
	// Source records which endpoint in the chain answered: SourceGitHub,
	// SourceMirror, or SourceCDN. Surfaced in the console so an operator can
	// see that their host's direct route to GitHub is unhealthy without having
	// to read a log.
	Source string
	// CheckOnly marks a Release whose metadata came from a source that cannot
	// serve the release FILES (the CDN fallback lists tags only). The apply
	// path refuses these with an honest message instead of a confusing
	// mid-download failure.
	CheckOnly bool
}

// Asset is a downloadable artifact attached to a release.
type Asset struct {
	Name        string
	DownloadURL string
	Size        int64
}

// ghRelease mirrors the subset of the GitHub releases API we consume.
type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

// AuthToken is an optional GitHub token (set from VAYU_UPDATE_TOKEN or
// GITHUB_TOKEN at the call site) that raises the API rate limit from 60 to 5000
// requests/hour. It is read-only — only the public releases API is queried.
var AuthToken string

// CheckLatest queries the GitHub releases API for owner/repo and returns the
// latest release. It uses the provided *http.Client (which should carry a
// timeout). There are NO global/network calls at package init.
//
// Robustness: GitHub's `releases/latest` 404s when the most recent release is a
// pre-release (or none is marked latest), and unauthenticated callers are capped
// at 60 requests/hour (a 403 with X-RateLimit-Remaining: 0). Both surfaced as a
// bare "unable to check". We now report rate limiting with a clear, actionable
// message and fall back to the full releases list when `latest` is unavailable.
func CheckLatest(ctx context.Context, client *http.Client, owner, repo string) (*Release, error) {
	if client == nil {
		return nil, fmt.Errorf("update: nil http client")
	}
	latestURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	rel, err := getRelease(ctx, client, latestURL)
	if err == nil {
		rel.Source = SourceGitHub
		return rel, nil
	}
	// Rate-limit errors are terminal — every other endpoint hits the same wall.
	if errors.Is(err, errRateLimited) {
		return nil, err
	}
	// GitHub ANSWERED (404 from `latest`, e.g. newest release is a pre-release):
	// the network is fine, so the existing list fallback is the right next step
	// and the mirror adds nothing but latency.
	if !IsNetworkErr(err) {
		rel2, err2 := latestFromList(ctx, client, owner, repo)
		if err2 != nil {
			if errors.Is(err2, errRateLimited) {
				return nil, err2
			}
			return nil, err
		}
		rel2.Source = SourceGitHub
		return rel2, nil
	}
	// GitHub is unreachable at the transport level. Fall through the chain:
	// the official mirror (full fidelity — same API JSON, files included),
	// then a metadata-only CDN listing. See endpoints.go for the guarantees.
	if mb := mirrorBase(); mb != "" {
		if rel2, merr := mirrorLatest(ctx, client, mb, owner, repo); merr == nil {
			return rel2, nil
		}
	}
	if rel3, jerr := jsdelivrLatest(ctx, client, owner, repo, false); jerr == nil {
		return rel3, nil
	}
	// Every layer failed: surface the original network error verbatim so the
	// console can classify it for the operator.
	return nil, err
}

// CheckLatestChannel is CheckLatest with an explicit release channel. When
// includePrerelease is true, GitHub pre-releases (the "development" channel) are
// considered too, so an operator can opt into the newest *unreleased* build;
// when false it is identical to CheckLatest and returns only stable releases.
// GitHub's `releases/latest` endpoint never returns a pre-release, so the
// development channel always consults the full releases list.
func CheckLatestChannel(ctx context.Context, client *http.Client, owner, repo string, includePrerelease bool) (*Release, error) {
	if !includePrerelease {
		return CheckLatest(ctx, client, owner, repo)
	}
	if client == nil {
		return nil, fmt.Errorf("update: nil http client")
	}
	rel, err := latestFromListChannel(ctx, client, owner, repo, true)
	if err == nil {
		rel.Source = SourceGitHub
		return rel, nil
	}
	if errors.Is(err, errRateLimited) {
		return nil, err
	}
	if IsNetworkErr(err) {
		// Same chain as the stable channel: mirror first, CDN last.
		if mb := mirrorBase(); mb != "" {
			if rel2, merr := mirrorReleasesList(ctx, client, mb, owner, repo, true); merr == nil {
				return rel2, nil
			}
		}
		if rel3, jerr := jsdelivrLatest(ctx, client, owner, repo, true); jerr == nil {
			return rel3, nil
		}
	}
	return nil, err
}

// errRateLimited marks a GitHub rate-limit (403/429) so callers can stop early.
var errRateLimited = errors.New("update: GitHub API rate limit reached (60 requests/hour for unauthenticated checks). Wait an hour and try again, or set VAYU_UPDATE_TOKEN to a GitHub token to raise the limit")

func githubGet(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("update: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vayupress-updater")
	if AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+AuthToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: request: %w", err)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || strings.Contains(strings.ToLower(resp.Header.Get("X-RateLimit-Resource")), "core") || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			return nil, errRateLimited
		}
	}
	return resp, nil
}

func decodeRelease(gr ghRelease) *Release {
	rel := &Release{Version: gr.TagName, Notes: gr.Body, URL: gr.HTMLURL, Published: gr.PublishedAt}
	for _, a := range gr.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, DownloadURL: a.BrowserDownloadURL, Size: a.Size})
	}
	return rel
}

func getRelease(ctx context.Context, client *http.Client, url string) (*Release, error) {
	resp, err := githubGet(ctx, client, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: github returned status %d", resp.StatusCode)
	}
	var gr ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, fmt.Errorf("update: decode: %w", err)
	}
	return decodeRelease(gr), nil
}

// latestFromList GETs the releases list and returns the newest non-draft,
// non-prerelease by semver — the fallback when `releases/latest` 404s.
func latestFromList(ctx context.Context, client *http.Client, owner, repo string) (*Release, error) {
	return latestFromListChannel(ctx, client, owner, repo, false)
}

// latestFromListChannel returns the newest non-draft release by semver. When
// includePrerelease is false, pre-releases are skipped (stable channel); when
// true they are eligible (development channel). GitHub returns the list
// newest-first, so on a semver tie the more recently published build wins.
func latestFromListChannel(ctx context.Context, client *http.Client, owner, repo string, includePrerelease bool) (*Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases?per_page=30", owner, repo)
	return latestFromListURL(ctx, client, url, includePrerelease)
}

// latestFromListURL is the list decode+pick shared by the GitHub endpoint and
// the mirror's relay of the same list.
func latestFromListURL(ctx context.Context, client *http.Client, listURL string, includePrerelease bool) (*Release, error) {
	resp, err := githubGet(ctx, client, listURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: github returned status %d", resp.StatusCode)
	}
	var list []struct {
		ghRelease
		Draft      bool `json:"draft"`
		Prerelease bool `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("update: decode: %w", err)
	}
	var best *Release
	for i := range list {
		if list[i].Draft || list[i].TagName == "" {
			continue
		}
		if list[i].Prerelease && !includePrerelease {
			continue
		}
		cand := decodeRelease(list[i].ghRelease)
		if best == nil || CompareVersions(cand.Version, best.Version) > 0 {
			best = cand
		}
	}
	if best == nil {
		if includePrerelease {
			return nil, fmt.Errorf("update: no releases found (including pre-releases)")
		}
		return nil, fmt.Errorf("update: no published releases found")
	}
	return best, nil
}

// CompareVersions returns -1, 0, or +1 comparing semver-ish versions. It
// tolerates a leading "v" and pre-release/build suffixes (which are stripped).
func CompareVersions(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

// UpdateAvailable reports whether latest is strictly newer than current.
func UpdateAvailable(current, latest string) bool {
	return CompareVersions(current, latest) < 0
}

// parseVersion extracts [major, minor, patch] from a version string, tolerating
// a leading "v" and ignoring any pre-release/build metadata.
func parseVersion(v string) [3]int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	// Drop pre-release / build metadata.
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			n = 0
		}
		out[i] = n
	}
	return out
}

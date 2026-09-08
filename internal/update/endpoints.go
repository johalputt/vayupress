// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/johalputt/vayupress/internal/logging"
)

// The release-endpoint chain: GitHub first, then the official mirror, then a
// metadata-only CDN — so a "check for updates" click survives a host whose
// network cannot reach GitHub at all.
//
// The shape of the problem: a self-hosted install on a mail-server IP range
// reported `dial tcp 140.82.121.5:443: i/o timeout` on every check. DNS
// answered, the local firewall allowed outbound, the box had no IPv6 — the
// provider's route to GitHub's edge was simply dead. GitHub-side blackholing
// of datacenter and mail-hosting ranges is common enough that VayuPress cannot
// treat "api.github.com is reachable" as an axiom, and an operator without a
// shell must never be asked to fix routing.
//
// Every layer after GitHub serves data that GitHub itself published, and every
// BYTE that reaches ApplyVerified still passes the release's Sigstore signature
// and checksum — a mirror is a relay, never a publisher. That is what makes an
// automatic fallback safe to ship: the worst a hostile mirror can do is serve
// bytes that are refused, not bytes that are installed.

// OfficialMirror is the project-operated pass-through for GitHub release
// traffic, served from a CDN edge (Cloudflare) that is reachable even when
// GitHub's own edges are not. It relays the releases API JSON and streams the
// release files; it cannot alter them undetected, because every install
// verifies the Sigstore signature over the bytes it downloads.
const OfficialMirror = "https://updates.johal.in"

// Release sources, recorded on Release.Source and shown in the console so an
// operator can see which path answered.
const (
	SourceGitHub   = "github"
	SourceMirror   = "mirror"
	SourceCDN      = "cdn"
	SourceFallback = "fallback"
)

// mirrorBase resolves the mirror to use: the VAYU_UPDATE_MIRROR override
// (self-hosters may point it at their own relay; "off" disables the fallback
// entirely) or the project's official mirror. An empty result means the
// mirror layer is switched off.
func mirrorBase() string {
	m := strings.TrimSpace(os.Getenv("VAYU_UPDATE_MIRROR"))
	if m == "" {
		return OfficialMirror
	}
	if strings.EqualFold(m, "off") {
		return ""
	}
	return strings.TrimRight(m, "/")
}

// networkErrFragments are the error fingerprints of "could not connect" — the
// class of failure a mirror can actually fix. An HTTP-level answer (404, 403,
// rate limit) means GitHub REACHED us, so retrying elsewhere for the same
// object would only add latency.
var networkErrFragments = []string{
	"i/o timeout", "connection refused", "connection reset", "connection closed",
	"no route to host", "network is unreachable", "network is down",
	"dial tcp", "dial udp", "TLS handshake timeout", "proxyconnect",
	"server misbehaving", "Client.Timeout", "context deadline exceeded",
	"host has no public address", "no public address to dial",
}

// IsNetworkErr reports whether err is a transport-level failure — the case a
// mirror fallback (and the console's plain-language card) exists for. Exported
// so the console classifies failures the same way the chain does.
func IsNetworkErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, frag := range networkErrFragments {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}

// mirrorLatest fetches the GitHub releases API JSON through the mirror's
// relay. The mirror answers with the same JSON shape GitHub does, so the
// normal decode path is reused unchanged.
func mirrorLatest(ctx context.Context, client *http.Client, mb, owner, repo string) (*Release, error) {
	u := mb + "/api/github/repos/" + owner + "/" + repo + "/releases/latest"
	rel, err := getRelease(ctx, client, u)
	if err != nil {
		return nil, err
	}
	rel.Source = SourceMirror
	logging.LogWarn("update", "GitHub unreachable — latest release answered by the official mirror (version "+rel.Version+")")
	return rel, nil
}

// mirrorReleasesList fetches the paginated releases list through the mirror
// (the development channel's source), preserving the semantics of
// latestFromListChannel.
func mirrorReleasesList(ctx context.Context, client *http.Client, mb, owner, repo string, includePre bool) (*Release, error) {
	u := mb + "/api/github/repos/" + owner + "/" + repo + "/releases?per_page=30"
	rel, err := latestFromListURL(ctx, client, u, includePre)
	if err != nil {
		return nil, err
	}
	rel.Source = SourceMirror
	logging.LogWarn("update", "GitHub unreachable — releases list answered by the official mirror (version "+rel.Version+")")
	return rel, nil
}

// jsdelivrLatest resolves the latest version through the jsDelivr data API —
// a CDN edge reachable even when both GitHub and the mirror are not. It can
// only supply the version TAG, never the release files, so the returned
// Release is marked CheckOnly: the console can say "an update exists" but the
// apply path must not pretend it can download from it.
func jsdelivrLatest(ctx context.Context, client *http.Client, owner, repo string, includePre bool) (*Release, error) {
	u := "https://data.jsdelivr.com/v1/packages/gh/" + owner + "/" + repo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vayupress-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: cdn status %d", resp.StatusCode)
	}
	var listing struct {
		Versions []struct {
			Version string `json:"version"`
			Tags    map[string]string `json:"tags"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return nil, fmt.Errorf("update: cdn decode: %w", err)
	}
	var best string
	for _, v := range listing.Versions {
		stable := !strings.Contains(strings.ToLower(v.Version), "-")
		if !includePre && !stable {
			continue
		}
		if best == "" || CompareVersions(v.Version, best) > 0 {
			best = v.Version
		}
	}
	if best == "" {
		return nil, errors.New("update: cdn listing has no usable version")
	}
	if !strings.HasPrefix(best, "v") && !strings.Contains(best, "-") {
		// Project tags carry the v prefix; keep the display consistent with
		// what GitHub would have answered.
		best = "v" + best
	}
	logging.LogWarn("update", "GitHub and the official mirror unreachable — latest version answered by the CDN fallback, metadata only (version "+best+")")
	return &Release{
		Version:   best,
		URL:       "https://github.com/" + owner + "/" + repo + "/releases/tag/" + best,
		Source:    SourceCDN,
		CheckOnly: true,
	}, nil
}

// mirrorAssetURL rewrites a github.com release-download URL into the mirror's
// streaming path. A URL that is not a github.com release download (an asset
// published on a different host, or an already-mirrored URL) maps to "".
func mirrorAssetURL(mb, rawURL string) string {
	if mb == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if !strings.EqualFold(u.Host, "github.com") {
		return ""
	}
	p := strings.TrimPrefix(u.Path, "/")
	if !strings.Contains(p, "/releases/download/") {
		return ""
	}
	return mb + "/download/github/" + p
}

// downloadSourced downloads a release file, retrying through the official
// mirror when the direct route dies at the transport level. Verification is
// NOT relaxed for mirror bytes: the caller checksums and signature-checks
// whatever comes back, exactly as it would for a direct download.
func downloadSourced(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	data, err := download(ctx, client, rawURL)
	if err == nil {
		return data, nil
	}
	mb := mirrorBase()
	if mb == "" || !IsNetworkErr(err) {
		return nil, err
	}
	murl := mirrorAssetURL(mb, rawURL)
	if murl == "" {
		return nil, err
	}
	logging.LogWarn("update", "direct download unreachable — retrying the release file via the official mirror ("+murl+")")
	started := time.Now()
	data, err = download(ctx, client, murl)
	if err == nil {
		logging.LogInfo("update", fmt.Sprintf("release file fetched via mirror in %s", time.Since(started).Round(time.Millisecond)))
	}
	return data, err
}

// HumanNetworkCheckMessage turns a raw transport error into the console's
// plain-language card. The technical detail is preserved — an operator who
// wants the truth can still read it — but the first sentence answers "is my
// install broken?" (no) and "what do I do?" (nothing, or retry later).
func HumanNetworkCheckMessage(err error) string {
	return "Your server could not reach GitHub or the VayuPress release mirror — this is your host's outbound network, not a broken install. " +
		"VayuOS retried automatically across several network paths before giving up. " +
		"You can check again in a few minutes; VayuOS also re-checks on its own every 6 hours and rings the update bell once a new release is reachable. " +
		"Technical detail: " + err.Error()
}

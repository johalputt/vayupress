// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/johalputt/vayupress/internal/logging"
)

// ApplyOptions configures a verified binary apply.
type ApplyOptions struct {
	Current    string
	DryRun     bool
	DBPath     string
	BackupDir  string
	BinaryPath string // path to the currently-running binary to replace (os.Executable())

	// IncludePrerelease opts into the development channel: GitHub pre-releases
	// (unreleased builds) become eligible for install, not just stable releases.
	// Verification is unchanged — checksum always, signature when a key is pinned.
	IncludePrerelease bool
}

// Guard injects a mode lookup so apply can refuse in unsafe modes.
type Guard struct {
	CurrentMode func() string
}

// PreflightMode refuses an apply when the runtime is in a mode that forbids
// mutating the binary (read-only, quarantined, maintenance). It is the subset of
// PreflightApply that the authenticated admin UI enforces: an operator's
// explicit, admin-role-checked click is itself the opt-in, so the env flag and a
// pinned key are not required there (verification still happens in
// ApplyVerified — checksum always, signature when a key is pinned).
func PreflightMode(currentMode string) error {
	switch strings.ToLower(strings.TrimSpace(currentMode)) {
	case "read-only", "readonly":
		return errors.New("update: apply refused — system mode is read-only")
	case "quarantined":
		return errors.New("update: apply refused — system mode is quarantined")
	case "maintenance":
		return errors.New("update: apply refused — system mode is maintenance")
	}
	return nil
}

// PreflightApply runs all safety gates and returns an error if apply must not
// proceed:
//   - VAYU_SELFUPDATE_ENABLED must be "true" (enabled==true)
//   - mode must not be read-only / quarantined / maintenance
//
// It no longer requires a pinned Ed25519 key. Requiring one made the CLI
// unusable in BOTH directions: without a key this refused, and with a key
// ApplyVerified demanded a ".sig" asset the release pipeline has never
// produced. Authenticity is the release's Sigstore signature, which needs no
// operator configuration.
//
// This is the strict gate used by the CLI; the admin UI uses PreflightMode. Both
// paths now verify the release's Sigstore signature unconditionally, so neither
// can apply an unauthentic binary — the flag that used to permit that is gone.
func PreflightApply(enabled bool, currentMode string) error {
	if !enabled {
		return errors.New("update: apply refused — set VAYU_SELFUPDATE_ENABLED=true to opt in")
	}
	return PreflightMode(currentMode)
}

// ApplyVerified downloads the release binary plus its .sig and .sha256, verifies
// the checksum AND the Ed25519 signature against the pinned public key, backs up
// the database, then atomically replaces the running binary. In DryRun it
// verifies everything but does NOT replace. It never restarts/execs the process;
// it returns the new version and prints restart instructions to the operator.
func ApplyVerified(ctx context.Context, client *http.Client, owner, repo string, opt ApplyOptions, st *Store) (string, error) {
	if client == nil {
		return "", fmt.Errorf("update: nil http client")
	}

	rel, err := CheckLatestChannel(ctx, client, owner, repo, opt.IncludePrerelease)
	if err != nil {
		return "", err
	}
	if !UpdateAvailable(opt.Current, rel.Version) {
		return "", fmt.Errorf("update: no newer release available (current=%s latest=%s)", opt.Current, rel.Version)
	}
	// The CDN fallback can only prove that a newer version EXISTS — it cannot
	// serve the release files. Refuse here with the honest path forward rather
	// than failing mid-download with a confusing "no binary asset" error.
	if rel.CheckOnly {
		return "", fmt.Errorf("update: %s is available, but this server cannot reach GitHub's download servers or the official mirror to fetch it. "+
			"This is the host's outbound network, not a broken install — retry later, or from a network that can reach GitHub", rel.Version)
	}

	// VERIFICATION POLICY (Section 5 audit).
	//
	// Authenticity is the Sigstore signature every release carries, pinned to the
	// release workflow's identity. It is ALWAYS required — there is no flag that
	// turns it off, because the previous design made the signature conditional on
	// an operator pinning a key and so gave the default install no authenticity
	// control at all. The checksum is still verified: it catches a truncated or
	// proxy-mangled download and produces a far clearer error than a signature
	// failure would.
	//
	// The Ed25519 path this replaces is GONE, not demoted to optional. It
	// required a "<binary>.sig" asset the release pipeline has never produced, so
	// pinning VAYU_RELEASE_PUBKEY — which the panel and docs both told operators
	// to do — made every update fail, while leaving it unset verified nothing.
	// Keeping it as an "optional extra" would have left that landmine armed
	// underneath release notes calling it optional.

	// The name of the file about to be overwritten is the strongest evidence
	// available about which asset is the binary; fall back to the repository name
	// when the caller has not resolved an install path (dry runs).
	wantName := strings.TrimSpace(filepath.Base(opt.BinaryPath))
	if wantName == "" || wantName == "." || wantName == string(filepath.Separator) {
		wantName = repo
	}
	binAsset := selectBinaryAsset(rel.Assets, runtime.GOOS, runtime.GOARCH, wantName)
	if binAsset == nil {
		return "", fmt.Errorf("update: release %s has no installable binary asset for %s/%s — "+
			"no attachment is named %q and none names this platform",
			rel.Version, runtime.GOOS, runtime.GOARCH, wantName)
	}
	sumAsset := selectChecksumAsset(rel.Assets, binAsset.Name)
	if sumAsset == nil {
		return "", fmt.Errorf("update: release %s is missing a .sha256 checksum for %s", rel.Version, binAsset.Name)
	}
	// No bundle, no install. A release that failed to sign is refused rather than
	// taken on its checksum, which is the whole point: an attacker who can publish
	// to the release channel can publish a matching checksum, and could otherwise
	// simply omit the signature to be waved through.
	bundleAsset := selectBundleAsset(rel.Assets, binAsset.Name)
	if bundleAsset == nil {
		return "", fmt.Errorf("update: release %s carries no signature for %s, so it cannot be "+
			"verified and will not be installed. Every genuine release is signed by the "+
			"project's release workflow; an unsigned one means the release did not complete "+
			"correctly, or did not come from the project", rel.Version, binAsset.Name)
	}
	// The second lock, resolved after the first so a release missing both is
	// reported against the primary control rather than this one.
	var sigAsset *Asset
	if ReleaseRequiresEd25519() {
		sigAsset = selectSidecar(rel.Assets, binAsset.Name, ".sig")
		if sigAsset == nil {
			return "", fmt.Errorf("update: release %s carries no Ed25519 signature for %s, "+
				"which this build requires in addition to the Sigstore signature",
				rel.Version, binAsset.Name)
		}
	}

	binData, err := downloadSourced(ctx, client, binAsset.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("update: download binary: %w", err)
	}
	// Turn the most confusing failure into a clear one: when a proxy or network
	// hiccup between this server and GitHub's download CDN returns an HTML/JSON
	// error page (or a truncated transfer) instead of the binary, the bytes hash
	// to something that will never match — surfacing as a cryptic "checksum
	// mismatch". Detect that here and say what actually happened, so the operator
	// knows it is a transport problem, not a corrupt or mismatched release.
	if why := binaryDownloadProblem(binData); why != "" {
		return "", fmt.Errorf("update: the release binary did not download correctly — %s. "+
			"This is a network/proxy problem between this server and GitHub's download CDN, not a checksum problem with the release itself. "+
			"Retry; if it persists, make sure the server can reach github.com and its release-download hosts "+
			"(release-assets.githubusercontent.com, objects.githubusercontent.com) outbound", why)
	}
	sumData, err := downloadSourced(ctx, client, sumAsset.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("update: download checksum: %w", err)
	}

	// Checksum must pass before any signature check or write. checksumForFile
	// tolerates both a per-binary ".sha256" ("<hex>  <file>") and a combined
	// SHA256SUMS listing (many files), picking the line for this binary.
	expectedHex := checksumForFile(sumData, binAsset.Name)
	if err := VerifyChecksum(binData, expectedHex); err != nil {
		return "", fmt.Errorf("%w — the %d bytes downloaded do not match the release's published SHA-256. "+
			"This normally means the download was corrupted or intercepted in transit (a proxy/CDN issue), not a bad release; retry the update", err, len(binData))
	}

	// THE AUTHENTICITY CHECK. Everything above proves the bytes arrived intact;
	// only this proves who made them.
	bundleData, err := downloadSourced(ctx, client, bundleAsset.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("update: download release signature: %w", err)
	}
	sigHex := ""
	if sigAsset != nil {
		sigData, derr := downloadSourced(ctx, client, sigAsset.DownloadURL)
		if derr != nil {
			return "", fmt.Errorf("update: download release key signature: %w", derr)
		}
		sigHex = string(sigData)
	}
	if err := verifyReleaseSignature(binData, bundleData, sigHex); err != nil {
		return "", err
	}

	if sigAsset != nil {
		logging.LogInfo("update", fmt.Sprintf(
			"verified release %s (checksum + Sigstore signature by %s + release signing key OK)",
			rel.Version, ReleaseSignerIdentity))
	} else {
		logging.LogInfo("update", fmt.Sprintf("verified release %s (checksum + Sigstore signature by %s OK)", rel.Version, ReleaseSignerIdentity))
	}

	// Authenticity is settled; now the question authenticity cannot answer. These
	// bytes are provably the ones the release published — that says nothing about
	// whether they are a program this machine can exec, and in the v3.16.86 outage
	// they were a ZIP archive that passed every check above.
	//
	// Deliberately after verification, so an attacker-supplied file is still
	// rejected as unauthentic first, and deliberately before DryRun returns, so a
	// dry run reports the problem instead of blessing it.
	if err := verifyExecutableImage(binData, runtime.GOOS, binAsset.Name); err != nil {
		return "", err
	}

	if opt.DryRun {
		logging.LogInfo("update", "dry-run — verification passed, binary NOT replaced")
		return rel.Version, nil
	}

	// Always back up the database before mutating the binary.
	backupPath := ""
	if opt.DBPath != "" {
		bp, berr := CreateBackup(opt.DBPath, opt.BackupDir)
		if berr != nil {
			return "", fmt.Errorf("update: backup failed, aborting apply: %w", berr)
		}
		backupPath = bp
		logging.LogInfo("update", "database backed up to "+backupPath)
	}

	if opt.BinaryPath == "" {
		return "", fmt.Errorf("update: empty binary path — cannot replace")
	}
	if err := atomicReplace(opt.BinaryPath, binData); err != nil {
		return "", err
	}

	logging.LogInfo("update", fmt.Sprintf("binary replaced: %s → %s (old kept at %s.bak)", opt.Current, rel.Version, opt.BinaryPath))
	_ = backupPath // surfaced by caller via history record
	return rel.Version, nil
}

// ResolveInstallPath returns the real on-disk path of the binary to replace,
// following symlinks. An enterprise deployment runs VayuPress from a
// service-owned, writable directory (e.g. /var/lib/vayupress/bin/vayupress) and
// exposes /usr/local/bin/vayupress as a convenience symlink to it. In that
// layout the atomic swap must target the resolved real file in the writable
// directory — replacing the symlink itself would fail on a read-only /usr and
// would not update the running binary. A "(deleted)" marker (left after a prior
// swap unlinked the old inode) is stripped first; on any error the input path is
// returned unchanged so single-file layouts behave exactly as before.
func ResolveInstallPath(execPath string) string {
	p := strings.TrimSuffix(strings.TrimSpace(execPath), " (deleted)")
	if p == "" {
		return execPath
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}

// atomicReplace writes data to a temp file in the same dir, makes it executable,
// keeps the old binary as <target>.bak, then os.Rename over the target. Falls
// back to copy+chmod if rename fails (e.g. cross-device).
func atomicReplace(target string, data []byte) error {
	// Last line of defence, deliberately duplicated from the apply path: nothing
	// in this package may write a non-executable over the running binary, whatever
	// route it took to get here.
	if err := verifyExecutableImage(data, runtime.GOOS, filepath.Base(target)); err != nil {
		return err
	}
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".vayupress-update-*")
	if err != nil {
		return fmt.Errorf("update: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if successfully renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("update: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("update: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("update: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("update: chmod temp: %w", err)
	}

	// Keep the old binary as a .bak rollback artifact (best-effort copy).
	if err := copyFile(target, target+".bak", 0o755); err != nil {
		logging.LogError("update", "could not back up old binary", err.Error())
	}

	if err := os.Rename(tmpName, target); err != nil {
		// Cross-device or other rename failure → fall back to copy+chmod.
		if cerr := copyFile(tmpName, target, 0o755); cerr != nil {
			return fmt.Errorf("update: rename failed (%v) and copy fallback failed: %w", err, cerr)
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vayupress-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20)) // 512 MiB cap
}

// metadataAssetSuffixes lists the non-executable artefacts that are commonly
// attached to a release alongside the binary (checksums, signatures, SBOMs,
// notes). None of these may ever be mistaken for the binary to install.
var metadataAssetSuffixes = []string{
	".sha256", ".sha512", ".sha1", ".md5",
	".sig", ".asc", ".pem", ".pub", ".cert", ".crt",
	".bundle", ".sbom", ".spdx", ".json", ".cdx",
	".txt", ".md", ".sum",
}

// archiveAssetSuffixes lists container formats. A release may legitimately carry
// several of these beside the binary — helper bundles, a packaged website, an
// SBOM archive — and NONE of them is a thing the operating system can execute.
//
// This list exists because its absence took a production site down. v3.16.86
// attached a packaged marketing site as `selfhosted-site.zip`; `.zip` was not a
// recognised sidecar, so the zip entered the candidate pool as a possible
// "binary", and see the note on selectBinaryAsset for what happened next.
var archiveAssetSuffixes = []string{
	".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2",
	".tar.zst", ".gz", ".xz", ".bz2", ".zst", ".7z", ".rar",
	".deb", ".rpm", ".apk", ".aab", ".dmg", ".pkg", ".msi", ".msix", ".snap",
	".html", ".htm", ".yml", ".yaml", ".toml", ".xml", ".csv", ".log", ".pdf",
}

// isMetadataAsset reports whether name is a release sidecar rather than the
// executable itself.
func isMetadataAsset(name string) bool {
	n := strings.ToLower(name)
	for _, s := range metadataAssetSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// isArchiveAsset reports whether name is a container/document rather than an
// executable image.
func isArchiveAsset(name string) bool {
	n := strings.ToLower(name)
	for _, s := range archiveAssetSuffixes {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// archAliases maps a Go GOARCH to the substrings release artefacts commonly use
// for the same architecture, so a download matches whatever naming a release
// adopts.
var archAliases = map[string][]string{
	"amd64":   {"amd64", "x86_64", "x64"},
	"arm64":   {"arm64", "aarch64"},
	"arm":     {"armv7", "armv6", "armhf", "arm"},
	"386":     {"386", "i386", "x86"},
	"ppc64le": {"ppc64le"},
	"s390x":   {"s390x"},
	"riscv64": {"riscv64"},
}

// selectBinaryAsset chooses the release asset that is the executable for the
// running platform. It discards every checksum/signature/SBOM sidecar and every
// archive or document, prefers an asset named exactly like the binary being
// replaced, and only then — when a release ships builds for several platforms —
// falls back to matching the running GOOS and GOARCH in the asset name.
//
// WHY THE EXACT-NAME RULE IS FIRST, from an outage this caused.
//
// The previous version of this function ended in `return cands[0]`: when no
// candidate name carried a platform hint, it installed whichever asset the
// GitHub API happened to list first. The GitHub API sorts release assets
// ALPHABETICALLY BY NAME. VayuPress ships its binary as a bare `vayupress`, with
// no OS or arch in the name, so nothing ever matched on platform and the choice
// was always `cands[0]` — correct only because `vayupress` sorted ahead of
// `vayuprovision-helpers.tar.gz` and `vayushield-agent.tar.gz`. That is luck, not
// logic, and the whole selection rested on it.
//
// v3.16.86 attached `selfhosted-site.zip`. It sorts before every `vayu*` name,
// `.zip` was not a recognised sidecar, and so it became cands[0] — and its
// `.sha256` sibling was right there on the release, so the checksum verified
// against the wrong file and reported success. A 500 KB zip was written over the
// service binary, chmod 0755. The unit could not exec it, nothing bound the
// port, and every request to the site returned 502 until the operator restored
// the `.bak`. The update was reproducible: every retry installed the zip again.
//
// So: the name is matched, never assumed, and a candidate that cannot possibly
// be an executable is not a candidate. `verifyExecutableImage` is the backstop
// that catches this class of mistake even when selection goes wrong again.
func selectBinaryAsset(assets []Asset, goos, goarch, wantName string) *Asset {
	cands := make([]*Asset, 0, len(assets))
	for i := range assets {
		if isMetadataAsset(assets[i].Name) || isArchiveAsset(assets[i].Name) {
			continue
		}
		cands = append(cands, &assets[i])
	}
	if len(cands) == 0 {
		return nil
	}

	// The binary being replaced is called something. A release that ships an
	// asset by exactly that name has answered the question, and no heuristic
	// below should get a vote.
	if want := strings.ToLower(strings.TrimSpace(wantName)); want != "" {
		for _, a := range cands {
			n := strings.ToLower(a.Name)
			if n == want || n == want+".exe" {
				return a
			}
		}
	}

	if len(cands) == 1 {
		return cands[0]
	}

	wantArch := archAliases[goarch]
	if len(wantArch) == 0 {
		wantArch = []string{goarch}
	}
	var osOnlyMatch *Asset
	for _, a := range cands {
		n := strings.ToLower(a.Name)
		if goos != "" && !strings.Contains(n, goos) {
			continue
		}
		if osOnlyMatch == nil {
			osOnlyMatch = a
		}
		for _, al := range wantArch {
			if strings.Contains(n, al) {
				return a // exact OS + arch match
			}
		}
	}
	if osOnlyMatch != nil {
		return osOnlyMatch // right OS, arch not encoded in the name
	}
	// Several candidates, none named after this binary and none naming this
	// platform. There is no evidence here, only an ordering — and taking the
	// first one is precisely what installed a zip over a live service binary.
	// Refuse and say so; a failed update the operator can read beats a
	// successful one that replaces the binary with the wrong file.
	return nil
}

// selectChecksumAsset finds the .sha256 file that verifies the chosen binary.
// It prefers an exact "<binary>.sha256" sibling and otherwise falls back to the
// sole .sha256 asset when a release ships just one.
func selectChecksumAsset(assets []Asset, binaryName string) *Asset {
	return selectSidecar(assets, binaryName, ".sha256")
}

// selectSidecar returns the asset named "<binaryName><suffix>" if present, else
// the only asset carrying suffix when a release ships exactly one.
func selectSidecar(assets []Asset, binaryName, suffix string) *Asset {
	want := strings.ToLower(binaryName) + suffix
	var sole *Asset
	count := 0
	for i := range assets {
		n := strings.ToLower(assets[i].Name)
		if n == want {
			return &assets[i]
		}
		if strings.HasSuffix(n, suffix) {
			sole = &assets[i]
			count++
		}
	}
	if count == 1 {
		return sole
	}
	return nil
}

// checksumForFile extracts the SHA-256 hex for binaryName from a checksum file.
// It accepts both a per-binary ".sha256" ("<hex>  <file>", the format produced by
// `sha256sum <file>`) and a combined listing (many "<hex>  <file>" lines, e.g.
// SHA256SUMS / checksums.txt): with several lines it returns the hash on the line
// whose filename column matches the binary; with one line it returns its hash.
func checksumForFile(sumData []byte, binaryName string) string {
	base := strings.ToLower(binaryName)
	firstTok := ""
	for _, ln := range strings.Split(string(sumData), "\n") {
		fields := strings.Fields(strings.TrimSpace(ln))
		if len(fields) == 0 {
			continue
		}
		if firstTok == "" {
			firstTok = fields[0]
		}
		if len(fields) >= 2 {
			// The filename column may be "*name" (binary mode), "name", or a path.
			fn := strings.ToLower(strings.TrimPrefix(fields[len(fields)-1], "*"))
			if fn == base || strings.HasSuffix(fn, "/"+base) {
				return fields[0]
			}
		}
	}
	return firstTok
}

// binaryDownloadProblem returns a human-readable reason when the downloaded
// "binary" is obviously not a VayuPress executable — an empty response, or an
// HTML/JSON error page from a proxy/CDN — else "". It lets the updater report a
// transport failure as such instead of a cryptic checksum error. (A subtly
// truncated-but-binary transfer still fails the checksum, whose error now says
// so.)
func binaryDownloadProblem(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(data) == 0:
		return "the download was empty (0 bytes)"
	case bytes.HasPrefix(trimmed, []byte("<")) || bytes.HasPrefix(trimmed, []byte("{")) || bytes.HasPrefix(trimmed, []byte("[")):
		return fmt.Sprintf("the download returned a %d-byte HTML/JSON page, not a binary", len(data))
	}
	return ""
}

// executableMagic maps a GOOS to the leading bytes its loader requires. Anything
// else, whatever its name and whatever its checksum says, is not a program this
// machine can run.
//
// Mach-O carries four variants (32/64-bit, each in both byte orders) plus the
// universal "fat" container, so darwin lists all five.
var executableMagic = map[string][][]byte{
	"linux":     {{0x7f, 'E', 'L', 'F'}},
	"freebsd":   {{0x7f, 'E', 'L', 'F'}},
	"openbsd":   {{0x7f, 'E', 'L', 'F'}},
	"netbsd":    {{0x7f, 'E', 'L', 'F'}},
	"dragonfly": {{0x7f, 'E', 'L', 'F'}},
	"solaris":   {{0x7f, 'E', 'L', 'F'}},
	"illumos":   {{0x7f, 'E', 'L', 'F'}},
	"darwin": {
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, // universal binary
	},
	"windows": {{'M', 'Z'}},
}

// verifyExecutableImage refuses to install bytes the operating system could not
// possibly execute, and names what arrived instead.
//
// THIS IS THE GATE THAT WAS MISSING. The updater verified a SHA-256 and an
// Ed25519 signature and then wrote the result over the service binary — proving
// the file was intact and authentic, never that it was a program. When asset
// selection picked a release's packaged website instead of the binary, both
// checks passed on the zip (its own .sha256 was published beside it) and the
// install "succeeded". The site returned 502 until the operator restored the
// backup by hand, and every retry did the same thing again.
//
// Checksums answer "are these the bytes the release published". They cannot
// answer "are these bytes the program", and nothing else was asking.
//
// An unknown GOOS returns nil rather than guessing: refusing to update on a
// platform whose format is not listed here would be a worse failure than the one
// being prevented.
func verifyExecutableImage(data []byte, goos, assetName string) error {
	magics, known := executableMagic[goos]
	if !known {
		return nil
	}
	for _, m := range magics {
		if bytes.HasPrefix(data, m) {
			return nil
		}
	}
	return fmt.Errorf(
		"update: refusing to install %q — it is not an executable for %s (%s). "+
			"The release attachment chosen for this platform is not the program; "+
			"the running binary has been left untouched and this install is unchanged",
		assetName, goos, describeNonExecutable(data))
}

// describeNonExecutable names the format that turned up, so the log says "a ZIP
// archive" rather than "wrong magic bytes".
func describeNonExecutable(data []byte) string {
	switch {
	case len(data) == 0:
		return "it is empty"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return fmt.Sprintf("it is a %d-byte ZIP archive", len(data))
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return fmt.Sprintf("it is a %d-byte gzip archive", len(data))
	case bytes.HasPrefix(data, []byte("ustar")), len(data) > 262 && bytes.HasPrefix(data[257:], []byte("ustar")):
		return fmt.Sprintf("it is a %d-byte tar archive", len(data))
	case bytes.HasPrefix(data, []byte("%PDF")):
		return fmt.Sprintf("it is a %d-byte PDF", len(data))
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("<")):
		return fmt.Sprintf("it is a %d-byte HTML/XML document", len(data))
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")), bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")):
		return fmt.Sprintf("it is a %d-byte JSON document", len(data))
	case bytes.HasPrefix(data, []byte("#!")):
		return fmt.Sprintf("it is a %d-byte shell script", len(data))
	}
	return fmt.Sprintf("it is %d bytes of some other format", len(data))
}

// RestartInstructions returns operator guidance after a successful apply.
func RestartInstructions(newVersion string) string {
	return fmt.Sprintf(
		"VayuPress %s installed. The running process was NOT restarted.\n"+
			"Restart via your service manager to activate, e.g.:\n"+
			"  sudo systemctl restart vayupress\n"+
			"Rollback (if needed): move <binary>.bak back over the binary, then restart.",
		newVersion)
}

// verifyReleaseSignature runs EVERY authenticity check a release must pass, in
// one place, so a caller cannot satisfy one lock and skip the other.
//
// Sigstore is checked first because it is the primary control and the one every
// build enforces; the Ed25519 signature is an additional lock that applies when
// this build pins a key. A release failing either is refused.
//
// A package-level variable purely so tests can drive the stages AFTER it with a
// synthetic release, since no fixture can hold a genuine Sigstore signature. It
// is deliberately UNEXPORTED and absent from ApplyOptions: nothing outside this
// package can reach it, so it cannot become the opt-out AllowUnsigned was.
// TestAReleaseWithAnUnreadableSignatureIsRefused drives the real function end to
// end, so substituting it elsewhere cannot hide a regression here.
var verifyReleaseSignature = func(artifact, bundleJSON []byte, sigHex string) error {
	if err := VerifyReleaseBundle(artifact, bundleJSON); err != nil {
		return err
	}
	if ReleaseRequiresEd25519() {
		return verifyReleaseEd25519(artifact, sigHex)
	}
	return nil
}

// selectBundleAsset finds the Sigstore bundle proving who built the binary.
//
// Exact sibling only — no "sole asset with this suffix" fallback like the
// checksum and signature selectors have. Those fall back because a release
// shipping one checksum for one binary is unambiguous. A bundle is different:
// this release attaches bundles for the helper archives and the SBOM too, so
// "the only .cosign.bundle" would silently pair the binary with a signature over
// something else, and that pairing is exactly what an attacker wants.
func selectBundleAsset(assets []Asset, binaryName string) *Asset {
	want := strings.ToLower(binaryName) + ".cosign.bundle"
	for i := range assets {
		if strings.ToLower(assets[i].Name) == want {
			return &assets[i]
		}
	}
	return nil
}

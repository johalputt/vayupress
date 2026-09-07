// SPDX-License-Identifier: Apache-2.0

package update

// releasekey.go — the second, independent signature over a release.
//
// Sigstore (cosign.go) proves the release came from this project's release
// workflow. It is enforced on every install and needs no configuration. This
// adds a second lock with a DIFFERENT key custody model, so that compromising
// one does not open the door:
//
//	Sigstore   — an attacker must be able to run the real release workflow on
//	             the real branch. There is no long-lived secret to steal, and
//	             every signature is written to a public transparency log, so a
//	             malicious release is permanently recorded.
//	Ed25519    — an attacker must additionally hold a private key that lives
//	             only in the release runner's secret store and never appears in
//	             the repository, the artifacts, or any log.
//
// Holding the workflow identity does not yield the key, and holding the key
// does not let you publish under the workflow identity. Both are required.
//
// WHY THIS IS A COMPILED-IN CONSTANT AND NOT AN ENVIRONMENT VARIABLE
//
// It used to be VAYU_RELEASE_PUBKEY, read from the environment, and that shape
// is exactly what failed. Unset — which was every default install — meant no
// signature was checked at all. Set, as the documentation instructed, meant the
// updater demanded a ".sig" asset the pipeline had never produced and every
// update failed. An operator-configurable control protects only the operators
// who already knew, and in this case it protected nobody while breaking the
// careful ones.
//
// Compiled in, the policy is identical on every install, cannot be switched off
// by anyone who reaches the environment, and travels with the binary the updater
// itself delivers.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// releaseEd25519PubKey is the hex-encoded public half of the release signing
// key, or empty when no second signature is in force.
//
// EMPTY IS AN HONEST STATE, NOT A DISABLED CONTROL. It means this build predates
// the project publishing an Ed25519 signature, so there is nothing to check
// against and Sigstore alone is enforced. It is deliberately NOT a way to turn
// verification off: the moment a key is compiled in, ReleaseRequiresEd25519
// reports true and a release without a valid signature is refused — there is no
// intermediate state where a key is present and the check is skipped.
//
// To put a key in force:
//
//  1. Generate a keypair on a trusted machine. The private half never enters
//     this repository, any artifact, or any log.
//  2. Store the private half in the release runner's secret store as
//     VAYU_RELEASE_SIGNING_KEY.
//  3. Paste the public half here and ship a release. From that release onward
//     every install verifies both signatures.
//
// Rotation is the same three steps: installs running an older binary keep
// verifying against the older key until they update, which is why the key is
// changed in a release rather than out of band.
const releaseEd25519PubKey = "d644670c592630d755d62270c15762702afdd3adb4bd0ef3c9c9fe8d6e3e2454"

// ReleaseRequiresEd25519 reports whether this build enforces the second
// signature. It exists so the panel can state which controls are actually in
// force rather than describing an aspiration — the failure this section was
// opened to fix was a page claiming a check that was not running.
func ReleaseRequiresEd25519() bool { return strings.TrimSpace(releaseEd25519PubKey) != "" }

// verifyReleaseEd25519 checks sigHex over the SHA-256 digest of data against the
// compiled-in release key.
//
// The digest is signed rather than the whole artifact so a release binary can be
// verified without holding forty megabytes twice, and it matches what the
// pipeline signs.
func verifyReleaseEd25519(data []byte, sigHex string) error {
	return verifyEd25519Against(releaseEd25519PubKey, data, sigHex)
}

// verifyEd25519Against is the check with the key as a parameter.
//
// Split out so the failure modes of a BAD pin are reachable from a test. The pin
// itself is a compile-time constant — correctly, since that is what stops anyone
// changing it at runtime — but a constant cannot be varied, and a branch no test
// can reach is a branch nobody has seen work. The earlier shape left the
// malformed-pin path covered by a skip message that claimed coverage elsewhere
// and there was no elsewhere.
func verifyEd25519Against(pubKeyHex string, data []byte, sigHex string) error {
	key := strings.TrimSpace(pubKeyHex)
	if key == "" {
		return errors.New("update: no release signing key is compiled into this build")
	}
	pub, err := hex.DecodeString(key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		// A malformed pin is a build defect, and failing closed is the only safe
		// reading: the alternative silently drops the control this file exists for.
		return fmt.Errorf("update: the compiled-in release signing key is malformed, so "+
			"releases cannot be verified against it (%d bytes)", len(pub))
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("update: the release's Ed25519 signature is malformed")
	}
	digest := sha256.Sum256(data)
	if !ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig) {
		return errors.New("update: the release's Ed25519 signature does not match this " +
			"project's release signing key")
	}
	return nil
}

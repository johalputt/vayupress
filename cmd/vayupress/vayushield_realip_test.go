// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// "Real visitor IP" was the longest-standing posture row with no button.
//
// It names a live fault — every per-IP control metering the edge instead of the
// reader — and then handed it back to the operator as homework. That is the
// exact defect the remediation section exists to stop, and this row was the one
// example of it left.

func TestTheRealIPFindingHasARemediation(t *testing.T) {
	fix, ok := shieldFixes["realip"]
	if !ok {
		t.Fatal("the Real visitor IP posture row still has no fix, so the panel reports a live " +
			"fault it cannot act on")
	}
	// Every filename must be a constant in the table, never derived. This is the
	// property the surrounding code is explicit about: the caller's string is only
	// ever a lookup KEY.
	for name, got := range map[string]string{
		"Flag": fix.Flag, "State": fix.State, "Reason": fix.Reason,
	} {
		if !strings.HasPrefix(got, "realip.") {
			t.Errorf("%s = %q, want a realip.* constant", name, got)
		}
	}
	if fix.Cap != "realip=1" {
		t.Errorf("Cap = %q — an older helper must get no button rather than a button that writes "+
			"a flag nothing will ever read", fix.Cap)
	}
	// Registered is not rendered. The row must exist on the page, and it must be
	// wired into the section body rather than merely being renderable.
	row := shieldFixRow("realip")
	if !strings.Contains(row, "Real visitor IP") {
		t.Errorf("shieldFixRow(\"realip\") does not render the finding:\n%s", row)
	}
	if !strings.Contains(readSourceFile(t, "vayushield_hardening.go"), `shieldFixRow("realip")`) {
		t.Error("the row is renderable but the hardening section never calls it, so it appears nowhere")
	}
}

// The helper has to advertise the capability, or the panel renders a button that
// writes a flag no agent reads — which looks to the operator exactly like a fix
// that silently did nothing.
func TestTheAgentAdvertisesAndHandlesRealIP(t *testing.T) {
	agent := readDeployFile(t, "vayushield-agent.sh")
	if !strings.Contains(agent, "realip=1") {
		t.Fatal("the agent does not advertise realip=1, so the button never appears")
	}
	if !strings.Contains(agent, "reconcile_realip()") {
		t.Fatal("the agent advertises realip=1 and has no reconciler for it")
	}
	// Advertised, defined — and actually called. A reconciler that exists but is
	// not in the poll loop is the same outage with more code. Slice the poll
	// loop's function body out with the same helper the other tests use; an
	// unguarded strings.Index here used to panic (slice from -1) whenever the
	// marker drifted, instead of reporting the drift as a failure.
	loop := shellFuncBody(agent, "run_agent")
	if loop == "" {
		t.Fatal("the agent has no run_agent poll loop, so nothing would ever reconcile")
	}
	if !strings.Contains(loop, "reconcile_realip") {
		t.Error("reconcile_realip is defined but never called from the poll loop")
	}
}

// Nothing the unprivileged web app can write may reach an nginx file. The ranges
// must come from the root-owned list the firewall script populates, and the
// agent must not fetch or accept them from anywhere else.
func TestRealIPRangesComeFromTheRootOwnedListOnly(t *testing.T) {
	agent := readDeployFile(t, "vayushield-agent.sh")
	body := shellFuncBody(agent, "reconcile_realip")
	if body == "" {
		t.Fatal("reconcile_realip not found")
	}
	if !strings.Contains(body, "CDN_ALLOW_FILE") {
		t.Error("the reconciler does not read the root-owned range list")
	}
	for _, forbidden := range []string{"curl", "wget", "$(cat ${CONTROL_DIR}", "realip.ranges"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("reconcile_realip uses %q — a range that the panel or the network can influence "+
				"must never reach an nginx file", forbidden)
		}
	}
}

// This file lands in conf.d, where a malformed line does not break one vhost —
// it stops nginx loading at all. So anything that is not a well-formed CIDR must
// be dropped before it is written, and an empty result must leave nginx alone.
func TestRealIPRefusesToWriteAnythingThatIsNotACIDR(t *testing.T) {
	body := shellFuncBody(readDeployFile(t, "vayushield-agent.sh"), "reconcile_realip")
	if !strings.Contains(body, "*[!0-9a-fA-F.:/]*") {
		t.Error("no character filter on the range list. This file sits in conf.d, so one malformed " +
			"line takes the whole web server down rather than one vhost")
	}
	if !strings.Contains(body, `*/*) ;;`) {
		t.Error("a bare address with no prefix length is accepted; set_real_ip_from wants a CIDR")
	}
	if !strings.Contains(body, `[ "$n" -eq 0 ]`) {
		t.Error("an empty range list still rewrites the config, so a bad fetch silently replaces " +
			"working config with a file that resolves nothing")
	}
	// And a rejected config must be rolled back, not left in place.
	if !strings.Contains(body, "nginx_try_reload") {
		t.Error("the config is written without validating and reloading through the helper that " +
			"restores the previous file when nginx refuses it")
	}
}

// The explanation an operator reads before pressing must say what is actually
// wrong today, not merely name the setting.
func TestTheRealIPExplanationNamesTheConsequence(t *testing.T) {
	fix := shieldFixes["realip"]
	low := strings.ToLower(fix.Explain)
	for _, want := range []string{"metering your edge", "one abuser", "busy minute"} {
		if !strings.Contains(low, strings.ToLower(want)) {
			t.Errorf("the explanation never mentions %q, so it names a setting rather than the "+
				"failure the operator is living with", want)
		}
	}
}

// readDeployFile loads a shipped deploy artefact, so these tests read what
// actually ships rather than a copy that can drift from it.
func readDeployFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../deploy/" + name)
	if err != nil {
		t.Fatalf("read deploy/%s: %v", name, err)
	}
	return string(b)
}

// shellFuncBody returns the body of a shell function defined as `name() {`,
// ending at the first line that is a bare closing brace.
func shellFuncBody(src, name string) string {
	start := strings.Index(src, name+"() {")
	if start < 0 {
		return ""
	}
	rest := src[start:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}

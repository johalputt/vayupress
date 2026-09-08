// SPDX-License-Identifier: Apache-2.0

package safefetch

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicIPsPrefersV6AndFiltersPrivate(t *testing.T) {
	ips := []net.IPAddr{
		{IP: net.ParseIP("140.82.121.5")},        // public v4
		{IP: net.ParseIP("192.168.1.10")},        // private — filtered
		{IP: net.ParseIP("2606:50c0:8000::153")}, // public v6
		{IP: net.ParseIP("169.254.169.254")},     // metadata — filtered
	}
	got := publicIPs(ips)
	if len(got) != 2 {
		t.Fatalf("publicIPs = %v, want 2 public addresses", got)
	}
	if got[0].To4() != nil {
		t.Errorf("first candidate = %v, want the v6 address first (RFC 8305)", got[0])
	}
	if got[1].To4() == nil {
		t.Errorf("second candidate = %v, want the v4 address second", got[1])
	}
}

func TestDialRacingSkipsADeadAddress(t *testing.T) {
	// The first candidate dials a port with nothing listening on 127.0.0.1 —
	// refused immediately — while the real listener sits on 127.0.0.2. The
	// old "first address only" dialer returned the refusal; racing must
	// reach the second address.
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer inner.Close()
	addr := inner.Listener.Addr().(*net.TCPAddr)
	dead := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: addr.Port}

	ips := []net.IP{dead.IP, addr.IP}
	if strings.EqualFold(addr.IP.String(), "127.0.0.1") {
		t.Skip("listener is on 127.0.0.1; the dead/alive split needs a second loopback address")
	}

	base := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialRacing(context.Background(), base, ips, itoa(addr.Port))
	if err != nil {
		t.Fatalf("dialRacing should have reached the live address: %v", err)
	}
	conn.Close()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestDohPermittedRespectsTorAndOperatorSwitch(t *testing.T) {
	t.Setenv("VAYU_DNS_FALLBACK", "")
	if !dohPermitted() {
		t.Error("DoH should be permitted by default")
	}
	t.Setenv("VAYU_DNS_FALLBACK", "off")
	if dohPermitted() {
		t.Error("VAYU_DNS_FALLBACK=off must disable the DoH fallback too — it is an off-box DNS query")
	}
	t.Setenv("VAYU_DNS_FALLBACK", "")
	SetBlockClearnetEgress(true)
	defer SetBlockClearnetEgress(false)
	if dohPermitted() {
		t.Error("a Tor Space must never issue a clearnet DoH query (ADR-0141)")
	}
}

func TestDohLookupIPsFiltersAnswers(t *testing.T) {
	// The parser is fed a hostile answer through a stub server replacing the
	// endpoints: private addresses must be filtered, public kept, and each
	// query type answered in kind. The production dohClient refuses loopback
	// destinations by design, so the parser test swaps in a plain transport.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "28" { // AAAA query — answer empty
			_, _ = w.Write([]byte(`{"Answer":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"Answer":[{"name":"api.github.com.","type":1,"data":"140.82.121.5"},{"name":"api.github.com.","type":1,"data":"192.168.0.9"},{"name":"api.github.com.","type":1,"data":"169.254.169.254"}]}`))
	}))
	defer stub.Close()
	savedEndpoints := dohEndpoints
	dohEndpoints = []string{stub.URL}
	savedClient := dohClient
	dohClient = &http.Client{Timeout: 5 * time.Second, Transport: http.DefaultTransport}
	defer func() {
		dohEndpoints = savedEndpoints
		dohClient = savedClient
	}()

	ips, err := dohLookupIPs(context.Background(), "api.github.com")
	if err != nil {
		t.Fatalf("dohLookupIPs: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "140.82.121.5" {
		t.Fatalf("ips = %v, want only the public 140.82.121.5", ips)
	}
}

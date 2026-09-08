// SPDX-License-Identifier: Apache-2.0

package safefetch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/johalputt/vayupress/internal/logging"
)

// The resilient dialer: racing across every public address the resolver
// offers, with DNS-over-HTTPS as the last resort.
//
// WHY. A self-hosted box reported `dial tcp 140.82.121.5:443: i/o timeout` on
// every update check. DNS worked, the local firewall allowed outbound, and the
// box was IPv4-only — the provider's route to that one GitHub edge was black-
// holed. The old dialer tried exactly the first address the resolver returned
// and gave up, so a single dead edge became "updates are broken" for the whole
// install. Nothing on the box could fix it, and asking for a shell is exactly
// the answer this project rules out for operators.
//
// Two layers, both still fail-closed:
//
//  1. dialRacing — try EVERY public address (v6 first, RFC 8305 order), each
//     with the configured dial timeout, staggered 250ms apart; the first
//     connection to complete wins and the rest are cancelled. Same addresses
//     the old code trusted, just not one of them.
//  2. DoH re-resolution (opt-in) — when every address fails, the resolver's
//     answer itself may be the problem: stale, region-poisoned, or pinned to
//     edges a provider blocks. Re-resolving through a public DoH endpoint
//     returns a different view of the same name. Whatever comes back goes
//     through the identical private/reserved filter and is pinned at dial
//     time, so the SSRF posture is unchanged; only the source of the answer
//     widened.
const (
	// racingStagger is the Happy-Eyeballs delay between starting each
	// additional dial. 250ms lets a fast edge win before the slower ones are
	// even attempted, while a dead edge never gets to serialize the whole
	// request.
	racingStagger = 250 * time.Millisecond

	// maxRacingIPs caps how many addresses are raced. GitHub's api.github.com
	// answers with a handful of A records; racing every address a wildcard
	// resolver might return would fan out the dial unbounded.
	maxRacingIPs = 6

	// dohQueryTimeout bounds one DoH endpoint round-trip.
	dohQueryTimeout = 4 * time.Second
)

// publicIPs filters the resolver's answer down to dialable public addresses
// (the same isPrivateOrReservedIP rule the dialer enforced anyway) and caps
// the list at maxRacingIPs, IPv6 first per RFC 8305 preference.
func publicIPs(ips []net.IPAddr) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ipa := range ips {
		if isPrivateOrReservedIP(ipa.IP) {
			continue
		}
		out = append(out, ipa.IP)
	}
	// Stable partition: v6 before v4, keeping resolver order within family.
	partition := make([]net.IP, 0, len(out))
	for _, ip := range out {
		if ip.To4() == nil {
			partition = append(partition, ip)
		}
	}
	for _, ip := range out {
		if ip.To4() != nil {
			partition = append(partition, ip)
		}
	}
	if len(partition) > maxRacingIPs {
		partition = partition[:maxRacingIPs]
	}
	return partition
}

// dialRacing dials the candidate addresses with a staggered start and returns
// the first connection that completes, cancelling the rest. With a single
// candidate it is a plain dial. Every dial uses the same base dialer — its
// timeout applies per address, and the request context still governs the total.
func dialRacing(ctx context.Context, base *net.Dialer, ips []net.IP, port string) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no public address to dial", ErrBlockedAddress)
	}
	if len(ips) == 1 {
		return base.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
	}
	type attempt struct {
		conn net.Conn
		err  error
	}
	// Buffered to len(ips): every launched dial posts exactly one result even
	// after the winner is chosen and the context is cancelled, so no goroutine
	// can block on the channel and leak.
	results := make(chan attempt, len(ips))
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	launch := func(ip net.IP) {
		conn, err := base.DialContext(rctx, "tcp", net.JoinHostPort(ip.String(), port))
		select {
		case results <- attempt{conn: conn, err: err}:
		case <-rctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}

	go launch(ips[0])
	for i := 1; i < len(ips); i++ {
		ip := ips[i]
		time.AfterFunc(time.Duration(i)*racingStagger, func() {
			launch(ip) // launch() itself is a no-op leak-free once rctx is done
		})
	}

	var firstErr error
	for range ips {
		select {
		case r := <-results:
			if r.conn != nil {
				return r.conn, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, firstErr
}

// ── DNS-over-HTTPS last resort ───────────────────────────────────────────────

// dohEndpoints are the public resolvers tried in order. Two independent
// operators, both on edges (Cloudflare, Google) that are reachable from hosts
// whose own resolver or routes are broken — the exact failure the fallback
// exists for.
var dohEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
}

// dohUsed counts requests whose connection succeeded ONLY through a DoH
// re-resolved address — surfaced so an operator can see their host's normal
// route to a name is broken rather than discovering it during an outage.
var dohUsed atomic.Int64

// DoHDialCount reports how many connections were established through a
// DNS-over-HTTPS re-resolved address.
func DoHDialCount() int64 { return dohUsed.Load() }

func noteDoHDial(host string) {
	dohUsed.Add(1)
	logging.LogWarn("safefetch", "connected via DNS-over-HTTPS re-resolution — the system resolver's addresses for "+host+" are unreachable")
}

// dohPermitted is the whole enablement decision, testable without I/O:
// a DoH query is itself a clearnet HTTPS request, so it is refused in a Tor
// Space (ADR-0141 anti-leak), and an operator who set VAYU_DNS_FALLBACK=off
// has already said "refuse off-box DNS" — a DoH query would defeat exactly
// that switch.
func dohPermitted() bool {
	if ClearnetBlocked() {
		return false
	}
	return dnsFallbackEnabled()
}

// dohClient dials its endpoints with the shared resolver (so resolve.go's
// public-resolver fallback still protects the DoH query itself) and never
// recurses into DoH.
var dohClient = &http.Client{
	Timeout: 2*dohQueryTimeout + 2*time.Second,
	Transport: &http.Transport{
		Proxy:               nil, // a proxy for the DoH query defeats the fallback
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := resolveIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipa := range ips {
				if isPrivateOrReservedIP(ipa.IP) {
					continue
				}
				d := &net.Dialer{Timeout: dohQueryTimeout}
				return d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
			}
			return nil, fmt.Errorf("%w: DoH endpoint %q has no public address", ErrBlockedAddress, host)
		},
	},
}

// dohResponse is the RFC 8484 JSON wire format both endpoints answer with.
type dohResponse struct {
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

const (
	dohTypeA    = 1
	dohTypeAAAA = 28
)

// dohLookupIPs re-resolves host through the public DoH endpoints and returns
// its dialable public addresses (A then AAAA), private/reserved answers
// filtered by the same rule every dial honours. It never returns loopback or
// reserved targets regardless of what a resolver claims.
func dohLookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		// An IP-literal host cannot be re-resolved; the caller already raced it.
		return nil, nil
	}
	var out []net.IP
	for _, ep := range dohEndpoints {
		for _, qtype := range []int{dohTypeA, dohTypeAAAA} {
			qctx, cancel := context.WithTimeout(ctx, dohQueryTimeout)
			u := ep + "?name=" + url.QueryEscape(host) + "&type=" + fmt.Sprint(qtype)
			req, err := http.NewRequestWithContext(qctx, http.MethodGet, u, nil)
			if err != nil {
				cancel()
				continue
			}
			req.Header.Set("Accept", "application/dns-json")
			req.Header.Set("User-Agent", "VayuPress/safefetch")
			resp, err := dohClient.Do(req)
			if err != nil {
				cancel()
				continue
			}
			var parsed dohResponse
			err = json.NewDecoder(resp.Body).Decode(&parsed)
			resp.Body.Close()
			cancel()
			if err != nil {
				continue
			}
			for _, a := range parsed.Answer {
				if a.Type != dohTypeA && a.Type != dohTypeAAAA {
					continue
				}
				ip := net.ParseIP(a.Data)
				if ip == nil || isPrivateOrReservedIP(ip) {
					continue
				}
				dup := false
				for _, seen := range out {
					if seen.Equal(ip) {
						dup = true
						break
					}
				}
				if dup {
					continue
				}
				out = append(out, ip)
				if len(out) >= maxRacingIPs {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

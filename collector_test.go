package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// startTestResolver spins up an in-process UDP DNS server that answers SOA
// queries with the given handler, and returns its address plus a shutdown func.
func startTestResolver(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestProbeAndCollect(t *testing.T) {
	exp := uint32(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	addr, shutdown := startTestResolver(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.AuthenticatedData = true // simulate a validating resolver
		m.Answer = []dns.RR{soa("systemli.org"), rrsig("systemli.org", exp)}
		_ = w.WriteMsg(m)
	})
	defer shutdown()

	prober := NewProber(addr, 2*time.Second)

	res := prober.Probe("systemli.org")
	if !res.Success || !res.Validated {
		t.Fatalf("Probe = %+v, want success+validated", res)
	}
	if !res.HasExpiry || res.EarliestExpiry.Unix() != int64(exp) {
		t.Fatalf("expiry = %v (has=%v), want %d", res.EarliestExpiry.Unix(), res.HasExpiry, exp)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(prober, "systemli.org"))

	expected := `
# HELP dnssec_validated 1 if the zone validated (RCODE NOERROR and AD bit set), 0 otherwise.
# TYPE dnssec_validated gauge
dnssec_validated 1
# HELP dnssec_probe_success 1 if the validating resolver returned a usable response, 0 otherwise.
# TYPE dnssec_probe_success gauge
dnssec_probe_success 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), "dnssec_validated", "dnssec_probe_success"); err != nil {
		t.Errorf("unexpected metrics: %v", err)
	}
}

func TestProbeResolverUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listening, query fails fast.
	prober := NewProber("127.0.0.1:1", 200*time.Millisecond)
	res := prober.Probe("systemli.org")
	if res.Success {
		t.Fatalf("expected probe failure against dead resolver, got %+v", res)
	}
}

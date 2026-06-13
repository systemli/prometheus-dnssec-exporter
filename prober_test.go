package main

import (
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func soa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns0." + dns.Fqdn(zone), Mbox: "hostmaster." + dns.Fqdn(zone), Serial: 1,
	}
}

func rrsig(zone string, expiration uint32) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeSOA, Algorithm: 8, Labels: 2,
		OrigTtl: 3600, Expiration: expiration, Inception: 1, KeyTag: 12345, SignerName: dns.Fqdn(zone),
	}
}

func TestEvaluate(t *testing.T) {
	exp := uint32(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	tests := []struct {
		name          string
		resp          *dns.Msg
		err           error
		wantSuccess   bool
		wantValidated bool
		wantExpiry    bool
	}{
		{
			name: "validated with rrsig",
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.Rcode = dns.RcodeSuccess
				m.AuthenticatedData = true
				m.Answer = []dns.RR{soa("systemli.org"), rrsig("systemli.org", exp)}
				return m
			}(),
			wantSuccess: true, wantValidated: true, wantExpiry: true,
		},
		{
			name: "noerror but AD not set (zone not signed / chain broken)",
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.Rcode = dns.RcodeSuccess
				m.AuthenticatedData = false
				m.Answer = []dns.RR{soa("example.org")}
				return m
			}(),
			wantSuccess: true, wantValidated: false, wantExpiry: false,
		},
		{
			name: "servfail (validation failure)",
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.Rcode = dns.RcodeServerFailure
				return m
			}(),
			wantSuccess: true, wantValidated: false, wantExpiry: false,
		},
		{
			name: "resolver unreachable",
			resp: nil, err: errors.New("i/o timeout"),
			wantSuccess: false, wantValidated: false, wantExpiry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := evaluate(tt.resp, 10*time.Millisecond, tt.err)
			if res.Success != tt.wantSuccess {
				t.Errorf("Success = %v, want %v", res.Success, tt.wantSuccess)
			}
			if res.Validated != tt.wantValidated {
				t.Errorf("Validated = %v, want %v", res.Validated, tt.wantValidated)
			}
			if res.HasExpiry != tt.wantExpiry {
				t.Errorf("HasExpiry = %v, want %v", res.HasExpiry, tt.wantExpiry)
			}
			if tt.wantExpiry && res.EarliestExpiry.Unix() != int64(exp) {
				t.Errorf("EarliestExpiry = %d, want %d", res.EarliestExpiry.Unix(), exp)
			}
		})
	}
}

func TestEvaluateEarliestExpiry(t *testing.T) {
	early := uint32(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC).Unix())
	late := uint32(time.Date(2029, 6, 1, 0, 0, 0, 0, time.UTC).Unix())

	m := new(dns.Msg)
	m.Rcode = dns.RcodeSuccess
	m.AuthenticatedData = true
	m.Answer = []dns.RR{rrsig("systemli.org", late), soa("systemli.org"), rrsig("systemli.org", early)}

	res := evaluate(m, 0, nil)
	if !res.HasExpiry || res.EarliestExpiry.Unix() != int64(early) {
		t.Fatalf("EarliestExpiry = %v (has=%v), want %d", res.EarliestExpiry.Unix(), res.HasExpiry, early)
	}
}

package main

import (
	"time"

	"github.com/miekg/dns"
)

// Result holds the outcome of probing a single zone through a validating
// recursive resolver.
type Result struct {
	// Success is true when the resolver returned a usable response.
	Success bool
	// Validated is true when the response had RCODE NOERROR and the AD
	// (Authenticated Data) bit set, i.e. the resolver validated the whole
	// DNSSEC chain (root -> parent DS -> zone DNSKEY -> RRSIG).
	Validated bool
	// Rcode is the response code returned by the resolver.
	Rcode int
	// EarliestExpiry is the soonest RRSIG expiration found in the answer.
	EarliestExpiry time.Time
	// HasExpiry indicates whether any RRSIG was present to derive an expiry.
	HasExpiry bool
	// Duration is the round trip time of the query.
	Duration time.Duration
}

// Prober queries a DNSSEC-validating recursive resolver.
type Prober struct {
	resolver string
	client   *dns.Client
}

// NewProber returns a Prober querying the given resolver (host:port).
func NewProber(resolver string, timeout time.Duration) *Prober {
	return &Prober{
		resolver: resolver,
		client:   &dns.Client{Timeout: timeout},
	}
}

// Probe asks the resolver to validate the zone's SOA with the DO bit set and
// CD (CheckingDisabled) cleared, so the resolver performs DNSSEC validation.
func (p *Prober) Probe(zone string) Result {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.SetEdns0(4096, true) // EDNS0 with the DNSSEC OK (DO) bit
	m.RecursionDesired = true

	resp, rtt, err := p.client.Exchange(m, p.resolver)
	return evaluate(resp, rtt, err)
}

// evaluate turns a raw DNS exchange into a Result. It is kept separate from the
// network call so it can be unit tested with crafted messages.
func evaluate(resp *dns.Msg, rtt time.Duration, err error) Result {
	res := Result{Duration: rtt}
	if err != nil || resp == nil {
		return res
	}

	res.Success = true
	res.Rcode = resp.Rcode
	res.Validated = resp.Rcode == dns.RcodeSuccess && resp.AuthenticatedData

	for _, rr := range resp.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		// RRSIG expiration is seconds since the Unix epoch; safe to treat as
		// int64 well past the year 2100.
		exp := time.Unix(int64(sig.Expiration), 0).UTC()
		if !res.HasExpiry || exp.Before(res.EarliestExpiry) {
			res.EarliestExpiry = exp
			res.HasExpiry = true
		}
	}

	return res
}

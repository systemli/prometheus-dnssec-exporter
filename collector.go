package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Collector runs a single probe per scrape and exposes the result. It follows
// the multi-target exporter pattern: the zone label is attached by Prometheus
// relabeling from the ?target= parameter, so the metrics themselves carry no
// zone label.
type Collector struct {
	prober *Prober
	target string

	probeSuccess *prometheus.Desc
	validated    *prometheus.Desc
	rcode        *prometheus.Desc
	rrsigExpiry  *prometheus.Desc
	duration     *prometheus.Desc
}

// NewCollector builds a Collector probing the given target zone.
func NewCollector(prober *Prober, target string) *Collector {
	return &Collector{
		prober: prober,
		target: target,
		probeSuccess: prometheus.NewDesc(
			"dnssec_probe_success",
			"1 if the validating resolver returned a usable response, 0 otherwise.",
			nil, nil),
		validated: prometheus.NewDesc(
			"dnssec_validated",
			"1 if the zone validated (RCODE NOERROR and AD bit set), 0 otherwise.",
			nil, nil),
		rcode: prometheus.NewDesc(
			"dnssec_response_rcode",
			"Numeric DNS response code returned by the resolver.",
			nil, nil),
		rrsigExpiry: prometheus.NewDesc(
			"dnssec_rrsig_earliest_expiry_timestamp_seconds",
			"Unix timestamp of the earliest RRSIG expiration in the answer.",
			nil, nil),
		duration: prometheus.NewDesc(
			"dnssec_probe_duration_seconds",
			"Duration of the DNS query in seconds.",
			nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.probeSuccess
	ch <- c.validated
	ch <- c.rcode
	ch <- c.rrsigExpiry
	ch <- c.duration
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	res := c.prober.Probe(c.target)

	ch <- prometheus.MustNewConstMetric(c.probeSuccess, prometheus.GaugeValue, b2f(res.Success))
	ch <- prometheus.MustNewConstMetric(c.duration, prometheus.GaugeValue, res.Duration.Seconds())

	if !res.Success {
		return
	}

	ch <- prometheus.MustNewConstMetric(c.validated, prometheus.GaugeValue, b2f(res.Validated))
	ch <- prometheus.MustNewConstMetric(c.rcode, prometheus.GaugeValue, float64(res.Rcode))

	if res.HasExpiry {
		ch <- prometheus.MustNewConstMetric(c.rrsigExpiry, prometheus.GaugeValue, float64(res.EarliestExpiry.Unix()))
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

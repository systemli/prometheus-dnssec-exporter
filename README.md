# prometheus-dnssec-exporter

[![Integration](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/integration.yaml/badge.svg)](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/integration.yaml)
[![Quality](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/quality.yaml/badge.svg)](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/quality.yaml)
[![Release](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/release.yaml/badge.svg)](https://github.com/systemli/prometheus-dnssec-exporter/actions/workflows/release.yaml)

Prometheus exporter that checks whether a zone's DNSSEC chain validates, written in Go.

For each probed zone it queries a **DNSSEC-validating recursive resolver** for the zone's
`SOA` with the EDNS0 DO bit set and CD (CheckingDisabled) cleared, then reports whether the
resolver returned `NOERROR` with the **AD (Authenticated Data)** bit set. That single signal
validates the whole chain of trust: root → parent DS → zone DNSKEY → RRSIG. A broken or stale
parent DS, an unsigned zone, or an expired signature all surface as `dnssec_validated 0`
(typically via `SERVFAIL`). The earliest RRSIG expiry is exported too, so signatures lapsing
can be alerted on before they break.

> [!IMPORTANT]
> The configured resolver **must** perform validation (e.g. `unbound`, or BIND with
> `dnssec-validation auto`). Querying a non-validating resolver — or an authoritative server
> directly — makes every zone falsely report `dnssec_validated 0`, because the AD bit is only
> set by a validating resolver.

## Usage

```shell
go install github.com/systemli/prometheus-dnssec-exporter@latest
$GOPATH/bin/prometheus-dnssec-exporter -resolver=127.0.0.1:53
```

This is a multi-target ("blackbox style") exporter: probe a zone via
`http://localhost:9204/probe?target=<zone>`.

```shell
curl 'http://localhost:9204/probe?target=systemli.org'
```

### Commandline options

```text
  -resolver string
        Address (host:port) of a DNSSEC-validating recursive resolver to query. (default "127.0.0.1:53")
  -timeout duration
        Timeout for a single DNS query. (default 5s)
  -web.listen-address string
        Address on which to expose metrics and the probe interface. (default ":9204")
```

## Metrics

The `zone` label is attached by Prometheus relabeling from the `?target=` parameter, so the
probe metrics carry no zone label themselves.

```text
# HELP dnssec_probe_success 1 if the validating resolver returned a usable response, 0 otherwise.
# TYPE dnssec_probe_success gauge
dnssec_probe_success 1
# HELP dnssec_validated 1 if the zone validated (RCODE NOERROR and AD bit set), 0 otherwise.
# TYPE dnssec_validated gauge
dnssec_validated 1
# HELP dnssec_response_rcode Numeric DNS response code returned by the resolver.
# TYPE dnssec_response_rcode gauge
dnssec_response_rcode 0
# HELP dnssec_rrsig_earliest_expiry_timestamp_seconds Unix timestamp of the earliest RRSIG expiration in the answer.
# TYPE dnssec_rrsig_earliest_expiry_timestamp_seconds gauge
dnssec_rrsig_earliest_expiry_timestamp_seconds 1.8939456e+09
# HELP dnssec_probe_duration_seconds Duration of the DNS query in seconds.
# TYPE dnssec_probe_duration_seconds gauge
dnssec_probe_duration_seconds 0.012
```

## Prometheus scrape config

```yaml
- job_name: "dnssec"
  metrics_path: "/probe"
  static_configs:
    - targets:
        - "systemli.org"
        - "systemli.net"
  relabel_configs:
    - source_labels: [__address__]
      target_label: __param_target
    - source_labels: [__param_target]
      target_label: zone
    - target_label: __address__
      replacement: "localhost:9204"
```

## Example alerting rules

```yaml
- alert: DnssecValidationFailed
  expr: dnssec_validated == 0
  for: 15m
  labels:
    severity: critical
  annotations:
    summary: "DNSSEC validation failed for {{ $labels.zone }}"

- alert: DnssecRrsigExpiringSoon
  expr: dnssec_rrsig_earliest_expiry_timestamp_seconds - time() < 7 * 86400
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "DNSSEC signatures for {{ $labels.zone }} expire in less than 7 days"

- alert: DnssecProbeFailed
  expr: dnssec_probe_success == 0
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "DNSSEC probe for {{ $labels.zone }} could not reach the resolver"
```

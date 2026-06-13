package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	addr     = flag.String("web.listen-address", ":9204", "Address on which to expose metrics and the probe interface.")
	resolver = flag.String("resolver", "127.0.0.1:53", "Address (host:port) of a DNSSEC-validating recursive resolver to query.")
	timeout  = flag.Duration("timeout", 5*time.Second, "Timeout for a single DNS query.")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	prober := NewProber(*resolver, *timeout)

	// Multi-target (blackbox style): Prometheus scrapes /probe?target=<zone>.
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "missing 'target' query parameter", http.StatusBadRequest)
			return
		}

		registry := prometheus.NewRegistry()
		registry.MustRegister(NewCollector(prober, target))
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	})

	// Exporter's own process metrics.
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, `<html>
<head><title>DNSSEC Exporter</title></head>
<body>
<h1>DNSSEC Exporter</h1>
<p><a href="/probe?target=example.org">Probe example.org</a></p>
<p><a href="/metrics">Exporter metrics</a></p>
</body>
</html>`)
	})

	log.Printf("listening on %s, validating resolver %s", *addr, *resolver)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

package metrics

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusExporter encapsulates the prometheus registry and exposes the HTTP endpoint.
type PrometheusExporter struct {
	port string

	// Metrics
	reqsTotal      *prometheus.CounterVec
	currentRPS     prometheus.Gauge
	blockedIPs     prometheus.Gauge
	ebpfDropsTotal prometheus.Counter
	activeConns    prometheus.Gauge
	attackTotal    prometheus.Counter
}

// NewPrometheus creates a new exporter and registers all metrics.
func NewPrometheus(port string) *PrometheusExporter {
	p := &PrometheusExporter{
		port: port,
		reqsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "noxis_requests_total",
				Help: "Total number of HTTP requests processed by Noxis.",
			},
			[]string{"status"},
		),
		currentRPS: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "noxis_current_rps",
				Help: "Current Requests Per Second globally.",
			},
		),
		blockedIPs: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "noxis_banned_ips_total",
				Help: "Current number of IPs in the blocklist.",
			},
		),
		ebpfDropsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "noxis_ebpf_drops_total",
				Help: "Total number of packets dropped by the eBPF Shield/Userspace.",
			},
		),
		activeConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "noxis_active_connections",
				Help: "Current active proxied TCP connections.",
			},
		),
		attackTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "noxis_attack_detected_total",
				Help: "Total number of isolated attack spikes detected by Z-Score Anomaly.",
			},
		),
	}

	prometheus.MustRegister(p.reqsTotal)
	prometheus.MustRegister(p.currentRPS)
	prometheus.MustRegister(p.blockedIPs)
	prometheus.MustRegister(p.ebpfDropsTotal)
	prometheus.MustRegister(p.activeConns)
	prometheus.MustRegister(p.attackTotal)

	return p
}

// Start launches the HTTP server blockingly on the configured metrics port
func (p *PrometheusExporter) Start() error {
	log.Printf("[Metrics] Starting Prometheus exporter on %s", p.port)
	http.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(p.port, nil)
}

// Sync updates the prometheus gauges using data from the standard Aggregator
func (p *PrometheusExporter) Sync(stats Stats) {
	p.reqsTotal.WithLabelValues("passed").Add(float64(stats.Passed))
	p.reqsTotal.WithLabelValues("blocked").Add(float64(stats.Blocked))
	p.currentRPS.Set(stats.CurrentRPS)
	p.blockedIPs.Set(float64(stats.BannedIPs))
	p.ebpfDropsTotal.Add(float64(stats.EbpfDrops)) // This requires care since it's a counter, Add() sums delta, not absolute!
	p.activeConns.Set(float64(stats.ActiveConnections))
}

// IncAttack counter increments when the anomaly detector fires.
func (p *PrometheusExporter) IncAttack() {
	p.attackTotal.Inc()
}

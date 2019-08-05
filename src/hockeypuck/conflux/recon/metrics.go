package recon

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var metrics = struct {
	itemsRecovered *prometheus.CounterVec
	reconBusyPeer  *prometheus.CounterVec
	reconFailure   *prometheus.CounterVec
	reconSuccess   *prometheus.CounterVec
	reconDuration  *prometheus.HistogramVec
}{
	itemsRecovered: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_items_recovered",
			Help:      "Count of items recovered since startup",
		},
		[]string{
			"peer",
		},
	),
	reconBusyPeer: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_busy_peer",
			Help:      "Count of reconciliations attempted against busy peers since startup",
		},
		[]string{
			"peer",
		},
	),
	reconFailure: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_failure",
			Help:      "Count of failed reconciliations since startup",
		},
		[]string{
			"peer",
		},
	),
	reconSuccess: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_success",
			Help:      "Count of successful reconciliations since startup",
		},
		[]string{
			"peer",
		},
	),
	reconDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "conflux",
			Name:      "reconciliation_duration_seconds",
			Help:      "Time spent performing a reconciliation",
		},
		[]string{
			"peer",
			"result",
		},
	),
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(metrics.reconBusyPeer)
		prometheus.MustRegister(metrics.reconFailure)
		prometheus.MustRegister(metrics.reconSuccess)
		prometheus.MustRegister(metrics.itemsRecovered)
		prometheus.MustRegister(metrics.reconDuration)
	})
}

func labelPeer(peer net.Addr) prometheus.Labels {
	labels := prometheus.Labels{"peer": "unknown"}
	if h, _, err := net.SplitHostPort(peer.String()); err == nil {
		labels["peer"] = h
	}
	return labels
}

func labelPeerResult(peer net.Addr, result string) prometheus.Labels {
	labels := prometheus.Labels{"peer": "unknown", "result": result}
	if h, _, err := net.SplitHostPort(peer.String()); err == nil {
		labels["peer"] = h
	}
	return labels
}

func recordItemsRecovered(peer net.Addr, items int) {
	metrics.itemsRecovered.With(labelPeer(peer)).Add(float64(items))
}

func recordReconBusyPeer(peer net.Addr) {
	metrics.reconBusyPeer.With(labelPeer(peer)).Inc()
}

func recordReconFailure(peer net.Addr, duration time.Duration) {
	metrics.reconFailure.With(labelPeer(peer)).Inc()
	metrics.reconDuration.With(labelPeerResult(peer, "failure")).Observe(duration.Seconds())
}

func recordReconSuccess(peer net.Addr, duration time.Duration) {
	metrics.reconSuccess.With(labelPeer(peer)).Inc()
	metrics.reconDuration.With(labelPeerResult(peer, "success")).Observe(duration.Seconds())
}

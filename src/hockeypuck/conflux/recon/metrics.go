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
	reconDuration  *prometheus.HistogramVec
	reconFailure   *prometheus.CounterVec
	reconSuccess   *prometheus.CounterVec
}{
	itemsRecovered: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_items_recovered",
			Help:      "Count of items recovered since startup",
		},
		[]string{"peer"},
	),
	reconBusyPeer: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_busy_peer",
			Help:      "Count of reconciliations attempted against busy peers since startup",
		},
		[]string{"peer"},
	),
	reconDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "conflux",
			Name:      "reconciliation_duration_seconds",
			Help:      "Time spent performing a reconciliation",
		},
		[]string{"peer", "result"},
	),
	reconFailure: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_failure",
			Help:      "Count of failed reconciliations since startup",
		},
		[]string{"peer"},
	),
	reconSuccess: prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "conflux",
			Name:      "reconciliation_success",
			Help:      "Count of successful reconciliations since startup",
		},
		[]string{"peer"},
	),
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(metrics.itemsRecovered)
		prometheus.MustRegister(metrics.reconBusyPeer)
		prometheus.MustRegister(metrics.reconDuration)
		prometheus.MustRegister(metrics.reconFailure)
		prometheus.MustRegister(metrics.reconSuccess)
	})
}

func hostFromPeer(peer net.Addr) string {
	if h, _, err := net.SplitHostPort(peer.String()); err == nil {
		return h
	}
	return "unknown"
}

func recordItemsRecovered(peer net.Addr, items int) {
	metrics.itemsRecovered.WithLabelValues(hostFromPeer(peer)).Add(float64(items))
}

func recordReconBusyPeer(peer net.Addr) {
	metrics.reconBusyPeer.WithLabelValues(hostFromPeer(peer)).Inc()
}

func recordReconFailure(peer net.Addr, duration time.Duration) {
	metrics.reconDuration.WithLabelValues(hostFromPeer(peer), "failure").Observe(duration.Seconds())
	metrics.reconFailure.WithLabelValues(hostFromPeer(peer)).Inc()
}

func recordReconSuccess(peer net.Addr, duration time.Duration) {
	metrics.reconDuration.WithLabelValues(hostFromPeer(peer), "success").Observe(duration.Seconds())
	metrics.reconSuccess.WithLabelValues(hostFromPeer(peer)).Inc()
}

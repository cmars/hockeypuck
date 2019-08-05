package recon

import (
	"net"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var metrics = struct {
	itemsRecovered *prometheus.CounterVec
	reconBusyPeer  *prometheus.CounterVec
	reconFailure   *prometheus.CounterVec
	reconSuccess   *prometheus.CounterVec
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
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(metrics.reconBusyPeer)
		prometheus.MustRegister(metrics.reconFailure)
		prometheus.MustRegister(metrics.reconSuccess)
		prometheus.MustRegister(metrics.itemsRecovered)
	})
}

func labelPeer(peer net.Addr) prometheus.Labels {
	labels := prometheus.Labels{"peer": "unknown"}
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

func recordReconFailure(peer net.Addr) {
	metrics.reconFailure.With(labelPeer(peer)).Inc()
}

func recordReconSuccess(peer net.Addr) {
	metrics.reconSuccess.With(labelPeer(peer)).Inc()
}

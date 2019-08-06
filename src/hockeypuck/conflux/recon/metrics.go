package recon

import (
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	CLIENT = "client"
	SERVER = "server"
)

var reconMetrics = struct {
	itemsRecovered      *prometheus.CounterVec
	reconBusyPeer       *prometheus.CounterVec
	reconDuration       *prometheus.HistogramVec
	reconEventTimestamp *prometheus.GaugeVec
	reconFailure        *prometheus.CounterVec
	reconSuccess        *prometheus.CounterVec
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
			Buckets:   prometheus.ExponentialBuckets(0.001, 10, 7), // 1ms to 1000s (16m40s)
		},
		[]string{"peer", "result"},
	),
	reconEventTimestamp: prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "conflux",
			Name:      "reconciliation_event_time_seconds",
			Help:      "When the given event last occurred, in seconds since the epoch",
		},
		[]string{"peer", "event", "role"},
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
		prometheus.MustRegister(reconMetrics.itemsRecovered)
		prometheus.MustRegister(reconMetrics.reconBusyPeer)
		prometheus.MustRegister(reconMetrics.reconDuration)
		prometheus.MustRegister(reconMetrics.reconEventTimestamp)
		prometheus.MustRegister(reconMetrics.reconFailure)
		prometheus.MustRegister(reconMetrics.reconSuccess)
	})
}

func hostFromPeer(peer net.Addr) string {
	if h, _, err := net.SplitHostPort(peer.String()); err == nil {
		return h
	}
	return "unknown"
}

func recordItemsRecovered(peer net.Addr, items int) {
	reconMetrics.itemsRecovered.WithLabelValues(hostFromPeer(peer)).Add(float64(items))
}

func recordReconBusyPeer(peer net.Addr, role string) {
	reconMetrics.reconBusyPeer.WithLabelValues(hostFromPeer(peer)).Inc()
	reconMetrics.reconEventTimestamp.WithLabelValues(hostFromPeer(peer), "busy", role, role).Set(float64(time.Now().Unix()))
}

func recordReconFailure(peer net.Addr, duration time.Duration, role string) {
	reconMetrics.reconDuration.WithLabelValues(hostFromPeer(peer), "failure").Observe(duration.Seconds())
	reconMetrics.reconEventTimestamp.WithLabelValues(hostFromPeer(peer), "failure", role).Set(float64(time.Now().Unix()))
	reconMetrics.reconFailure.WithLabelValues(hostFromPeer(peer)).Inc()
}

func recordReconInitiate(peer net.Addr, role string) {
	reconMetrics.reconEventTimestamp.WithLabelValues(hostFromPeer(peer), "initiate", role).Set(float64(time.Now().Unix()))
}

func recordReconSuccess(peer net.Addr, duration time.Duration, role string) {
	reconMetrics.reconDuration.WithLabelValues(hostFromPeer(peer), "success").Observe(duration.Seconds())
	reconMetrics.reconEventTimestamp.WithLabelValues(hostFromPeer(peer), "success", role).Set(float64(time.Now().Unix()))
	reconMetrics.reconSuccess.WithLabelValues(hostFromPeer(peer)).Inc()
}

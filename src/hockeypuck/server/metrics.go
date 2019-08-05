package server

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"hockeypuck/hkp/storage"
)

var metrics = struct {
	keysAdded           prometheus.Counter
	keysIgnored         prometheus.Counter
	keysUpdated         prometheus.Counter
	httpRequestDuration *prometheus.HistogramVec
}{
	keysAdded: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added",
			Help:      "New keys added since startup",
		},
	),
	keysIgnored: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_ignored",
			Help:      "Keys with no-op updates since startup",
		},
	),
	keysUpdated: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_updated",
			Help:      "Keys updated since startup",
		},
	),
	httpRequestDuration: prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "hockeypuck",
			Name:      "http_request_duration_seconds",
			Help:      "Time spent generating HTTP responses",
		},
		[]string{
			"method",
			"status_code",
		},
	),
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(metrics.keysAdded)
		prometheus.MustRegister(metrics.keysIgnored)
		prometheus.MustRegister(metrics.keysUpdated)
		prometheus.MustRegister(metrics.httpRequestDuration)
	})
}

func metricsStorageNotifier(kc storage.KeyChange) error {
	switch kc.(type) {
	case storage.KeyAdded:
		metrics.keysAdded.Inc()
	case storage.KeyNotChanged:
		metrics.keysIgnored.Inc()
	case storage.KeyReplaced:
		metrics.keysUpdated.Inc()
	}
	return nil
}

func recordHTTPRequestDuration(method string, statusCode int, duration time.Duration) {
	labels := prometheus.Labels{"method": method, "status_code": strconv.Itoa(statusCode)}
	metrics.httpRequestDuration.With(labels).Observe(duration.Seconds())
}

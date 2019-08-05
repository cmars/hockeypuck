package server

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"hockeypuck/hkp/storage"
)

var metrics = struct {
	keysAdded   prometheus.Counter
	keysUpdated prometheus.Counter
	// TODO(pjdc): Track KeyNotChanged? i.e. .Upsert called yielding no change
	httpRequestDuration *prometheus.HistogramVec
}{
	keysAdded: prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "hockeypuck",
			Name:      "keys_added",
			Help:      "New keys added since startup",
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
		prometheus.MustRegister(metrics.keysUpdated)
		prometheus.MustRegister(metrics.httpRequestDuration)
	})
}

func metricsStorageNotifier(kc storage.KeyChange) error {
	switch kc.(type) {
	case storage.KeyAdded:
		metrics.keysAdded.Inc()
	case storage.KeyReplaced:
		metrics.keysUpdated.Inc()
	}
	return nil
}

func recordHTTPRequestDuration(method string, statusCode int, duration time.Duration) {
	labels := prometheus.Labels{"method": method, "status_code": strconv.Itoa(statusCode)}
	metrics.httpRequestDuration.With(labels).Observe(duration.Seconds())
}

package server

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"hockeypuck/hkp/storage"
)

var metrics = struct {
	keysAdded   prometheus.Counter
	keysUpdated prometheus.Counter
	// TODO(pjdc): Track KeyNotChanged? i.e. .Upsert called yielding no change
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
}

var metricsRegister sync.Once

func registerMetrics() {
	metricsRegister.Do(func() {
		prometheus.MustRegister(metrics.keysAdded)
		prometheus.MustRegister(metrics.keysUpdated)
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

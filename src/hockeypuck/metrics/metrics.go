package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/tomb.v2"
)

type Metrics struct {
	mux *http.ServeMux
	t   tomb.Tomb
}

const (
	// TODO(pjdc): become settings later
	metricsAddr = ":9626"
	metricsPath = "/metrics"
)

func NewMetrics() *Metrics {
	m := &Metrics{
		mux: http.NewServeMux(),
	}
	m.mux.Handle(metricsPath, promhttp.Handler())

	return m
}

func (m *Metrics) Start() {
	m.t.Go(func() error {
		return http.ListenAndServe(metricsAddr, m.mux)
	})
}

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/errgo.v1"
	"gopkg.in/tomb.v2"

	log "hockeypuck/logrus"
)

type Metrics struct {
	s   *Settings
	mux *http.ServeMux
	t   tomb.Tomb
}

func NewMetrics(s *Settings) *Metrics {
	if s == nil {
		s = DefaultSettings()
	}

	m := &Metrics{
		s:   s,
		mux: http.NewServeMux(),
	}
	m.mux.Handle(m.s.MetricsPath, promhttp.Handler())

	return m
}

func (m *Metrics) Start() {
	m.t.Go(func() error {
		log.Info("metrics: starting")
		if err := http.ListenAndServe(m.s.MetricsAddr, m.mux); err != nil {
			log.Errorf("failed to serve metrics: %v", err)
			return err
		}
		return nil
	})
}

func (m *Metrics) Stop() {
	log.Info("metrics: stopping")
	m.t.Kill(nil)
	if err := m.t.Wait(); err != nil {
		log.Error(errgo.Details(err))
	}
	log.Info("metrics: stopped")
}

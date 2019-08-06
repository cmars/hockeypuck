package metrics

type Settings struct {
	MetricsAddr string `toml:"metricsAddr"`
	MetricsPath string `toml:"metricsPath"`
}

var defaultSettings = Settings{
	MetricsAddr: ":9626",
	MetricsPath: "/metrics",
}

func DefaultSettings() *Settings {
	return &defaultSettings
}

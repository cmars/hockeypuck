package settings

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/conflux.v2/recon"
)

type confluxConfig struct {
	Recon reconConfig `toml:"recon"`
}

type reconConfig struct {
	recon.Settings
	LevelDB struct {
		Path string `toml:"path"`
	} `toml:"leveldb"`
}

const (
	DefaultHkpBind = ":11371"
)

type HkpConfig struct {
	Bind string `toml:"bind"`
}

type HkpsConfig struct {
	HkpConfig
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type PksConfig struct {
	From string     `toml:"from"`
	To   []string   `toml:"to"`
	Smtp SmtpConfig `toml:"smtp"`
}

const (
	DefaultSmtpHost = "localhost:25"
)

type SmtpConfig struct {
	Host     string `toml:"host"`
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

const (
	DefaultDBDriver = "postgres"
	DefaultDBDSN    = "dbname=hkp host=/var/run/postgresql sslmode=disable user=%s"
)

type DBConfig struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
}

const (
	DefaultStatsRefreshHours = 4
	DefaultNWorkers          = 8
)

type OpenPGPConfig struct {
	Pks               *PksConfig `toml:"pks"`
	VerifySigs        bool       `toml:"verifySigs"`
	StatsRefreshHours int        `toml:"statsRefresh"`
	NWorkers          int        `toml:"nworkers"`
	DB                DBConfig   `toml:"db"`
}

func DefaultOpenPGP() OpenPGPConfig {
	return OpenPGPConfig{
		StatsRefreshHours: DefaultStatsRefreshHours,
		NWorkers:          DefaultNWorkers,
		DB: DBConfig{
			Driver: DefaultDBDriver,
			DSN:    DefaultDBDSN,
		},
	}
}

type Settings struct {
	Conflux confluxConfig `toml:"conflux"`

	Hkp  HkpConfig   `toml:"hkp"`
	Hkps *HkpsConfig `toml:"hkps"`

	OpenPGP OpenPGPConfig `toml:"openpgp"`

	Logfile string `toml:"logfile"`
	Webroot string `toml:"webroot"`
}

func Default() Settings {
	reconSettings := recon.DefaultSettings()
	return Settings{
		Conflux: confluxConfig{
			Recon: reconConfig{
				Settings: *reconSettings,
			},
		},
		Hkp: HkpConfig{
			Bind: DefaultHkpBind,
		},
		OpenPGP: DefaultOpenPGP(),
	}
}

func Parse(data string) (*Settings, error) {
	var doc struct {
		Hockeypuck Settings `toml:"hockeypuck"`
	}
	doc.Hockeypuck = Default()
	_, err := toml.Decode(data, &doc)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	err = doc.Hockeypuck.Conflux.Recon.Settings.Resolve()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &doc.Hockeypuck, nil
}

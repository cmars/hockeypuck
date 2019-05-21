package leveldb

import (
	"hockeypuck/conflux/recon"
)

type Config struct {
	Path string `toml:"path"`
}

type Settings struct {
	recon.Settings

	LevelDB Config `toml:"leveldb"`
}

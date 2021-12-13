package config

import (
	"encoding/json"
	"log"

	"github.com/net-byte/vtun/common/cipher"
)

type Config struct {
	LocalAddr  string
	ServerAddr string
	CIDR       string
	Key        string
	Protocol   string
	ServerMode bool
	GlobalMode bool
	Obfuscate  bool
	Pprof      bool
}

func (config *Config) Init() {
	cipher.GenerateKey(config.Key)
	json, _ := json.Marshal(config)
	log.Printf("init config:%s", string(json))
}

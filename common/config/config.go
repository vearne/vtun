package config

import (
	"encoding/json"
	"os"
)

// Config The config struct
type Config struct {
	DeviceName                string `json:"device_name"`
	LocalAddr                 string `json:"local_addr"`
	ServerAddr                string `json:"server_addr"`
	ServerIP                  string `json:"server_ip"`
	ServerIPv6                string `json:"server_ipv6"`
	CIDR                      string `json:"cidr"`
	CIDRv6                    string `json:"cidr_ipv6"`
	Key                       string `json:"key"`
	Protocol                  string `json:"protocol"`
	Path                      string `json:"path"`
	ServerMode                bool   `json:"server_mode"`
	GlobalMode                bool   `json:"global_mode"`
	Obfs                      bool   `json:"obfs"`
	Compress                  bool   `json:"compress"`
	MTU                       int    `json:"mtu"`
	Timeout                   int    `json:"timeout"`
	LocalGateway              string `json:"local_gateway"`
	LocalGatewayv6            string `json:"local_gateway_ipv6"`
	TLSCertificateFilePath    string `json:"tls_certificate_file_path"`
	TLSCertificateKeyFilePath string `json:"tls_certificate_key_file_path"`
	TLSSni                    string `json:"tls_sni"`
	TLSInsecureSkipVerify     bool   `json:"tls_insecure_skip_verify"`
	BufferSize                int    `json:"buffer_size"`
	Verbose                   bool   `json:"verbose"`
	PSKMode                   bool   `json:"psk_mode"`
	Host                      string `json:"host"`
}

type nativeConfig Config

var DefaultConfig = nativeConfig{
	DeviceName:                "",
	LocalAddr:                 ":3000",
	ServerAddr:                ":3001",
	ServerIP:                  "172.16.0.1",
	ServerIPv6:                "fced:9999::1",
	CIDR:                      "172.16.0.10/24",
	CIDRv6:                    "fced:9999::9999/64",
	Key:                       "freedom@2023",
	Protocol:                  "udp",
	Path:                      "/freedom",
	ServerMode:                false,
	GlobalMode:                false,
	Obfs:                      false,
	Compress:                  false,
	MTU:                       1500,
	Timeout:                   30,
	TLSCertificateFilePath:    "./certs/server.pem",
	TLSCertificateKeyFilePath: "./certs/server.key",
	TLSSni:                    "",
	TLSInsecureSkipVerify:     false,
	Verbose:                   false,
	PSKMode:                   false,
	Host:                      "",
}

func (c *Config) UnmarshalJSON(data []byte) error {
	_ = json.Unmarshal(data, &DefaultConfig)
	*c = Config(DefaultConfig)
	return nil
}

func (c *Config) LoadConfig(configFile string) (err error) {
	file, err := os.Open(configFile)
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(c)
	if err != nil {
		return
	}
	return
}

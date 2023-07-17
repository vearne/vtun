package config

// Config The config struct
type Config struct {
	DeviceName                string `json:"device_name"`
	LocalAddr                 string `json:"local_addr"`
	ServerAddr                string `json:"server_addr"`
	ServerIP                  string `json:"server_ip"`
	ServerIPv6                string `json:"server_i_pv_6"`
	CIDR                      string `json:"cidr"`
	CIDRv6                    string `json:"cid_rv_6"`
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
	LocalGatewayv6            string `json:"local_gatewayv_6"`
	TLSCertificateFilePath    string `json:"tls_certificate_file_path"`
	TLSCertificateKeyFilePath string `json:"tls_certificate_key_file_path"`
	TLSSni                    string `json:"tls_sni"`
	TLSInsecureSkipVerify     bool   `json:"tls_insecure_skip_verify"`
	BufferSize                int    `json:"buffer_size"`
	Verbose                   bool   `json:"verbose"`
	PSKMode                   bool   `json:"psk_mode"`
	Host                      string `json:"host"`
}

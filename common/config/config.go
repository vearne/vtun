package config

type Config struct {
	DeviceName                string
	LocalAddr                 string
	ServerAddr                string
	IntranetServerIP          string
	IntranetServerIPv6        string
	DNSServerIP               string
	CIDR                      string
	CIDRv6                    string
	Key                       string
	Protocol                  string
	WebSocketPath             string
	ServerMode                bool
	GlobalMode                bool
	Obfs                      bool
	MTU                       int
	Timeout                   int
	LocalGateway              string
	TLSCertificateFilePath    string
	TLSCertificateKeyFilePath string
	TLSSni                    string
	InsecureSkipVerify        bool
}

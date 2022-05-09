package config

type Config struct {
	LocalAddr      string
	ServerAddr     string
	CIDR           string
	Key            string
	Protocol       string
	DNS            string
	WebSocketPath  string
	ServerMode     bool
	GlobalMode     bool
	Obfs           bool
	MTU            int
	Timeout        int
	DefaultGateway string
}

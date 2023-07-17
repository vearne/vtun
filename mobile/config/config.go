package kc

import (
	"encoding/json"
	"github.com/net-byte/vtun/common/config"
)

var Config = config.Config{}

func Init(str []byte) error {
	err := json.Unmarshal(str, &Config)
	if err != nil {
		return err
	}
	//_, ip4Net, err := net.ParseCIDR(Config.CIDR)
	//if err != nil {
	//	return err
	//}
	//Config.ServerIP = ip4Net.String()
	//_, ip6Net, err := net.ParseCIDR(Config.CIDRv6)
	//if err != nil {
	//	return err
	//}
	//Config.ServerIPv6 = ip6Net.String()
	return nil
}

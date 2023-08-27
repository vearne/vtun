package common

import "log"

var (
	Version   = "v1.7.2"
	GitHash   = ""
	BuildTime = ""
	GoVersion = ""
	Banner    = `
_                 
__ __ | |_   _  _   _ _  
\ V / |  _| | || | | ' \ 
 \_/   \__|  \_,_| |_||_|
						 
A simple VPN written in Go.
https://github.com/net-byte/vtun
`
)

func DisplayVersionInfo() {
	log.Println(Banner)
	log.Printf("version -> %s", Version)
	if GitHash != "" {
		log.Printf("git hash -> %s", GitHash)
	}
	if BuildTime != "" {
		log.Printf("build time -> %s", BuildTime)
	}
	if GoVersion != "" {
		log.Printf("go version -> %s", GoVersion)
	}
}

package common

import "log"

var (
	Version   = "v1.7.1"
	GitHash   = "nil"
	BuildTime = "nil"
	GoVersion = "nil"
)

func DisplayVersionInfo() {
	log.Printf("vtun version -> %s", Version)
	log.Printf("git hash -> %s", GitHash)
	log.Printf("build time -> %s", BuildTime)
	log.Printf("go version -> %s", GoVersion)
}

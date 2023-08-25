package config

import (
	"log"
	"testing"
)

func TestConfig_LoadConfig(t *testing.T) {
	c := &Config{}
	err := c.LoadConfig("../../example/config.json")
	if err != nil {
		log.Printf("err: %v\n", err)
		return
	}
	log.Printf("config:  %v\n", c)
}

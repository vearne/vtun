package xproto

import (
	"encoding/hex"
	"github.com/net-byte/vtun/common/config"
	"testing"
)

func TestClientHandshakePacket_Bytes(t *testing.T) {
	ch, err := GenClientHandshakePacket(config.Config{
		Key:    "flyflygogo",
		CIDR:   "172.16.0.10/24",
		CIDRv6: "fced:9999::9999/64",
	})
	if err != nil {
		t.Error("err", err)
	}
	t.Logf("bytes: %v\n", hex.EncodeToString(ch.Bytes()))
}

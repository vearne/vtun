package kcp

import (
	"github.com/xtaci/kcp-go"
)

func splitRead(session *kcp.UDPSession, expectLen int, packet []byte) (int, error) {
	count := 0
	splitSize := 99
	for count < expectLen {
		receiveSize := splitSize
		if expectLen-count < splitSize {
			receiveSize = expectLen - count
		}
		n, err := session.Read(packet[count : count+receiveSize])
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}

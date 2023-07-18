package quic

import (
	"github.com/quic-go/quic-go"
)

func splitRead(stream quic.Stream, expectLen int, packet []byte) (int, error) {
	count := 0
	splitSize := 99
	for count < expectLen {
		receiveSize := splitSize
		if expectLen-count < splitSize {
			receiveSize = expectLen - count
		}
		n, err := stream.Read(packet[count : count+receiveSize])
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}

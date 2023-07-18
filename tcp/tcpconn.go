package tcp

import "net"

func splitRead(conn net.Conn, expectLen int, packet []byte) (int, error) {
	count := 0
	splitSize := 99
	for count < expectLen {
		receiveSize := splitSize
		if expectLen-count < splitSize {
			receiveSize = expectLen - count
		}
		n, err := conn.Read(packet[count : count+receiveSize])
		if err != nil {
			return count, err
		}
		count += n
	}
	return count, nil
}

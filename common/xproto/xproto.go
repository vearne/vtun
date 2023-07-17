package xproto

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/net-byte/vtun/common/config"
	"net"
)

const ProtocolVersion = 1
const ClientSendPacketHeaderLength = 19
const ServerSendPacketHeaderLength = 3
const ClientHandshakePacketLength = 37

type ClientHandshakePacket struct {
	ProtocolVersion uint8    //1 byte
	Key             *AuthKey //16 byte
	CIDRv4          net.IP   //4 byte
	CIDRv6          net.IP   //16 byte
}

func (p *ClientHandshakePacket) Bytes() []byte {
	data := make([]byte, ClientHandshakePacketLength)
	data[0] = p.ProtocolVersion
	copy(data[1:17], p.Key[:])
	copy(data[17:21], p.CIDRv4.To4()[:])
	copy(data[21:37], p.CIDRv6.To16()[:])
	return data
}

func GenClientHandshakePacket(config config.Config) (*ClientHandshakePacket, error) {
	authKey := ParseAuthKeyFromString(config.Key)
	ipv4Addr, _, err := net.ParseCIDR(config.CIDR)
	if err != nil {
		return nil, err
	}
	ipv6Addr, _, err := net.ParseCIDR(config.CIDRv6)
	if err != nil {
		return nil, err
	}
	obj := &ClientHandshakePacket{
		ProtocolVersion: ProtocolVersion,
		Key:             authKey,
		CIDRv4:          ipv4Addr,
		CIDRv6:          ipv6Addr,
	}
	return obj, nil
}

func ParseClientHandshakePacket(data []byte) *ClientHandshakePacket {
	var obj = &ClientHandshakePacket{}
	var authKey AuthKey
	if len(data) != ClientHandshakePacketLength {
		return nil
	}
	obj.ProtocolVersion = data[0]
	copy(authKey[:], data[1:17])
	obj.Key = &authKey
	obj.CIDRv4 = net.IP{data[17], data[18], data[19], data[20]}
	obj.CIDRv6 = net.IP{data[21], data[22], data[23], data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35], data[36]}
	return obj
}

type ClientSendPacketHeader struct {
	ProtocolVersion uint8    //1 byte
	Key             *AuthKey //16 byte
	Length          int      //2 byte, convert to [2]byte
}

func (p *ClientSendPacketHeader) Bytes() []byte {
	data := make([]byte, ClientSendPacketHeaderLength)
	data[0] = p.ProtocolVersion
	copy(data[1:17], p.Key[:])
	data[17] = byte(p.Length >> 8 & 0xff)
	data[18] = byte(p.Length & 0xff)
	return data
}

func ParseClientSendPacketHeader(data []byte) *ClientSendPacketHeader {
	var obj = &ClientSendPacketHeader{}
	var authKey AuthKey
	if len(data) != ClientSendPacketHeaderLength {
		return nil
	}
	obj.ProtocolVersion = data[0]
	copy(authKey[:], data[1:17])
	obj.Key = &authKey
	obj.Length = ((obj.Length & 0x00) | int(data[17])) << 8
	obj.Length = obj.Length | int(data[18])
	return obj
}

type ServerSendPacketHeader struct {
	ProtocolVersion uint8 //1 byte
	Length          int   //2 byte, convert to [2]byte
}

func (p *ServerSendPacketHeader) Bytes() []byte {
	data := make([]byte, ServerSendPacketHeaderLength)
	data[0] = p.ProtocolVersion
	data[1] = byte(p.Length >> 8 & 0xff)
	data[2] = byte(p.Length & 0xff)
	return data
}

func ParseServerSendPacketHeader(data []byte) *ServerSendPacketHeader {
	var obj = &ServerSendPacketHeader{}
	if len(data) != ServerSendPacketHeaderLength {
		return nil
	}
	obj.ProtocolVersion = data[0]
	obj.Length = ((obj.Length & 0x00) | int(data[1])) << 8
	obj.Length = obj.Length | int(data[2])
	return obj
}

const HeaderLength = 2

// ReadLength []byte length to int length
func ReadLength(header []byte) int {
	length := 0
	if len(header) >= 2 {
		length = ((length & 0x00) | int(header[0])) << 8
		length = length | int(header[1])
	}
	return length
}

func WriteLength(header []byte, length int) {
	if len(header) >= 2 {
		header[0] = byte(length >> 8 & 0xff)
		header[1] = byte(length & 0xff)
	}
}

func Copy(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func Merge(a, b []byte) []byte {
	al := len(a)
	bl := len(b)
	c := make([]byte, len(a)+len(b))
	copy(c[al:al+bl], b)
	copy(c[:al], a)
	return c
}

type AuthKey [16]byte

// Bytes returns the bytes representation of this AuthKey.
func (u *AuthKey) Bytes() []byte {
	return u[:]
}

// Equals returns true if this AuthKey equals another AuthKey by value.
func (u *AuthKey) Equals(another *AuthKey) bool {
	if u == nil && another == nil {
		return true
	}
	if u == nil || another == nil {
		return false
	}
	return bytes.Equal(u.Bytes(), another.Bytes())
}

// ParseBytes converts a AuthKey in byte form to object.
func ParseBytes(b []byte) (AuthKey, error) {
	var authKey AuthKey
	if len(b) != 16 {
		return authKey, errors.New(fmt.Sprintf("invalid AuthKey: %v", b))
	}
	copy(authKey[:], b)
	return authKey, nil
}

// ParseAuthKeyFromString converts a AuthKey in string form to object.
func ParseAuthKeyFromString(str string) *AuthKey {
	var authKey AuthKey
	m := md5.New()
	m.Write([]byte(str))
	r := m.Sum(nil)
	copy(authKey[:], r[:16])
	return &authKey
}

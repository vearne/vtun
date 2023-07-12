package xproto

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
)

const ProtocolVersion = 1

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

const ClientSendPacketHeaderLength = 19
const ServerSendPacketHeaderLength = 3

// ConvertLength []byte length to int length
func ConvertLength(header []byte) int {
	length := 0
	if len(header) >= 2 {
		length = ((length & 0x00) | int(header[0])) << 8
		length = length | int(header[1])
	}
	return length
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

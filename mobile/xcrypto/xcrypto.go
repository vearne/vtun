package xcrypto

import (
	"github.com/golang/snappy"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/x/xcrypto"
)

var xp = xcrypto.XCrypto{}

func Init(key string) error {
	err := xp.Init(key)
	if err != nil {
		return err
	}
	return nil
}

func Decode(ci []byte) []byte {
	res, err := xp.Decode(ci)
	if err != nil {
		return nil
	}
	return res
}

func Encode(ci []byte) []byte {
	res, err := xp.Encode(ci)
	if err != nil {
		return nil
	}
	return res
}

func Encrypt(b []byte, xor, compress bool) ([]byte, error) {
	if xor {
		b = cipher.XOR(b)
	}
	b, err := xp.Encode(b)
	if err != nil {
		return nil, err
	}
	if compress {
		b = snappy.Encode(nil, b)
	}
	return b, nil
}

func Decrypt(b []byte, xor, compress bool) ([]byte, error) {
	var err error
	if compress {
		b, err = snappy.Decode(nil, b)
		if err != nil {
			return nil, err
		}
	}
	b, err = xp.Decode(b)
	if err != nil {
		return nil, err
	}
	if xor {
		b = cipher.XOR(b)
	}
	return b, nil
}

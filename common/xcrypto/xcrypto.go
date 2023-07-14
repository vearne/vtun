package xcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
)

type XCrypto struct {
	Key    []byte
	Nonce  []byte
	aesGcm cipher.AEAD
}

func (x *XCrypto) Load(key string) {
	x.LoadKey(key)
	x.LoadNonce(key)
}

func (x *XCrypto) LoadKey(key string) {
	h := sha256.New()
	h.Write([]byte(key))
	x.Key = h.Sum(nil)
}

func (x *XCrypto) LoadNonce(key string) {
	h := sha1.New()
	h.Write([]byte(key))
	b := h.Sum(nil)
	x.Nonce = b[:12]
}

func (x *XCrypto) Init(key string) error {
	x.Load(key)
	return x.init()
}

func (x *XCrypto) init() error {
	block, err := aes.NewCipher(x.Key)
	if err != nil {
		return err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	x.aesGcm = aesGcm
	return nil
}

func (x *XCrypto) Encode(pl []byte) ([]byte, error) {
	ci := x.aesGcm.Seal(nil, x.Nonce, pl, nil)
	return ci, nil
}

func (x *XCrypto) Decode(ci []byte) ([]byte, error) {
	pl, err := x.aesGcm.Open(nil, x.Nonce, ci, nil)
	if err != nil {
		return nil, err
	}
	return pl, nil
}

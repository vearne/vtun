package xcrypto

import (
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestXCrypto_Load(t *testing.T) {
	testKey := "aaa"
	x := &XCrypto{}
	err := x.Init(testKey)
	if err != nil {
		t.Error("err: ", err)
		return
	}
	log.Printf("key: %v\n", x.Key)
	assert.Equal(t, x.Key, []byte{152, 52, 135, 109, 207, 176, 92, 177, 103, 165, 194, 73, 83, 235, 165, 140, 74, 200, 155, 26, 223, 87, 242, 143, 47, 157, 9, 175, 16, 126, 232, 240})
	log.Printf("nonce: %v\n", x.Nonce)
	assert.Equal(t, x.Nonce, []byte{13, 231, 79, 177, 237, 8, 250, 8, 211, 128, 99, 246})
}

func TestXCrypto_Encode(t *testing.T) {
	testKey := "aaa"
	x := &XCrypto{}
	err := x.Init(testKey)
	if err != nil {
		t.Error("err: ", err)
		return
	}
	encode, err := x.Encode([]byte{97, 97, 97})
	if err != nil {
		t.Error("err: ", err)
		return
	}
	log.Printf("encode: %v\n", encode)
	assert.Equal(t, encode, []byte{18, 6, 238, 145, 241, 153, 166, 123, 28, 246, 132, 118, 19, 1, 18, 100, 122, 172, 103})
}

func TestXCrypto_Decode(t *testing.T) {
	testKey := "aaa"
	x := &XCrypto{}
	err := x.Init(testKey)
	if err != nil {
		t.Error("err: ", err)
		return
	}
	decode, err := x.Decode([]byte{18, 6, 238, 145, 241, 153, 166, 123, 28, 246, 132, 118, 19, 1, 18, 100, 122, 172, 103})
	if err != nil {
		t.Error("err: ", err)
		return
	}
	log.Printf("decode: %v\n", decode)
	assert.Equal(t, decode, []byte{97, 97, 97})
}

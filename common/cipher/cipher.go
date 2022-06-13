package cipher

// The default key
var _key = []byte("vtun@2022")

// SetKey sets the key
func SetKey(key string) {
	_key = []byte(key)
}

// XOR encrypts the data
func XOR(src []byte) []byte {
	_klen := len(_key)
	for i := 0; i < len(src); i++ {
		src[i] ^= _key[i%_klen]
	}
	return src
}

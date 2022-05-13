package cipher

var _key = []byte("vtun@2022")

func SetKey(key string) {
	_key = []byte(key)
}

func XOR(src []byte) []byte {
	_klen := len(_key)
	for i := 0; i < len(src); i++ {
		src[i] ^= _key[i%_klen]
	}
	return src
}

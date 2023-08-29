package cipher

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestXOR(t *testing.T) {
	data := []byte(time.Now().String())
	src := make([]byte, len(data))
	copy(src, data)

	encode := XOR(src)
	assert.NotEqualValues(t, data, encode)

	decode := XOR(encode)
	assert.EqualValues(t, data, decode)
}

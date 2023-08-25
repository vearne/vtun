package counter

import (
	"fmt"
	"sync/atomic"

	"github.com/inhies/go-bytesize"
)

// totalReadBytes is the total number of bytes read
var _totalReadBytes uint64 = 0

// totalWrittenBytes is the total number of bytes written
var _totalWrittenBytes uint64 = 0

// IncrReadBytes increments the number of bytes read
func IncrReadBytes(n int) {
	atomic.AddUint64(&_totalReadBytes, uint64(n))
}

// IncrWrittenBytes increments the number of bytes written
func IncrWrittenBytes(n int) {
	atomic.AddUint64(&_totalWrittenBytes, uint64(n))
}

// GetReadBytes returns the number of bytes read
func GetReadBytes() uint64 {
	return atomic.LoadUint64(&_totalReadBytes)
}

// GetWrittenBytes returns the number of bytes written
func GetWrittenBytes() uint64 {
	return atomic.LoadUint64(&_totalWrittenBytes)
}

// PrintBytes returns the bytes info
func PrintBytes(serverMode bool) string {
	if serverMode {
		return fmt.Sprintf("download %v upload %v", bytesize.New(float64(GetWrittenBytes())).String(), bytesize.New(float64(GetReadBytes())).String())
	}
	return fmt.Sprintf("download %v upload %v", bytesize.New(float64(GetReadBytes())).String(), bytesize.New(float64(GetWrittenBytes())).String())
}

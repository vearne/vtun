package counter

import "sync/atomic"

var _totalReadBytes uint64 = 0
var _totalWrittenBytes uint64 = 0

func IncrReadBytes(n int) {
	atomic.AddUint64(&_totalReadBytes, uint64(n))
}

func IncrWrittenBytes(n int) {
	atomic.AddUint64(&_totalWrittenBytes, uint64(n))
}

func GetReadBytes() uint64 {
	return _totalReadBytes
}

func GetWrittenBytes() uint64 {
	return _totalWrittenBytes
}

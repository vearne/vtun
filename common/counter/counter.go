package counter

import "sync/atomic"

//TotalReadByte ...
var TotalReadByte uint64 = 0

//TotalWriteByte ...
var TotalWriteByte uint64 = 0

//IncrReadByte ...
func IncrReadByte(n int) {
	atomic.AddUint64(&TotalReadByte, uint64(n))
}

//IncrWriteByte ...
func IncrWriteByte(n int) {
	atomic.AddUint64(&TotalWriteByte, uint64(n))
}

package memorypool

import (
	"sync"

	"github.com/Evan2698/netstackm/common"
)

var (
	memorypool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, common.CONFIGMTU)
		},
	}
)

// Alloc ...
func Alloc() []byte {
	return memorypool.Get().([]byte)
}

// Free ..
func Free(b []byte) {
	if b != nil {
		memorypool.Put(b)
	}
}

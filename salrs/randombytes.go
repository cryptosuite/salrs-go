package salrs

import (
	"math/rand"
	"time"
)

func randombytes(len int) (sd []byte) {
	rand.Seed(time.Now().UnixNano())
	var i int
	tmp := make([]byte, len, len)
	for i = 0; i < len; i++ {
		num := rand.Intn(256)
		tmp[i] = byte(num)
	}
	return tmp
}

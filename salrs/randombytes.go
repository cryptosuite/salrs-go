package salrs

import (
	"crypto/rand"
	"log"
	"math/big"
)

func randombytes(len int) (res []byte) {
	rng := rand.Reader
	var i int
	res = make([]byte, len, len)
	for i = 0; i < len; i++ {
		num, err := rand.Int(rng, big.NewInt(256))
		if err != nil {
			log.Fatalln("randombytes error")
		}
		res[i] = byte(num.Int64())
	}
	return
}

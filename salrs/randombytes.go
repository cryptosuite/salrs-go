package salrs

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/sha3"
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

// randomBytesFromCRand generate a given length of seed from crypto/rand.
func randomBytesFromCRand(len int) ([]byte, error) {
	seed := rand.Reader
	res := make([]byte, len)
	for i := 0; i < len; i++ {
		num, err := rand.Int(seed, big.NewInt(256))
		if err != nil {
			return nil, err
		}
		res[i] = byte(num.Int64())
	}
	return res, nil
}

// randomIntFromSeed generate [0,max) from seed, the max must not more than 256.
func randomIntFromSeed(seed []byte, pos int, max int) (int, []byte, int,error) {
	if max>256{
		return -1,seed,pos,fmt.Errorf("the max number must be not more than 256")
	}
	for {
		if pos >= len(seed) {
			tmp := sha3.Sum256(seed[len(seed)-32:])
			for i := 0; i < len(tmp); i++ {
				seed = append(seed, tmp[i])
			}
		}
		if int(seed[pos]) < max {
			return int(seed[pos]), seed, pos + 1,nil
		} else {
			pos++
		}
	}
}

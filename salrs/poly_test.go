package salrs

import (
	"math/rand"
	"testing"
	"time"
)

func randomInt64(rng *rand.Rand) int64{
	return rng.Int63n(Q)

}
func TestBigNumberMultiplication2(t *testing.T) {
	seed:=time.Now().UTC().UnixNano()
	rng:=rand.New(rand.NewSource(seed))
	a:=randomInt64(rng)
	seed=time.Now().UTC().UnixNano()
	rng=rand.New(rand.NewSource(seed))
	b:=randomInt64(rng)
	res := BigNumberMultiplication(a, b)
	if got:=BigNumberMultiplication2(a,b);got!=res {
		t.Errorf("BigNumberMultiplication2(%v,%v) = %v",a,b,got)
	}
}

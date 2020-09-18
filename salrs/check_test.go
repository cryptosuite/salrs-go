package salrs

import (
	"encoding/hex"
	"log"
	"testing"
	"time"
)


func TestCheckTNorm(t *testing.T) {
	var v polyveck
	for i:=0;i<K;i++{
		for j:=0;j<N;j++{
			v.vec[i].coeffs[j]= randomInt64()
			time.Sleep(3*time.Nanosecond)
		}
	}
	want:=CheckTNorm(v)
	got:=v.CheckInQ()
	if got!=want {
		t.Errorf("CheckInGmte(%v) = %v, want= %v",v,got,want)
	}
}
func TestCheckZNorm(t *testing.T) {
	var v polyvecl
	for i:=0;i<L;i++{
		for j:=0;j<N;j++{
			v.vec[i].coeffs[j]= randomInt64()
			time.Sleep(3*time.Nanosecond)
		}
	}
	want:=CheckZNorm(v)
	got:=v.CheckInGmte()
	if got!=want {
		t.Errorf("CheckInGmte(%v) = %v, want= %v",v,got,want)
	}
}
func TestCheckInOne(t *testing.T) {
	 a:=NewPoly()
	 for i:=0;i<N;i++{
	 	a.coeffs[i]=randomInt64()
	 	time.Sleep(3*time.Nanosecond)
	 }
	want:=CheckC(*a)
	got:=a.CheckInOne()
	if got!=want {
		t.Errorf("CheckInOne(%v) = %v, want= %v",a,got,want)
	}
}
func TestEqualC(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < N; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want:=EqualC(*a,*b)
	got:=a.Equal(b)
	if got!=want {
		t.Errorf("EqualC(%v,%v) = %v, want= %v",a,b,got,want)
	}
}
func TestEqualI(t *testing.T) {
	var v,p polyvecm
	for i:=0;i<M;i++{
		for j:=0;j<N;j++{
			v.vec[i].coeffs[j]=randomInt64()
			time.Sleep(3*time.Nanosecond)
			p.vec[i].coeffs[j]=randomInt64()
			time.Sleep(3*time.Nanosecond)
		}
	}
	want:=EqualI(v,p)
	got:=v.Equal(&p)
	if got!=want{
		t.Errorf("Equal(%v,%v) = %v, want= %v",v,p,got,want)
	}

}
func TestEqualdpk(t *testing.T) {
	seed, err := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	if err!=nil{
		log.Fatal(err)
	}
	mpk, _, _, _,err := GenerateMasterKey(seed)
	if err!=nil {
		log.Fatal(err)
	}
	dpk1, err := GenerateDerivedPubKey(mpk)
	if err!=nil{
		log.Fatal(err)
	}
	dpk2, err := GenerateDerivedPubKey(mpk)
	if err!=nil{
		log.Fatal(err)
	}
	want:=[2]bool{true,false}
	got:=[2]bool{dpk1.Equal(dpk1),dpk1.Equal(dpk2)}
	for i:=0;i<2;i++{
		if got[i]!=want[i] {
			t.Errorf("dpk.Equal() logical error")
		}
	}
}

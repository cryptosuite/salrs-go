package salrs

import (
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
	got:=v.CheckTNorm()
	if got!=want {
		t.Errorf("CheckTNorm(%v) = %v, want= %v",v,got,want)
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
	got:=v.CheckZNorm()
	if got!=want {
		t.Errorf("CheckZNorm(%v) = %v, want= %v",v,got,want)
	}
}
func TestCheckC(t *testing.T) {
	 a:=NewPoly()
	 for i:=0;i<N;i++{
	 	a.coeffs[i]=randomInt64()
	 	time.Sleep(3*time.Nanosecond)
	 }
	want:=CheckC(*a)
	got:=a.CheckC()
	if got!=want {
		t.Errorf("CheckC(%v) = %v, want= %v",a,got,want)
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
	got:=a.EqualC(b)
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
	got:=v.EqualI(&p)
	if got!=want{
		t.Errorf("EqualI(%v,%v) = %v, want= %v",v,p,got,want)
	}

}

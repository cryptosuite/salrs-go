package salrs

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func randomInt64() int64 {
	seed := time.Now().UTC().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	return rng.Int63n(Q)
}
func TestBigNumberMultiplication(t *testing.T) {
	a := randomInt64()
	time.Sleep(3 * time.Nanosecond)
	b := randomInt64()
	want := BigNumberMultiplication(a, b)
	if got := BigNumberMultiplication1(a, b); got != want {
		t.Errorf("BigNumberMultiplication1(%v,%v) = %v,want = %v", a, b, got, want)
	}
}

func TestPoly_Add(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < N; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := polyAddition(*a, *b)
	got := NewPoly().Add(a, b)
	if !want.Equal(got) {
		t.Errorf("poly.Add(%v,%v) = %v,want = %v", a, b, got, want)
	}
}
func TestPoly_Sub(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < N; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := polySubstraction(*a, *b)
	got := NewPoly().Sub(a, b)
	if !want.Equal(got) {
		t.Errorf("poly.Add(%v,%v) = %v,want = %v", a, b, got, want)
	}
}

func TestPoly_MulLow16(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < 16; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := polyMulNormalSixteen(*a, *b)
	got := NewPoly().MulLow16(a, b)
	if !want.Equal(got) {
		t.Errorf("poly.MulLow16(%v,%v) = %v,want = %v", a, b, got, want)
	}
}

func TestPoly_Divide(t *testing.T) {
	a := NewPoly()
	for i := 0; i < N; i++ {
		a.coeffs[i] = randomInt64()
	}
	a111, a112, a121, a122, a211, a212, a221, a222 := polyModEight(*a)
	got := a.Divide()
	switch {
	case !a111.Equal(got[1][1][1]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a111, got[1][1][1])
	case !a112.Equal(got[1][1][2]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a112, got[1][1][2])

	case !a121.Equal(got[1][2][1]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a121, got[1][2][1])

	case !a122.Equal(got[1][2][2]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a122, got[1][2][2])

	case !a211.Equal(got[2][1][1]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a211, got[2][1][1])

	case !a212.Equal(got[2][1][2]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a212, got[2][1][2])

	case !a221.Equal(got[2][2][1]):
		t.Errorf("poly.Divide a111=%v,got[0]=%v", a221, got[2][2][1])

	case !a222.Equal(got[2][2][2]):
		t.Errorf("poly.Divide a222=%v,got[0]=%v", a222, got[2][2][2])
	}
}

func BenchmarkKaratsuba(t *testing.B) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < 32; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := polyMulKaratsuba(*a, *b)
	fmt.Printf("%v,%v = %v", a, b, want)
}
func BenchmarkPoly_MulKaratsubaKaratsuba(t *testing.B) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < 32; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := NewPoly().MulKaratsuba(a, b)
	fmt.Printf("%v,%v = %v", a, b, want)
}

func TestPoly_MulKaratsuba(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < 32; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want1 := polyMulKaratsuba(*a, *b)
	want2 := NewPoly().MulLow32(a, b)
	if !want2.Equal(&want1) {
		fmt.Println("polyMulKaratsuba err")
	}
	//fmt.Println("want = ",want)
	got := NewPoly().MulKaratsuba(a, b)
	if !want2.Equal(got) {
		t.Errorf("poly.MulKaratsuba(%v,%v) = %v,want2 = %v", a, b, got, want2)
	}
}

func TestPoly_Mul(t *testing.T) {
	a := NewPoly()
	b := NewPoly()
	for i := 0; i < N; i++ {
		a.coeffs[i] = randomInt64()
		time.Sleep(3 * time.Nanosecond)
		b.coeffs[i] = randomInt64()
	}
	want := polyMultiplication(*a, *b)
	got := NewPoly().Mul(a, b)
	if !want.Equal(got) {
		t.Errorf("poly.Mul(%v,%v) = %v,want = %v", a, b, got, want)
	}
}

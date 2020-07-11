package salrs

import (
	"math/big"
)

type poly struct {
	coeffs [N]int64
}

type polyvecl struct {
	vec [L]poly
}

type polyveck struct {
	vec [K]poly
}

//note that M = 1, although polyvecm here equals to poly, we still define a struct for polyvecm
type polyvecm struct {
	vec [M]poly
}

/*************************************************
* Name:        reduce
*
* Description: For an element a, compute and output
*              r = a mod¡À q.
*
* Arguments:   - a int64: element a
*
* Returns r.
**************************************************/
func reduce(a int64) int64 {
	var tmp int64
	tmp = a % Q
	if tmp > Q2 {
		tmp -= Q
	}
	if tmp < -Q2 {
		tmp += Q
	}
	return tmp
}

/*************************************************
 * Name:        poly_addition
 *
 * Description: addition of polynomials.
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    -a *poly: pointer to first input polynomial
 *              - b *poly: pointer to second input polynomial
 *              - c *poly: pointer to output polynomial
 **************************************************/
// poly.Add compute the sum of the receiver and the input
func (z *poly) Add(a,b *poly) *poly {
	for i := 0; i < N; i++ {
		z.coeffs[i] = a.coeffs[i] + b.coeffs[i]
		z.coeffs[i] = reduce(z.coeffs[i])
	}
	return z
}
func polyAddition(a poly, b poly) (c poly) {
	//var i int32
	var C poly
	var i int
	for i = 0; i < N; i++ {
		C.coeffs[i] = a.coeffs[i] + b.coeffs[i]
		C.coeffs[i] = reduce(C.coeffs[i])
	}
	return C
}

/*************************************************
 * Name:        poly_substraction
 *
 * Description: substraction of polynomials.
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - a *poly: pointer to first input polynomial
 *              - b *poly: pointer to second input polynomial
 *              - poly *c: pointer to output polynomial
 **************************************************/
func (z *poly) Sub(a,b *poly) *poly {
	for i := 0; i < N; i++ {
		z.coeffs[i] = a.coeffs[i] - b.coeffs[i]
		z.coeffs[i] = reduce(z.coeffs[i])
	}
	return z
}
func polySubstraction(a poly, b poly) (c poly) {
	//int i;
	var C poly
	for i := 0; i < N; i++ {
		C.coeffs[i] = a.coeffs[i] - b.coeffs[i]
		C.coeffs[i] = reduce(C.coeffs[i])
	}
	return C
}

/*************************************************
 * Name:        big_number_multiplication
 *
 * Description: multiplication of big numbers
 *             (especially for those whose product is bigger than 2^64).
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - long long a: pointer to first input number
 *              - long long b: pointer to second input number

 **************************************************/
// can be substituded by big.Int
func BigNumberMultiplication2(a, b int64) (res int64) {
	var factor1, factor2, modQ big.Int
	factor1 = *factor1.SetInt64(a)
	factor2 = *factor2.SetInt64(b)
	modQ = *modQ.SetInt64(int64(Q))
	tmp := big.NewInt(0).Mul(&factor1, &factor2)
	tmp.Mod(tmp, &modQ)
	return reduce(tmp.Int64())
}
func BigNumberMultiplication(a int64, b int64) (ans int64) {
	var tmp1 [30]int64
	var an int64
	var count1, count2, i int = 0, 0, 0
	var t1, t2, t3, t4 int64
	an = 0
	if a < 0 {
		t1 = -a
	} else {
		t1 = a
	}
	if b < 0 {
		t2 = -b
	} else {
		t2 = b
	}
	t3 = t1
	t4 = t2
	//while (t1 != 0)
	for i = 0; i < 10; i-- {
		if t1 == 0 {
			break
		}
		count1++
		t1 = t1 / 10
	}
	//while (t2 != 0)
	for i = 0; i < 10; i-- {
		if t2 == 0 {
			break
		}
		count2++
		t2 = t2 / 10
	}
	if count1+count2 <= 18 {
		return reduce(a * b)
	} else {
		for i = 0; i < 30; i++ {
			tmp1[i] = 0
		}
		t1 = t3 % 100000
		t2 = t3 / 100000
		t1 = t4 * t1
		t2 = t4 * t2
		count1 = 0
		//while (t1 != 0)
		for i = 0; i < 10; i-- {
			if t1 == 0 {
				break
			}
			tmp1[count1] = t1 % 10
			count1++
			t1 = t1 / 10
		}
		count1 = 5
		//while (t2 != 0)
		for i = 0; i < 10; i-- {
			if t2 == 0 {
				break
			}
			tmp1[count1] += t2 % 10
			count1++
			t2 = t2 / 10
		}
	}

	for i = 25; i >= 0; i-- {
		an = (an*10 + tmp1[i]) % Q
	}
	if (a < 0 && b > 0) || (a > 0 && b < 0) {
		return -an
	}
	return reduce(an)
}

/*************************************************
 * Name:        poly_num_mul_poly
 *
 * Description: polynomials multiply with numbers.
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - poly *a: pointer to input polynomial
 *              - long long *b: pointer to input number
 *              - poly *c: pointer to output polynomial
 **************************************************/
func (z *poly) Scale(a *poly, b int64) *poly {
	for i := 0; i < N; i++ {
		z.coeffs[i] = BigNumberMultiplication(a.coeffs[i], b)
		z.coeffs[i] = reduce(z.coeffs[i])
	}
	return z
}
func polyNumMulPoly(a poly, b int64) (c poly) {
	var i int
	var C poly
	for i = 0; i < N; i++ {
		C.coeffs[i] = BigNumberMultiplication(a.coeffs[i], b)
		C.coeffs[i] = reduce(C.coeffs[i])
	}
	return C
}

/*************************************************
 * Name:        poly_mod_one
 *
 * Description: a big poly mod (x^n - r0) into one small poly
 *              used for poly_multiplication
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments    - long long r0: the root
 *              - long long n; degree of a
 *              - poly *a: pointer input and output polynomial

 **************************************************/
func (z *poly) Mod(a *poly, n int64, r int64) *poly {
	if n == 32 {
		for i := 0; i < 32; i++ {
			z.coeffs[i] += BigNumberMultiplication(a.coeffs[i+32], r)
			z.coeffs[i] = reduce(z.coeffs[i])
		}
	}
	return z
}
func polyModOne(r0 int64, n int64, a poly) (b poly) {
	var i int
	var B poly
	if n == 32 {
		for i = 0; i < 32; i++ {
			B.coeffs[i] += BigNumberMultiplication(a.coeffs[i+32], r0)
			B.coeffs[i] = reduce(a.coeffs[i])
		}
	}
	return B
}

/*************************************************
 * Name:        poly_mul_normal_sixteen
 *
 * Description: the normal version of multiplication of polynomials of degree sixteen
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - poly *a: pointer to first input polynomial
 *              - poly *b: pointer to second input polynomial
 *              - poly *c: pointer to output polynomial

 **************************************************/
func (z *poly) MulLow16(a, b *poly) *poly {
	for i := 0; i < N; i++ {
		z.coeffs[i] = 0
	}
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			m := i + j
			z.coeffs[m] += BigNumberMultiplication2(a.coeffs[i], b.coeffs[j])
			z.coeffs[m] = reduce(z.coeffs[m])
		}
	}
	return z
}
func (z *poly) MulLow32(a, b *poly) *poly {
	for i := 0; i < N; i++ {
		z.coeffs[i] = 0
	}
	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			m := i + j
			z.coeffs[m] += BigNumberMultiplication(a.coeffs[i], b.coeffs[j])
			z.coeffs[m] = reduce(z.coeffs[m])
		}
	}
	return z
}
func polyMulNormalSixteen(a poly, b poly) (c poly) {
	var m, i, j int
	var C poly
	for i = 0; i < N; i++ {
		C.coeffs[i] = 0
	}
	for i = 0; i < 16; i++ {
		for j = 0; j < 16; j++ {
			m = i + j
			C.coeffs[m] += BigNumberMultiplication(a.coeffs[i], b.coeffs[j])
			C.coeffs[m] = reduce(C.coeffs[m])
		}
	}
	return C
}

/*************************************************
 * Name:        poly_mod_eight
 *
 * Description: a big poly mod (x^32 - r0) ~ (x^32 - r7) into eight small poly
 *              used for poly_multiplication
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - poly *a: pointer to input polynomial
 *              - poly *b: pointer to first output polynomial
 *              - poly *c: pointer to second output polynomial
 *              - long long r0: one of the root
 *              - long long r1: one of the root
 *              - long long n: degree of a

 **************************************************/
func (z *poly) Divide() (res [3][3][3]*poly) {
	for i := 1; i < 3; i++ {
		for j := 1; j < 3; j++ {
			for k := 1; k < 3; k++ {
				res[i][j][k] = NewPoly()
			}
		}
	}
	var a [3]*poly  //a1=a[1],a2=a[2]
	var a1 [3]*poly //a11=a1[1],a12=a1[2]
	var a2 [3]*poly //a21=a2[1],a22=a2[2]
	for i := 1; i < 3; i++ {
		a[i] = NewPoly()
		a1[i] = NewPoly()
		a2[i] = NewPoly()
	}

	var tmp [8]int64
	// compute a1,a2
	for i := 0; i < N/2; i++ {
		tmp[4] = BigNumberMultiplication(z.coeffs[i+N/2], -R4)
		a[1].coeffs[i] = reduce(z.coeffs[i] + tmp[4])
		a[2].coeffs[i] = reduce(z.coeffs[i] - tmp[4])
	}
	// compute a11,a12,a21,a22
	for i := 0; i < N/4; i++ {
		tmp[2] = BigNumberMultiplication(a[2].coeffs[i+N/4], -R2)
		tmp[6] = BigNumberMultiplication(a[1].coeffs[i+N/4], -R6)
		a1[1].coeffs[i] = reduce(a[1].coeffs[i] + tmp[6])
		a1[2].coeffs[i] = reduce(a[1].coeffs[i] - tmp[6])
		a2[1].coeffs[i] = reduce(a[2].coeffs[i] + tmp[2])
		a2[2].coeffs[i] = reduce(a[2].coeffs[i] - tmp[2])
	}
	// compute a111~a222
	for i := 0; i < N/8; i++ {
		tmp[1] = BigNumberMultiplication(a2[2].coeffs[i+N/8], -R1)
		tmp[3] = BigNumberMultiplication(a1[2].coeffs[i+N/8], -R3)
		tmp[5] = BigNumberMultiplication(a2[1].coeffs[i+N/8], -R5)
		tmp[7] = BigNumberMultiplication(a1[1].coeffs[i+N/8], -R7)
		res[1][1][1].coeffs[i] = reduce(a1[1].coeffs[i] + tmp[7]) //a111
		res[1][1][2].coeffs[i] = reduce(a1[1].coeffs[i] - tmp[7]) //a112
		res[1][2][1].coeffs[i] = reduce(a1[2].coeffs[i] + tmp[3]) //a121
		res[1][2][2].coeffs[i] = reduce(a1[2].coeffs[i] - tmp[3]) //a122
		res[2][1][1].coeffs[i] = reduce(a2[1].coeffs[i] + tmp[5]) //a211
		res[2][1][2].coeffs[i] = reduce(a2[1].coeffs[i] - tmp[5]) //a212
		res[2][2][1].coeffs[i] = reduce(a2[2].coeffs[i] + tmp[1]) //a221
		res[2][2][2].coeffs[i] = reduce(a2[2].coeffs[i] - tmp[1]) //a222
	}
	return res
}
func polyModEight(a poly) (a111 poly, a112 poly, a121 poly, a122 poly,
	a211 poly, a212 poly, a221 poly, a222 poly) {
	var tmp, i int64
	var A111, A112, A121, A122, A211, A212, A221, A222 poly
	var a1, a2, a11, a12, a21, a22 poly
	for i = 0; i < N; i++ {
		a1.coeffs[i] = 0
		a2.coeffs[i] = 0
		a11.coeffs[i] = 0
		a12.coeffs[i] = 0
		a21.coeffs[i] = 0
		a22.coeffs[i] = 0
	}
	// compute a1,a2
	for i = 0; i < N/2; i++ {
		tmp = BigNumberMultiplication(a.coeffs[i+N/2], -R4)
		a1.coeffs[i] = a.coeffs[i] + tmp
		a1.coeffs[i] = reduce(a1.coeffs[i])
		a2.coeffs[i] = a.coeffs[i] - tmp
		a2.coeffs[i] = reduce(a2.coeffs[i])
	}
	//compute a11,a12
	for i = 0; i < N/4; i++ {
		tmp = BigNumberMultiplication(a1.coeffs[i+N/4], -R6)
		a11.coeffs[i] = a1.coeffs[i] + tmp
		a11.coeffs[i] = reduce(a11.coeffs[i])
		a12.coeffs[i] = a1.coeffs[i] - tmp
		a12.coeffs[i] = reduce(a12.coeffs[i])
	}
	// compute a21,a22
	for i = 0; i < N/4; i++ {
		tmp = BigNumberMultiplication(a2.coeffs[i+N/4], -R2)
		a21.coeffs[i] = a2.coeffs[i] + tmp
		a21.coeffs[i] = reduce(a21.coeffs[i])
		a22.coeffs[i] = a2.coeffs[i] - tmp
		a22.coeffs[i] = reduce(a22.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = BigNumberMultiplication(a11.coeffs[i+N/8], -R7)
		A111.coeffs[i] = a11.coeffs[i] + tmp
		A111.coeffs[i] = reduce(A111.coeffs[i])
		A112.coeffs[i] = a11.coeffs[i] - tmp
		A112.coeffs[i] = reduce(A112.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = BigNumberMultiplication(a12.coeffs[i+N/8], -R3)
		A121.coeffs[i] = a12.coeffs[i] + tmp
		A121.coeffs[i] = reduce(A121.coeffs[i])
		A122.coeffs[i] = a12.coeffs[i] - tmp
		A122.coeffs[i] = reduce(A122.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = BigNumberMultiplication(a21.coeffs[i+N/8], -R5)
		A211.coeffs[i] = a21.coeffs[i] + tmp
		A211.coeffs[i] = reduce(A211.coeffs[i])
		A212.coeffs[i] = a21.coeffs[i] - tmp
		A212.coeffs[i] = reduce(A212.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = BigNumberMultiplication(a22.coeffs[i+N/8], -R1)
		A221.coeffs[i] = a22.coeffs[i] + tmp
		A221.coeffs[i] = reduce(A221.coeffs[i])
		A222.coeffs[i] = a22.coeffs[i] - tmp
		A222.coeffs[i] = reduce(A222.coeffs[i])
	}
	return A111, A112, A121, A122, A211, A212, A221, A222
}

/*************************************************
 * Name:        poly_mul_karatsuba
 *
 * Description: multiplication of small polynomials, the degree of which is 32,
 *               using karatsuba.
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - poly *a: pointer to first input polynomial
 *              - poly *b: pointer to second input polynomial
 *              - poly *c: pointer to output polynomial

 **************************************************/
func (z *poly) MulKaratsuba(a, b *poly) *poly {
	var f, g, fg [2]*poly
	for i := 0; i < 2; i++ {
		f[i] = NewPoly()
		g[i] = NewPoly()
	}
	// compute f0,f1,g0,g1
	for i := 0; i < 16; i++ {
		f[0].coeffs[i] = a.coeffs[i]
		f[1].coeffs[i] = a.coeffs[i+16]
		g[0].coeffs[i] = b.coeffs[i]
		g[1].coeffs[i] = b.coeffs[i+16]
	}
	// compute f0g0,f1g1
	for i := 0; i < 2; i++ {
		fg[i] = NewPoly().MulLow16(f[i], g[i])
	}
	tmp := NewPoly()
	for i := 0; i < 32; i++ {
		tmp.coeffs[i] += fg[0].coeffs[i]
		tmp.coeffs[i] = reduce(tmp.coeffs[i])
		tmp.coeffs[i+16] -= fg[1].coeffs[i]
		tmp.coeffs[i+16] = reduce(tmp.coeffs[i+16])
	}
	res1 := NewPoly()
	for i := 0; i < 16; i++ {
		res1.coeffs[i] = tmp.coeffs[i]
	}
	for i := 16; i < 48; i++ {
		res1.coeffs[i] = tmp.coeffs[i] - tmp.coeffs[i-16]
		res1.coeffs[i] = reduce(res1.coeffs[i])
	}
	for i := 48; i < 64; i++ {
		res1.coeffs[i] = -tmp.coeffs[i-16]
		res1.coeffs[i] = reduce(res1.coeffs[i])
	}
	f[0] = f[0].Add(f[0], f[1])
	g[0] = g[0].Add(g[0], g[1])
	tmp = tmp.MulLow16(f[0], g[0])
	z = NewPoly()
	for i := 0; i < 16; i++ {
		z.coeffs[i] = res1.coeffs[i]
	}
	for i := 16; i < 48; i++ {
		z.coeffs[i] = res1.coeffs[i] + tmp.coeffs[i-16]
		z.coeffs[i] = reduce(z.coeffs[i])
	}
	for i := 48; i < 64; i++ {
		z.coeffs[i] = res1.coeffs[i]
	}
	return z
}
func polyMulKaratsuba(a poly, b poly) (c poly) {
	var a0, a1, b0, b1 poly
	var C poly
	var i int
	//here we have a0 = F0, a1 = F1, b0 = G0, b1 = G1;

	for i = 0; i < 16; i++ {
		a0.coeffs[i] = a.coeffs[i]
		a1.coeffs[i] = a.coeffs[i+16]
		b0.coeffs[i] = b.coeffs[i]
		b1.coeffs[i] = b.coeffs[i+16]
	}

	var a0b0, a1b1, a0a1, b0b1, tmp1, tmp2 poly
	a0b0 = polyMulNormalSixteen(a0, b0)
	a1b1 = polyMulNormalSixteen(a1, b1)

	for i = 32; i >= 0; i-- {
		a1b1.coeffs[i+16] = -a1b1.coeffs[i]
	}
	for i = 0; i < 16; i++ {
		a1b1.coeffs[i] = 0
	}

	tmp1 = polyAddition(a0b0, a1b1)

	//(1 - x^16)(F0G0 - x^16F1G1) where tmp1 = (F0G0 - x^16F1G1)
	var tmp3, tmp4 poly
	for i = 0; i < N; i++ {
		tmp3.coeffs[i] = 0
	}
	for i = 48; i >= 0; i-- {
		tmp3.coeffs[i+16] = -tmp1.coeffs[i]
	}
	tmp4 = polyAddition(tmp1, tmp3)
	//end (1 - x^16)(F0G0 - x^16F1G1) where tmp1 = (F0G0 - x^16F1G1)

	a0a1 = polyAddition(a0, a1)
	b0b1 = polyAddition(b0, b1)

	tmp2 = polyMulNormalSixteen(a0a1, b0b1)
	for i = 32; i >= 0; i-- {
		tmp2.coeffs[i+16] = tmp2.coeffs[i]
	}
	for i = 0; i < 16; i++ {
		tmp2.coeffs[i] = 0
	}

	C = polyAddition(tmp4, tmp2)
	return C
}

/*************************************************
 * Name:        poly_multiplication
 *
 * Description: multiplication of polynomials using partially-splitting mathod
 *              every element in the output polynomial should
 *              call reduce() to map into (-q/2, q/2)
 * Arguments:    - poly *a: pointer to first input polynomial
 *              - poly *b: pointer to second input polynomial
 *              - poly *c: pointer to output polynomial

 **************************************************/
func (z *poly) Mul(a, b *poly) *poly {
	da := a.Divide()
	db := b.Divide()
	var dz [3][3][3]*poly
	for i := 1; i < 3; i++ {
		for j := 1; j < 3; j++ {
			for k := 1; k < 3; k++ {
				dz[i][j][k] = NewPoly().MulKaratsuba(da[i][j][k], db[i][j][k])
			}
		}
	}
	var res, res1, res2 [3]*poly //z1,z2,z11,z12,z21,z22

	// compute z111~z222
	for i := 0; i < 32; i++ {
		dz[1][1][1].coeffs[i] -= reduce(BigNumberMultiplication(dz[1][1][1].coeffs[i+32], R7))
		dz[1][1][1].coeffs[i] = reduce(dz[1][1][1].coeffs[i])

		dz[1][1][2].coeffs[i] += reduce(BigNumberMultiplication(dz[1][1][2].coeffs[i+32], R7))
		dz[1][1][2].coeffs[i] = reduce(dz[1][1][2].coeffs[i])

		dz[1][2][1].coeffs[i] -= reduce(BigNumberMultiplication(dz[1][2][1].coeffs[i+32], R3))
		dz[1][2][1].coeffs[i] = reduce(dz[1][2][1].coeffs[i])

		dz[1][2][2].coeffs[i] += reduce(BigNumberMultiplication(dz[1][2][2].coeffs[i+32], R3))
		dz[1][2][2].coeffs[i] = reduce(dz[1][2][2].coeffs[i])

		dz[2][1][1].coeffs[i] -= reduce(BigNumberMultiplication(dz[2][1][1].coeffs[i+32], R5))
		dz[2][1][1].coeffs[i] = reduce(dz[2][1][1].coeffs[i])

		dz[2][1][2].coeffs[i] += reduce(BigNumberMultiplication(dz[2][1][2].coeffs[i+32], R5))
		dz[2][1][2].coeffs[i] = reduce(dz[2][1][2].coeffs[i])

		dz[2][2][1].coeffs[i] -= reduce(BigNumberMultiplication(dz[2][2][1].coeffs[i+32], R1))
		dz[2][2][1].coeffs[i] = reduce(dz[2][2][1].coeffs[i])

		dz[2][2][2].coeffs[i] += reduce(BigNumberMultiplication(dz[2][2][2].coeffs[i+32], R1))
		dz[2][2][2].coeffs[i] = reduce(dz[2][2][2].coeffs[i])
	}
	for i := 0; i < 32; i++ {
		//c111
		dz[1][1][1].coeffs[i+32] = dz[1][1][1].coeffs[i]
		dz[1][1][1].coeffs[i] = reduce(reduce(BigNumberMultiplication(dz[1][1][1].coeffs[i], -R7)))
		//c112
		dz[1][1][2].coeffs[i+32] = reduce(-dz[1][1][2].coeffs[i])
		dz[1][1][2].coeffs[i] = reduce(-BigNumberMultiplication(dz[1][1][2].coeffs[i], R7))
		//c121
		dz[1][2][1].coeffs[i+32] = dz[1][2][1].coeffs[i]
		dz[1][2][1].coeffs[i] = reduce(BigNumberMultiplication(dz[1][2][1].coeffs[i], -R3))
		//c122
		dz[1][2][2].coeffs[i+32] = reduce(-dz[1][2][2].coeffs[i])
		dz[1][2][2].coeffs[i] = reduce(-BigNumberMultiplication(dz[1][2][2].coeffs[i], R3))
		//c211
		dz[2][1][1].coeffs[i+32] = dz[2][1][1].coeffs[i]
		dz[2][1][1].coeffs[i] = reduce(BigNumberMultiplication(dz[2][1][1].coeffs[i], -R5))
		//c212
		dz[2][1][2].coeffs[i+32] = reduce(-dz[2][1][2].coeffs[i])
		dz[2][1][2].coeffs[i] = reduce(-BigNumberMultiplication(dz[2][1][2].coeffs[i], R5))
		//c221
		dz[2][2][1].coeffs[i+32] = dz[2][2][1].coeffs[i]
		dz[2][2][1].coeffs[i] = reduce(BigNumberMultiplication(dz[2][2][1].coeffs[i], -R1))
		//c222
		dz[2][2][2].coeffs[i+32] = reduce(-dz[2][2][2].coeffs[i])
		dz[2][2][2].coeffs[i] = reduce(-BigNumberMultiplication(dz[2][2][2].coeffs[i], R1))
	}

	// compute z11,z12,z21,z22
	res1[1] = NewPoly().Add(dz[1][1][1], dz[1][1][2])
	res1[2] = NewPoly().Add(dz[1][2][1], dz[1][2][2])
	res2[1] = NewPoly().Add(dz[2][1][1], dz[2][1][2])
	res2[2] = NewPoly().Add(dz[2][2][1], dz[2][2][2])
	for i := 0; i < 64; i++ {
		res1[1].coeffs[i] = reduce(BigNumberMultiplication(res1[1].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R1))))
		res1[2].coeffs[i] = reduce(BigNumberMultiplication(res1[2].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R5))))
		res2[1].coeffs[i] = reduce(BigNumberMultiplication(res2[1].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R3))))
		res2[2].coeffs[i] = reduce(BigNumberMultiplication(res2[2].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R7))))
	}
	for i := 0; i < 64; i++ {
		res1[1].coeffs[i+64] = res1[1].coeffs[i]
		res1[1].coeffs[i] = reduce(BigNumberMultiplication(res1[1].coeffs[i], -R6))

		res1[2].coeffs[i+64] = reduce(-res1[2].coeffs[i])
		res1[2].coeffs[i] = reduce(-BigNumberMultiplication(res1[2].coeffs[i], R6))

		res2[1].coeffs[i+64] = res2[1].coeffs[i]
		res2[1].coeffs[i] = reduce(BigNumberMultiplication(res2[1].coeffs[i], -R2))

		res2[2].coeffs[i+64] = reduce(-res2[2].coeffs[i])
		res2[2].coeffs[i] = reduce(-BigNumberMultiplication(res2[2].coeffs[i], R2))
	}

	//compute z1,z2
	res[1] = NewPoly().Add(res1[1], res1[2])
	res[2] = NewPoly().Add(res2[1], res2[2])
	for i := 0; i < 128; i++ {
		res[1].coeffs[i] = reduce(BigNumberMultiplication(res[1].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R2))))
		res[2].coeffs[i] = reduce(BigNumberMultiplication(res[2].coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R6))))
	}
	for i := 0; i < 128; i++ {
		res[1].coeffs[i+128] = res[1].coeffs[i]
		res[1].coeffs[i] = reduce(BigNumberMultiplication(res[1].coeffs[i], -R4))
		res[2].coeffs[i+128] = reduce(-res[2].coeffs[i])
		res[2].coeffs[i] = reduce(-BigNumberMultiplication(res[2].coeffs[i], R4))
	}
	z = NewPoly().Add(res[1], res[2])
	for i := 0; i < N; i++ {
		z.coeffs[i] = reduce(BigNumberMultiplication(z.coeffs[i], BigNumberMultiplication((Q+1)/2, R4)))
	}
	return z
}
func polyMultiplication(a poly, b poly) (c poly) {
	var i int
	var C poly
	var a111, a112, a121, a122, a211, a212, a221, a222 poly
	var b111, b112, b121, b122, b211, b212, b221, b222 poly
	var c111, c112, c121, c122, c211, c212, c221, c222 poly
	var c11, c12, c21, c22, c1, c2 poly

	a111, a112, a121, a122, a211, a212, a221, a222 = polyModEight(a)
	b111, b112, b121, b122, b211, b212, b221, b222 = polyModEight(b)
	c111 = polyMulKaratsuba(a111, b111)
	c112 = polyMulKaratsuba(a112, b112)
	c121 = polyMulKaratsuba(a121, b121)
	c122 = polyMulKaratsuba(a122, b122)
	c211 = polyMulKaratsuba(a211, b211)
	c212 = polyMulKaratsuba(a212, b212)
	c221 = polyMulKaratsuba(a221, b221)
	c222 = polyMulKaratsuba(a222, b222)

	for i = 0; i < 32; i++ {
		c111.coeffs[i] -= reduce(BigNumberMultiplication(c111.coeffs[i+32], R7))
		c111.coeffs[i] = reduce(c111.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c112.coeffs[i] += reduce(BigNumberMultiplication(c112.coeffs[i+32], R7))
		c112.coeffs[i] = reduce(c112.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c121.coeffs[i] -= reduce(BigNumberMultiplication(c121.coeffs[i+32], R3))
		c121.coeffs[i] = reduce(c121.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c122.coeffs[i] += reduce(BigNumberMultiplication(c122.coeffs[i+32], R3))
		c122.coeffs[i] = reduce(c122.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c211.coeffs[i] -= reduce(BigNumberMultiplication(c211.coeffs[i+32], R5))
		c211.coeffs[i] = reduce(c211.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c212.coeffs[i] += reduce(BigNumberMultiplication(c212.coeffs[i+32], R5))
		c212.coeffs[i] = reduce(c212.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c221.coeffs[i] -= reduce(BigNumberMultiplication(c221.coeffs[i+32], R1))
		c221.coeffs[i] = reduce(c221.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c222.coeffs[i] += reduce(BigNumberMultiplication(c222.coeffs[i+32], R1))
		c222.coeffs[i] = reduce(c222.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c111.coeffs[i+32] = c111.coeffs[i]
		c111.coeffs[i] = reduce(BigNumberMultiplication(c111.coeffs[i], -R7))

		c112.coeffs[i+32] = reduce(-c112.coeffs[i])
		c112.coeffs[i] = reduce(-BigNumberMultiplication(c112.coeffs[i], R7))

		c121.coeffs[i+32] = c121.coeffs[i]
		c121.coeffs[i] = reduce(BigNumberMultiplication(c121.coeffs[i], -R3))

		c122.coeffs[i+32] = reduce(-c122.coeffs[i])
		c122.coeffs[i] = reduce(-BigNumberMultiplication(c122.coeffs[i], R3))

		c211.coeffs[i+32] = c211.coeffs[i]
		c211.coeffs[i] = reduce(BigNumberMultiplication(c211.coeffs[i], -R5))

		c212.coeffs[i+32] = reduce(-c212.coeffs[i])
		c212.coeffs[i] = reduce(-BigNumberMultiplication(c212.coeffs[i], R5))

		c221.coeffs[i+32] = c221.coeffs[i]
		c221.coeffs[i] = reduce(BigNumberMultiplication(c221.coeffs[i], -R1))

		c222.coeffs[i+32] = reduce(-c222.coeffs[i])
		c222.coeffs[i] = reduce(-BigNumberMultiplication(c222.coeffs[i], R1))
	}
	c11 = polyAddition(c111, c112)
	c12 = polyAddition(c121, c122)
	c21 = polyAddition(c211, c212)
	c22 = polyAddition(c221, c222)

	for i = 0; i < 64; i++ {
		c11.coeffs[i] = reduce(BigNumberMultiplication(c11.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R1))))
		c12.coeffs[i] = reduce(BigNumberMultiplication(c12.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R5))))
		c21.coeffs[i] = reduce(BigNumberMultiplication(c21.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R3))))
		c22.coeffs[i] = reduce(BigNumberMultiplication(c22.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R7))))
	}

	for i = 0; i < 64; i++ {
		c11.coeffs[i+64] = c11.coeffs[i]
		c11.coeffs[i] = reduce(BigNumberMultiplication(c11.coeffs[i], -R6))
		c12.coeffs[i+64] = reduce(-c12.coeffs[i])
		c12.coeffs[i] = reduce(-BigNumberMultiplication(c12.coeffs[i], R6))
		c21.coeffs[i+64] = c21.coeffs[i]
		c21.coeffs[i] = reduce(BigNumberMultiplication(c21.coeffs[i], -R2))
		c22.coeffs[i+64] = reduce(-c22.coeffs[i])
		c22.coeffs[i] = reduce(-BigNumberMultiplication(c22.coeffs[i], R2))
	}
	c1 = polyAddition(c11, c12)
	c2 = polyAddition(c21, c22)
	for i = 0; i < 128; i++ {
		c1.coeffs[i] = reduce(BigNumberMultiplication(c1.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R2))))
		c2.coeffs[i] = reduce(BigNumberMultiplication(c2.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R6))))
	}

	for i = 0; i < 128; i++ {
		c1.coeffs[i+128] = c1.coeffs[i]
		c1.coeffs[i] = reduce(BigNumberMultiplication(c1.coeffs[i], -R4))
		c2.coeffs[i+128] = reduce(-c2.coeffs[i])
		c2.coeffs[i] = reduce(-BigNumberMultiplication(c2.coeffs[i], R4))
	}
	C = polyAddition(c1, c2)
	for i = 0; i < N; i++ {
		C.coeffs[i] = reduce(BigNumberMultiplication(C.coeffs[i], reduce(BigNumberMultiplication((Q+1)/2, R4))))
	}

	return C
}

func NewPoly() (res *poly) {
	res = new(poly)
	for i := 0; i < N; i++ {
		res.coeffs[i] = 0
	}
	return res
}


func (z *poly) Equal(a *poly) bool {
	for i := 0; i < N; i++ {
		if z.coeffs[i] != a.coeffs[i] {
			return false
		}
	}
	return true
}
// Check check whether z has 256 coefficients,
// where 60 of them are 1/-1 and the rest are 0.
func (z *poly) Check() (res bool) {
	count := 0
	for i := 0; i < N; i++ {
		if z.coeffs[i] == 1 || z.coeffs[i] == -1 {
			count++
		} else if z.coeffs[i] != 0 {
			return false
		}
	}
	if count == 60 {
		res = true
	} else {
		res = false
	}
	return
}
func (t *polyveck)Equal(p *polyveck) bool {
	for i:=0;i<K;i++{
		if !t.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}

func (v *polyvecl)Equal(p *polyvecl) bool {
	for i:=0;i<L;i++{
		if !v.vec[i].Equal(&p.vec[i]) {
			return false
		}
	}
	return true
}
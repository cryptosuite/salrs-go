package salrs

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
func bigNumberMultiplication(a int64, b int64) (ans int64) {
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
	return an
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
func polyNumMulPoly(a poly, b int64) (c poly) {
	var i int
	var C poly
	for i = 0; i < N; i++ {
		C.coeffs[i] = bigNumberMultiplication(a.coeffs[i], b)
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
func polyModOne(r0 int64, n int64, a poly) (b poly) {
	var i int
	var B poly
	if n == 32 {
		for i = 0; i < 32; i++ {
			B.coeffs[i] += bigNumberMultiplication(a.coeffs[i+32], r0)
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
func polyMulNormalSixteen(a poly, b poly) (c poly) {
	var m, i, j int
	var C poly
	for i = 0; i < N; i++ {
		C.coeffs[i] = 0
	}
	for i = 0; i < 16; i++ {
		for j = 0; j < 16; j++ {
			m = i + j
			C.coeffs[m] += bigNumberMultiplication(a.coeffs[i], b.coeffs[j])
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
	for i = 0; i < N/2; i++ {
		tmp = bigNumberMultiplication(a.coeffs[i+N/2], -R4)
		a1.coeffs[i] = a.coeffs[i] + tmp
		a1.coeffs[i] = reduce(a1.coeffs[i])
		a2.coeffs[i] = a.coeffs[i] - tmp
		a2.coeffs[i] = reduce(a2.coeffs[i])
	}
	for i = 0; i < N/4; i++ {
		tmp = bigNumberMultiplication(a1.coeffs[i+N/4], -R6)
		a11.coeffs[i] = a1.coeffs[i] + tmp
		a11.coeffs[i] = reduce(a11.coeffs[i])
		a12.coeffs[i] = a1.coeffs[i] - tmp
		a12.coeffs[i] = reduce(a12.coeffs[i])
	}
	for i = 0; i < N/4; i++ {
		tmp = bigNumberMultiplication(a2.coeffs[i+N/4], -R2)
		a21.coeffs[i] = a2.coeffs[i] + tmp
		a21.coeffs[i] = reduce(a21.coeffs[i])
		a22.coeffs[i] = a2.coeffs[i] - tmp
		a22.coeffs[i] = reduce(a22.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = bigNumberMultiplication(a11.coeffs[i+N/8], -R7)
		A111.coeffs[i] = a11.coeffs[i] + tmp
		A111.coeffs[i] = reduce(A111.coeffs[i])
		A112.coeffs[i] = a11.coeffs[i] - tmp
		A112.coeffs[i] = reduce(A112.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = bigNumberMultiplication(a12.coeffs[i+N/8], -R3)
		A121.coeffs[i] = a12.coeffs[i] + tmp
		A121.coeffs[i] = reduce(A121.coeffs[i])
		A122.coeffs[i] = a12.coeffs[i] - tmp
		A122.coeffs[i] = reduce(A122.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = bigNumberMultiplication(a21.coeffs[i+N/8], -R5)
		A211.coeffs[i] = a21.coeffs[i] + tmp
		A211.coeffs[i] = reduce(A211.coeffs[i])
		A212.coeffs[i] = a21.coeffs[i] - tmp
		A212.coeffs[i] = reduce(A212.coeffs[i])
	}
	for i = 0; i < N/8; i++ {
		tmp = bigNumberMultiplication(a22.coeffs[i+N/8], -R1)
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
		c111.coeffs[i] -= reduce(bigNumberMultiplication(c111.coeffs[i+32], R7))
		c111.coeffs[i] = reduce(c111.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c112.coeffs[i] += reduce(bigNumberMultiplication(c112.coeffs[i+32], R7))
		c112.coeffs[i] = reduce(c112.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c121.coeffs[i] -= reduce(bigNumberMultiplication(c121.coeffs[i+32], R3))
		c121.coeffs[i] = reduce(c121.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c122.coeffs[i] += reduce(bigNumberMultiplication(c122.coeffs[i+32], R3))
		c122.coeffs[i] = reduce(c122.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c211.coeffs[i] -= reduce(bigNumberMultiplication(c211.coeffs[i+32], R5))
		c211.coeffs[i] = reduce(c211.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c212.coeffs[i] += reduce(bigNumberMultiplication(c212.coeffs[i+32], R5))
		c212.coeffs[i] = reduce(c212.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c221.coeffs[i] -= reduce(bigNumberMultiplication(c221.coeffs[i+32], R1))
		c221.coeffs[i] = reduce(c221.coeffs[i])
	}
	for i = 0; i < 32; i++ {
		c222.coeffs[i] += reduce(bigNumberMultiplication(c222.coeffs[i+32], R1))
		c222.coeffs[i] = reduce(c222.coeffs[i])
	}

	for i = 0; i < 32; i++ {
		c111.coeffs[i+32] = c111.coeffs[i]
		c111.coeffs[i] = reduce(bigNumberMultiplication(c111.coeffs[i], -R7))
		c112.coeffs[i+32] = reduce(-c112.coeffs[i])
		c112.coeffs[i] = reduce(-bigNumberMultiplication(c112.coeffs[i], R7))
		c121.coeffs[i+32] = c121.coeffs[i]
		c121.coeffs[i] = reduce(bigNumberMultiplication(c121.coeffs[i], -R3))
		c122.coeffs[i+32] = reduce(-c122.coeffs[i])
		c122.coeffs[i] = reduce(-bigNumberMultiplication(c122.coeffs[i], R3))
		c211.coeffs[i+32] = c211.coeffs[i]
		c211.coeffs[i] = reduce(bigNumberMultiplication(c211.coeffs[i], -R5))
		c212.coeffs[i+32] = reduce(-c212.coeffs[i])
		c212.coeffs[i] = reduce(-bigNumberMultiplication(c212.coeffs[i], R5))
		c221.coeffs[i+32] = c221.coeffs[i]
		c221.coeffs[i] = reduce(bigNumberMultiplication(c221.coeffs[i], -R1))
		c222.coeffs[i+32] = reduce(-c222.coeffs[i])
		c222.coeffs[i] = reduce(-bigNumberMultiplication(c222.coeffs[i], R1))
	}
	c11 = polyAddition(c111, c112)
	c12 = polyAddition(c121, c122)
	c21 = polyAddition(c211, c212)
	c22 = polyAddition(c221, c222)

	for i = 0; i < 64; i++ {
		c11.coeffs[i] = reduce(bigNumberMultiplication(c11.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R1))))
		c12.coeffs[i] = reduce(bigNumberMultiplication(c12.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R5))))
		c21.coeffs[i] = reduce(bigNumberMultiplication(c21.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R3))))
		c22.coeffs[i] = reduce(bigNumberMultiplication(c22.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R7))))
	}

	for i = 0; i < 64; i++ {
		c11.coeffs[i+64] = c11.coeffs[i]
		c11.coeffs[i] = reduce(bigNumberMultiplication(c11.coeffs[i], -R6))
		c12.coeffs[i+64] = reduce(-c12.coeffs[i])
		c12.coeffs[i] = reduce(-bigNumberMultiplication(c12.coeffs[i], R6))
		c21.coeffs[i+64] = c21.coeffs[i]
		c21.coeffs[i] = reduce(bigNumberMultiplication(c21.coeffs[i], -R2))
		c22.coeffs[i+64] = reduce(-c22.coeffs[i])
		c22.coeffs[i] = reduce(-bigNumberMultiplication(c22.coeffs[i], R2))
	}
	c1 = polyAddition(c11, c12)
	c2 = polyAddition(c21, c22)
	for i = 0; i < 128; i++ {
		c1.coeffs[i] = reduce(bigNumberMultiplication(c1.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R2))))
		c2.coeffs[i] = reduce(bigNumberMultiplication(c2.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R6))))
	}

	for i = 0; i < 128; i++ {
		c1.coeffs[i+128] = c1.coeffs[i]
		c1.coeffs[i] = reduce(bigNumberMultiplication(c1.coeffs[i], -R4))
		c2.coeffs[i+128] = reduce(-c2.coeffs[i])
		c2.coeffs[i] = reduce(-bigNumberMultiplication(c2.coeffs[i], R4))
	}
	C = polyAddition(c1, c2)
	for i = 0; i < N; i++ {
		C.coeffs[i] = reduce(bigNumberMultiplication(C.coeffs[i], reduce(bigNumberMultiplication((Q+1)/2, R4))))
	}

	return C
}

/*
func Polymul(a poly, b poly) (c poly) {
	var i int
	for i = 0; i < N; i++ {
		a.coeffs[i] = 1
		b.coeffs[i] = 1
	}
	a.coeffs[0] = 1
	b.coeffs[0] = 1
	return polyMultiplication(a, b)
}

func Test() {
	var a, b, c poly
	c = Polymul(a, b)
	fmt.Println(c)
}
*/

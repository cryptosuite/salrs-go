package salrs

import (
	"golang.org/x/crypto/sha3"
)

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [-(Q-1)/2,(Q-1)/2] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - long long *a: pointer to output array (allocated)
*              - unsigned int len: number of coefficients to be sampled
*              - const unsigned char *buf: array of random bytes
*              - unsigned int buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
func rejUniform(a [N]int64, len int, buf []byte, buflen int) (aa [N]int64, ctr int) {
	var pos = 0
	var t int64
	//ctr = 0
	//while (ctr < len && pos + 5 <= buflen)
	for {
		if len >= N || pos+5 > buflen {
			break
		}
		t = int64(buf[pos])
		pos++
		t |= int64(buf[pos]) << 8
		pos++
		t |= int64(buf[pos]) << 16
		pos++
		t |= int64(buf[pos]) << 24
		pos++
		t |= (int64(buf[pos]) >> 4) << 32
		pos++
		t &= 0xFFFFFFFFF
		if t < Q {
			a[len] = t - (Q-1)/2
			len++
		}
	}
	return a, len
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-ETA, ETA] by
 *              performing rejection sampling using array of random bytes.
 *
 * Arguments:   - long long *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const unsigned char *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
func rejEta(a [N]int64, len int, buf []byte, buflen int) (aa [N]int64, ctr int) {
	var pos = 0
	var t0, t1 int64
	//ctr = 0

	//while (ctr < len && pos < buflen)
	for {
		if len >= N || pos >= buflen {
			break
		}
		t0 = int64(buf[pos] & 0x07)
		t1 = int64(buf[pos] >> 5)
		pos++
		if t0 <= 2*Eta {
			a[len] = Eta - t0
			len++
		}
		if t1 <= 2*Eta && len < N {
			a[len] = Eta - t1
			len++
		}
	}
	return a, len
}

/*************************************************
 * Name:        rej_gamma
 *
 * Description: Sample uniformly random coefficients
 *              in [-GAMMA, GAMMA] by performing rejection sampling
 *              using array of random bytes.
 *
 * Arguments:   - long long *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const unsigned char *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
func rejGamma(a [N]int64, len int, buf []byte, buflen int) (aa [N]int64, ctr int) {
	var pos = 0
	var t int64
	//ctr = 0
	//while (ctr < len && pos + 3 <= buflen)
	for {
		if len >= N || pos+3 > buflen {
			break
		}
		t = int64(buf[pos])
		pos++
		t |= int64(buf[pos]) << 8
		pos++
		t |= int64(buf[pos]>>3) << 16
		pos++
		t &= 0x1FFFFF

		if t <= 2*Gamma {
			a[len] = Gamma - t
			len++
		}
	}
	return a, len
}

/*************************************************
 * Name:        rej_gmte
 *
 * Description: Sample uniformly random coefficients
 *              in [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA] by performing rejection sampling
 *              using array of random bytes.
 *
 * Arguments:   - long long *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const unsigned char *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
func rejGmte(a [N]int64, len int, buf []byte, buflen int) (aa [N]int64, ctr int) {
	var pos = 0
	var t int64
	//ctr = 0

	//while (ctr < len && pos + 3 <= buflen)
	for {
		if len >= N || pos+3 > buflen {
			break
		}
		t = int64(buf[pos])
		pos++
		t |= int64(buf[pos]) << 8
		pos++
		t |= int64(buf[pos]>>3) << 16
		pos++
		t &= 0x1FFFFF

		if t <= Gamma-2*Theta*Eta {
			a[len] = Gamma - 2*Theta*Eta - t
			len++
		}
	}
	return a, len
}

/*************************************************
* Name:        poly_uniform
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-(Q-1)/2,(Q-1)/2] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char cstr[]: byte array with seed of length
*                                            CSTRSIZE
*              - uint16_t nonce: 2-byte nonce
**************************************************/
func polyUniform(seed []byte) (a poly) {
	var ctr = 0
	var buflen = 5*N + 20
	var buf = make([]byte, buflen)

	c := sha3.NewShake256()
	c.Write(seed)
	c.Read(buf)

	a.coeffs, ctr = rejUniform(a.coeffs, ctr, buf, buflen)

	for {
		if ctr >= N {
			break
		}
		//c.Write(buf)
		c.Read(buf)
		a.coeffs, ctr = rejUniform(a.coeffs, ctr, buf, buflen)
	}
	return a
}

/*************************************************
* Name:        poly_uniform_eta
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-ETA,ETA] by performing rejection sampling using the
*              output stream from SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            ETASEEDBYTES
*              - uint16_t nonce: 2-byte nonce
**************************************************/
func polyUniformEta(seed []byte) (a poly) {
	var ctr = 0
	var buflen = N + 20
	var buf = make([]byte, buflen)

	c := sha3.NewShake256()
	c.Write(seed)
	c.Read(buf)

	a.coeffs, ctr = rejEta(a.coeffs, ctr, buf, buflen)
	//while (ctr < N)
	for {
		if ctr >= N {
			break
		}
		//c.Write(buf)
		c.Read(buf)
		a.coeffs, ctr = rejEta(a.coeffs, ctr, buf, buflen)
	}
	return a
}

/*************************************************
* Name:        poly_uniform_gamma
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-GAMMA, GAMMA] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            GAMMASEEDBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
func polyUniformGamma(seed []byte) (a poly) {
	var ctr = 0
	var buflen = N*3 + 20
	var buf = make([]byte, buflen)

	c := sha3.NewShake256()
	c.Write(seed)
	c.Read(buf)

	a.coeffs, ctr = rejGamma(a.coeffs, ctr, buf, buflen)

	//while (ctr < N)
	for {
		if ctr >= N {
			break
		}
		//c.Write(buf)
		c.Read(buf)
		a.coeffs, ctr = rejGamma(a.coeffs, ctr, buf, buflen)
	}
	return a
}

/*************************************************
* Name:        poly_uniform_gmte
*
* Description: Sample polynomial with uniformly random coefficients
*              in [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA] by performing rejection
*              sampling on output stream of SHAKE256(seed|nonce).
*
* Arguments:   - poly *a: pointer to output polynomial
*              - const unsigned char seed[]: byte array with seed of length
*                                            GMTESEEDBYTES
*              - uint16_t nonce: 16-bit nonce
**************************************************/
func polyUniformGmte(seed []byte) (a poly) {
	var ctr int
	var buflen = 3*N + 20
	var buf = make([]byte, buflen)

	c := sha3.NewShake256()
	c.Write(seed)
	c.Read(buf)

	a.coeffs, ctr = rejGmte(a.coeffs, ctr, buf, buflen)

	//while (ctr < N)
	for {
		if ctr >= N {
			break
		}
		//c.Write(buf)
		c.Read(buf)
		a.coeffs, ctr = rejGmte(a.coeffs, ctr, buf, buflen)
	}
	return a
}

/*************************************************
 * Name:        expand_matA
 *
 * Description: Implementation of expandA.
 *             generate a k * l matrix with polynomial elements
 *             with coefficients belonging to [-(Q-1)/2,(Q-1)/2] using cstr
 * Arguments:    - polyvecl mat[K]: output k*l matrix A
 *               - const unsigned char cstr[]: byte array with seed of length
 *                                            CSTRSIZE
 **************************************************/
func expandMatA() (matA [K]polyvecl) {
	var i, j int
	var mat [K]polyvecl
	var seedbuf = make([]byte, CSTRSIZE)
	for i = 0; i < CSTRSIZE; i++ {
		seedbuf[i] = cstr[i]
	}
	c := sha3.NewShake256()
	c.Write(seedbuf)
	c.Read(seedbuf)
	for i = 0; i < K; i++ {
		for j = 0; j < L; j++ {
			mat[i].vec[j] = polyUniform(seedbuf)
			c.Read(seedbuf)
		}
	}
	return mat
}

/*************************************************
 * Name:        expand_V
 *
 * Description: Implementation of expandV.
 *             generate a vector of length l with polynomial elements
 *             with coefficients belonging to[-ETA,ETA] using stream of random bytes
 * Arguments:   - unsigned char Kyber_k[KYBER_SYMBYTES]: byte array containing seed k in
 *                                                KYBER where KYBER_SYMBYTES = 32
 *                                                is the length of k in KYBER
 *             - polyvecl *V: pointer to output vector V
 **************************************************/
func expandV(KK []byte) (V polyvecl) {
	var i int
	v := polyvecl{}
	c := sha3.NewShake256()
	c.Write(KK)
	c.Read(KK)
	for i = 0; i < L; i++ {
		v.vec[i] = polyUniformEta(KK)
		c.Read(KK)
	}
	return v
}

/*************************************************
 * Name:        generate_L_eta
 *
 * Description: generate a vector of length l with polynomial elements
 *             with coefficients belonging to [-ETA,ETA]
 * Arguments:   - polyvecl *s: pointer to output polynomial
 **************************************************/
func generateLEtaforPassPhase(buf []byte) (s polyvecl) {
	var i int
	var buflen = N + 20
	var S polyvecl
	var seedbuf = make([]byte, buflen)
	c := sha3.NewShake256()
	c.Write(buf)
	c.Read(seedbuf)
	for i = 0; i < L; i++ {
		S.vec[i] = polyUniformEta(seedbuf)
		c.Read(seedbuf)
	}
	return S
}

/*************************************************
 * Name:        generate_L_eta
 *
 * Description: generate a vector of length l with polynomial elements
 *             with coefficients belonging to [-ETA,ETA]
 * Arguments:   - polyvecl *s: pointer to output polynomial
 **************************************************/
func generateLEta() (s polyvecl) {
	var i int
	var S polyvecl
	var buflen = N + 20
	var seedbuf = make([]byte, buflen)
	seedbuf = randombytes(buflen)
	c := sha3.NewShake256()
	c.Write(seedbuf)
	c.Read(seedbuf)
	for i = 0; i < L; i++ {
		S.vec[i] = polyUniformEta(seedbuf)
		c.Read(seedbuf)
	}
	return S
}

/*************************************************
 * Name:        generate_gamma
 *
 * Description: generate a vector of length l with polynomial elements
 *             with coefficients belonging to[-GAMMA, GAMMA]
 * Arguments:   - polyvecl *s: pointer to output polynomial
 **************************************************/
func generateLGamma() (s polyvecl) {
	var i int
	var S polyvecl
	var buflen = 3*N + 20
	var seedbuf = make([]byte, buflen)
	seedbuf = randombytes(buflen)
	c := sha3.NewShake256()
	c.Write(seedbuf)
	c.Read(seedbuf)
	for i = 0; i < L; i++ {
		S.vec[i] = polyUniformGamma(seedbuf)
		c.Read(seedbuf)
	}
	return S
}

/*************************************************
 * Name:        generate_gamma_sub_to_theta_eta
 *
 * Description: generate a vector of length l with polynomial elements
 *             with coefficients belonging to [-GAMMA+2*THETA*ETA, GAMMA-2*THETA*ETA]
 * Arguments:   - polyvecl *s: pointer to output polynomial
 **************************************************/
func generateLGammaSubToThetaEta() (s polyvecl) {
	var i int
	var S polyvecl
	var buflen int = 3*N + 20
	var seedbuf []byte = make([]byte, buflen)
	seedbuf = randombytes(buflen)
	c := sha3.NewShake256()
	c.Write(seedbuf)
	c.Read(seedbuf)
	for i = 0; i < L; i++ {
		S.vec[i] = polyUniformGmte(seedbuf)
		c.Read(seedbuf)
	}
	return S
}

/*************************************************
 * Name:        Hm
 *
 * Description:   Implementation of Hm.
 *             generate a m * l matrix with polynomial elements
 *             with coefficients belonging to [-(Q-1)/2,(Q-1)/2] using t as the seed
 * Arguments:   - polyveck * t: pointer to input vector t
 *             - polyvecl H[m]: output matrix H
 **************************************************/
func hm(t polyveck) (H [M]polyvecl) {
	var i, j uint32
	var h [M]polyvecl
	var seedpack [PackTByteLen]byte
	seedpack = packPolyveckQ(t)
	seedbuf := seedpack[0:len(seedpack)]
	c := sha3.NewShake256()
	c.Write(seedbuf)
	c.Read(seedbuf)
	for i = 0; i < M; i++ {
		for j = 0; j < L; j++ {
			h[i].vec[j] = polyUniform(seedbuf)
			c.Read(seedbuf)
		}
	}
	return h
}

/*************************************************
 * Name:        H_theta
 *
 * Description:   Implementation of H_theta,which is inside-out shuffle algorithm
 *             a function to generate c which has 256 coefficients
 *              , where 60 of them are 1/-1 and the rest are 0.
 * Arguments:   - unsigned char * m: point to input message
 *             - unsigned int mlen: the length of message
 *             - unsigned char **Ring: point to Ring = (dpk1, dpk2.....dpkr)
 *             - unsigned int r:r in Ring = (dpk1, dpk2.....dpkr)
 *             - polyveck *w:point to input vector w
 *             - polyvecm *v:point to input vector v
 *             - polyvecm *I:point to input vector I
 *             - poly* c: pointer to output c
 **************************************************/
func hTheta(m []byte, mlen int, dpkring *DpkRing, w polyveck, v polyvecm, I polyvecm) (c poly) {
	var (
		i, j, pos       int
		r               = dpkring.R
		k, signs, b, i2 uint64
		inbufLen        = N + r*DpkByteLen + PackTByteLen + 2*PackIByteLen
		inbuf           = make([]byte, inbufLen)
		outbuf          = make([]byte, N)
		tmpbuf1         = make([]byte, mlen)
		tmpbuf2         = make([]byte, N)
		tmpbuf3         [PackTByteLen]byte
		tmpbuf4         [PackIByteLen]byte
		dpkbyte         [DpkByteLen]byte
		count           = 0
		C               poly
	)
	for i = 0; i < mlen; i++ {
		tmpbuf1[i] = m[i]
	}
	sha := sha3.NewShake256()
	sha.Write(tmpbuf1)
	sha.Read(tmpbuf2)
	for i = 0; i < N; i++ {
		inbuf[i] = tmpbuf2[i]
	}
	count = N
	for i = 0; i < r; i++ {
		dpkbyte = packDpk(dpkring.Dpk[i])
		for j = 0; j < DpkByteLen; j++ {
			inbuf[count] = dpkbyte[j]
			count++
		}
	}

	tmpbuf3 = packPolyveckQ(w)
	for i = 0; i < PackTByteLen; i++ {
		inbuf[count+i] = tmpbuf3[i]
	}
	count += PackTByteLen
	tmpbuf4 = packPolyvecmQ(v)
	for i = 0; i < PackIByteLen; i++ {
		inbuf[count+i] = tmpbuf4[i]
	}
	count += PackIByteLen
	tmpbuf4 = packPolyvecmQ(I)
	for i = 0; i < PackIByteLen; i++ {
		inbuf[count+i] = tmpbuf4[i]
	}
	count += PackIByteLen

	sha2 := sha3.NewShake256()
	sha2.Write(inbuf)
	sha2.Read(outbuf)

	signs = 0
	for k = 0; k < 8; k++ {
		signs |= uint64(outbuf[k]) << 8 * k
	}
	pos = 8

	for i = 0; i < N; i++ {
		C.coeffs[i] = 0
	}

	b = uint64(outbuf[pos])
	pos++
	for i2 = 196; i2 < 256; i2++ {
		for i = 0; i < 10; i-- {
			b = uint64(outbuf[pos])
			pos++
			if pos >= N {
				//sha.Write(outbuf)
				sha.Read(outbuf)
				pos = 0
			}
			if b < i2 {
				break
			}
		}

		C.coeffs[i2] = C.coeffs[b]
		C.coeffs[b] = 1
		if signs&1 == 1 {
			C.coeffs[b] = 1
		} else {
			C.coeffs[b] = -1
		}
		//c.coeffs[b] ^= -(signs & 1) & (1 ^ (Q - 1))
		signs >>= 1
	}
	return C
}

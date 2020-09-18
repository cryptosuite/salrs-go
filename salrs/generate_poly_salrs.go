package salrs

import (
	"fmt"
	"golang.org/x/crypto/sha3"
)

// TODO:lack of handling error
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
func generateMatrixAFromCRS() (*[K]polyvecl, error) {
	res := new([K]polyvecl)
	var seed []byte
	var err error
	cstrBytes := []byte(cstr) // TODO:this transfer process should be encode/decode with hex.EncodeToString and hex.DecodeString
	for i := 0; i < len(cstrBytes); i++ {
		seed = append(seed, cstrBytes[i])
	}
	pos := 0
	for i := 0; i < K; i++ {
		seed, pos, err = generatePolyVecLFromSeed(seed, pos, generatePolyQFromSeed, &res[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
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
func expandV1(kk []byte) (*polyvecl, error) {
	temp := sha3.Sum256(kk)
	seed := make([]byte, len(temp))
	copy(seed, temp[:])
	res := new(polyvecl)
	_, _, err := generatePolyVecLFromSeed(seed, 0, generatePolyEtaFromSeed, res)
	if err != nil {
		return nil, err
	}
	return res, nil
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

// generatePolyVecLFromSeed requires that the seed is not nil and the length of given seed meets the length demand
//  if the polyvecl is nil, this function will apply for a new one.
func generatePolyVecLFromSeed(seed []byte, pos int, fn generatePoly, res *polyvecl) ([]byte, int, error) {
	if seed == nil || len(seed) < 32 {
		return nil, -1, fmt.Errorf("the length of seed is %v, but expected %v.", len(seed), 32)
	}
	var err error
	temp := make([]byte, len(seed))
	copy(temp, seed)
	if res == nil {
		res = new(polyvecl)
	}
	for i := 0; i < L; i++ {
		temp, pos, err = fn(temp, pos, &res.vec[i]) //update seed and current position
		if err != nil {
			return seed, 0, err
		}
	}
	return temp, pos, nil
}

type generatePoly func([]byte, int, *poly) ([]byte, int, error)

// the seed will be extended if the pos more than the length of sedd
func generatePolyEtaFromSeed(seed []byte, pos int, p *poly) ([]byte, int, error) {
	if seed == nil || len(seed) < 32 {
		return nil, -1, fmt.Errorf("the length of seed is %v, but expected %v.", len(seed), 32)
	}
	if p == nil {
		p = NewPoly()
	}
	index := 0
	//reject sample
	for {
		if index >= N {
			break
		}
		if pos >= len(seed) { //extend the seed if not enough
			extend := sha3.Sum256(seed[len(seed)-32:])
			seed = append(seed, extend[:]...)
		}

		temp0 := int64(seed[pos] & 0x07) // lowest three bits
		temp1 := int64(seed[pos] >> 5)   // highest three bits
		pos++
		if temp0 <= 2*Eta {
			p.coeffs[index] = Eta - temp0
			index++
		}
		if temp1 <= 2*Eta && index < N {
			p.coeffs[index] = Eta - temp1
			index++
		}

	}
	return seed, pos, nil
}
func generatePolyQFromSeed(seed []byte, pos int, p *poly) ([]byte, int, error) {
	if p == nil {
		p = NewPoly()
	}
	index := 0
	//reject sample
	for {
		if index >= N {
			break
		}
		if pos+4 >= len(seed) { //extend the seed if not enough
			extend := sha3.Sum256(seed[len(seed)-32:])
			seed = append(seed, extend[:]...)
		}

		temp := int64(0)
		for i := 0; i < 4; i++ {
			temp |= int64(seed[pos]) << (i * 8)
			pos++
		}
		temp |= int64(seed[pos]>>4) << 32 // highest 4 bits
		pos++

		if temp <= Q { //TODO:it can equal to Q?
			p.coeffs[index] = (Q-1)/2 - temp
			index++
		}
	}
	return seed, pos, nil
}
func generatePolyGammmaFromSeed(seed []byte, pos int, p *poly) ([]byte, int, error) {
	if p == nil {
		p = NewPoly()
	}
	index := 0
	//reject sample
	for {
		if index >= N {
			break
		}
		if pos+2 >= len(seed) { //extend the seed if not enough
			extend := sha3.Sum256(seed[len(seed)-32:])
			seed = append(seed, extend[:]...)
		}

		temp := int64(seed[pos]) //0-7
		pos++
		temp |= int64(seed[pos]) << 8 //8-15
		pos++
		temp |= int64(seed[pos]>>3) << 16 // highest 5 bits,16-20
		pos++

		if temp <= 2*Gamma {
			p.coeffs[index] = Gamma - temp
			index++
		}
	}
	return seed, pos, nil
}
func generatePolyGmteFromSeed(seed []byte, pos int, p *poly) ([]byte, int, error) {
	if p == nil {
		p = NewPoly()
	}
	index := 0
	//reject sample
	for {
		if index >= N {
			break
		}
		if pos+2 >= len(seed) { //extend the seed if not enough
			extend := sha3.Sum256(seed[len(seed)-32:])
			seed = append(seed, extend[:]...)
		}

		temp := int64(seed[pos]) //0-7
		pos++
		temp |= int64(seed[pos]) << 8 //8-15
		pos++
		temp |= int64(seed[pos]>>3) << 16 // highest 5 bits,16-20
		pos++

		if temp <= 2*Gamma-4*Theta*Eta { //TODO:这个判断可能有点问题，先改过来了
			p.coeffs[index] = Gamma - 2*Theta*Eta - temp
			index++
		}
	}
	return seed, pos, nil
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
	seedpack := make([]byte, PackTByteLen)
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
func hm1(t *polyveck) (*[M]polyvecl, error) {
	var err error
	res := &[M]polyvecl{}
	seedpack := t.packQ()
	seedbuf := sha3.Sum256(seedpack)
	seed := []byte(cstr) // TODO:this transfer process should be encode/decode with hex.EncodeToString and hex.DecodeString
	for i := 0; i < len(seedbuf); i++ {
		seed = append(seed, seedbuf[i])
	}
	pos := 0
	for i := 0; i < M; i++ {
		seed, pos, err = generatePolyVecLFromSeed(seed, pos, generatePolyQFromSeed, &res[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
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
		tmpbuf3         = make([]byte, PackTByteLen)
		tmpbuf4         = make([]byte, PackIByteLen)
		dpkbyte         = make([]byte, DpkByteLen)
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

func hTheta1(m []byte, mlen int, dpkring *DpkRing, w *polyveck, v *polyvecm, I *polyvecm) (*poly, error) {
	var inbuf []byte
	// h(m)
	tmpbuf := sha3.Sum256(m[:mlen])
	for i := 0; i < len(tmpbuf); i++ {
		inbuf = append(inbuf, tmpbuf[i])
	}
	//dpk
	for i := 0; i < dpkring.R; i++ {
		inbuf = append(inbuf, dpkring.Dpk[i].Serialize()...)
	}
	//w
	inbuf = append(inbuf, w.packQ()...)
	//v
	inbuf = append(inbuf, v.packQ()...)
	//I
	inbuf = append(inbuf, I.packQ()...)

	outbuf := sha3.Sum256(inbuf)

	res := NewPoly()
	// inside-out
	sign := int64(0)
	sign |= int64(outbuf[23] >> 4) // highest 4 bits
	for i := 0; i < 7; i++ {
		sign |= int64(outbuf[24+i] << (4 + 8*i))
	}
	// use the outbuf as seed
	seed:=make([]byte,32)
	copy(seed,outbuf[:])
	var err error
	pos:=0
	for i := 196; i < 256; i++ {
		index:=-1
		index, seed, pos, err = randomIntFromSeed(seed, pos, i+1)
		if err!=nil{
			return nil,err
		}
		if sign&0x01 == 0 {
			res.coeffs[i] = -1
		} else {
			res.coeffs[i] = 1
		}
		sign >>= 1
		res.coeffs[index], res.coeffs[i] = res.coeffs[i], res.coeffs[index]
	}
	if !res.CheckInOne(){
		return nil,fmt.Errorf("the h theta has logic error")
	}

	return res,nil
}

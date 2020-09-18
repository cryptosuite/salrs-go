package salrs

import (
	"fmt"
	"github.com/cryptosuite/kyber-go/kyber"
)

/*
This file contains all the public constant, type, and functions that are available to oue of the package.
*/

//	public const def	begin
const PassPhaseByteLen = 32

// TODO: This value should be a const value?
var pkem = kyber.Kyber768

const (
	N                     = 256
	L                     = 5
	K                     = 3
	M                     = 1
	Theta                 = 60          //0x3C,6bit
	Eta                   = 3           //0x3,2bit ->3bit
	Gamma                 = 699453      //0xAAC3D,20bit ->21bit
	GammaMinusTwoEtaTheta = 699093      //0xAAAD5,20bit ->21bit
	Q                     = 34360786961 //0x800100011,36bit
	Q2                    = 17180393480 //(Q - 1)/2,0x400080008,35bit
	R1                    = -16915236577
	R2                    = -8376412603
	R3                    = -3354919284
	R4                    = 11667088462
	R5                    = -12474372669
	R6                    = -3077095668
	R7                    = 14301820476

	PackTByteLen = 3456                                                          //
	PackSByteLen = 480                                                           //
	PackZByteLen = 3520                                                          //
	PackIByteLen = 1152                                                          //
	cstr         = "today_is_a_good_day_today_is_a_good_day_today_is_a_good_day" //TODO:this const string should be random?
	CSTRSIZE     = len(cstr)
)

var (
	PKKEMByteLen  = pkem.CryptoPublicKeyBytes()
	SKKEMByteLen  = pkem.CryptoSecretKeyBytes()
	CTKEMByteLen  = pkem.CryptoCiphertextBytes()
	MpkByteLen    = PKKEMByteLen + PackTByteLen
	MskByteLen    = MsvkByteLen + MsskByteLen
	MsvkByteLen   = SKKEMByteLen
	MsskByteLen   = PackSByteLen
	DpkByteLen    = CTKEMByteLen + PackTByteLen
	CipherByteLen = CTKEMByteLen
)

//	public const def	end=1000

//	public type def		begin
type MasterPubKey struct {
	t     polyveck
	pkkem *kyber.PublicKey
}

type MasterSecretViewKey struct {
	skkem *kyber.SecretKey
	//skkem [kyber.CryptoSecretkeybytes]byte
}

type MasterSecretSignKey struct {
	S polyvecl
}

type DerivedPubKey struct {
	c []byte
	t polyveck
}

type DpkRing struct {
	Dpk []DerivedPubKey
	R   int //环的尺寸应当可以不明确设定
}

type Signature struct {
	z []polyvecl
	r int //个数，应当是可以省略的
	c poly
	I polyvecm //这个I应当已经被移动到KeyImage中了
}

type KeyImage struct {
	I polyvecm
}

//	public type def		end

//	public fun	begin

//	to do: how to define or store PP
//  if the contents for PP are two large, use a separate param.go to store them, otherwise, also in this file
//	note that the sizes depend on the PP, we may need to put these constants together with PP.
// TODO: What does do this function?
func Setup() {
	pkem = kyber.Kyber768
}

//func GenerateMasterKey(masterSeed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, mseed []byte, err error) {
//	if len(masterSeed) == 0 {
//		md := make([]byte, 32)
//		md = randombytes(32)
//		masterSeed = md
//	}
//	masterPubKey := &MasterPubKey{}
//	masterSecretViewKey := &MasterSecretViewKey{}
//	masterSecretSignKey := &MasterSecretSignKey{}
//
//	var (
//		i, j int
//		A    [K]polyvecl
//		t    polyveck
//		s    polyvecl
//		tmp  poly
//		//stmp = make([]byte, PackSByteLen)
//	)
//
//	masterPubKey.pkkem, masterSecretViewKey.skkem, err = pkem.CryptoKemKeyPair(masterSeed)
//	if err != nil {
//		fmt.Println(err)
//	}
//
//	s = generateLEta()
//
//	A = expandMatA()
//	for i = 0; i < K; i++ {
//		t.vec[i] = polyMultiplication(A[i].vec[0], s.vec[0])
//		for j = 1; j < L; j++ {
//			tmp = polyMultiplication(A[i].vec[j], s.vec[j])
//			t.vec[i] = polyAddition(t.vec[i], tmp)
//		}
//	}
//	masterPubKey.t = t
//	masterSecretSignKey.S = s
//
//	return masterPubKey, masterSecretViewKey, masterSecretSignKey, masterSeed, nil
//}
func GenerateMasterKey(seed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, mseed []byte, err error) {
	return GenerateMasterKey1(seed)
}

func GenerateMasterKey1(seed []byte) (*MasterPubKey, *MasterSecretViewKey, *MasterSecretSignKey, []byte, error) {
	var err error
	if seed == nil {
		seed, err = randomBytesFromCRand(32)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	mpk := new(MasterPubKey)
	msvk := new(MasterSecretViewKey)
	mssk := new(MasterSecretSignKey)
	mpk.pkkem, msvk.skkem, err = pkem.CryptoKemKeyPair(seed)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	s := new(polyvecl)
	_, _, err = generatePolyVecLFromSeed(seed, 0, generatePolyEtaFromSeed, s)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	A, err := generateMatrixAFromCRS() //TODO:this variable should be a global parameter
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// compute t= As
	t := new(polyveck)
	for i := 0; i < K; i++ {
		t.vec[i] = *NewPoly().Mul(&A[i].vec[0], &s.vec[0])
		for j := 1; j < L; j++ {
			tmp := NewPoly().Mul(&A[i].vec[j], &s.vec[j])
			t.vec[i] = *NewPoly().Add(&t.vec[i], tmp)
		}
	}
	mpk.t = *t
	mssk.S = *s
	return mpk, msvk, mssk, seed, nil
}

//func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
//	if mpk == nil {
//		return nil, errors.New("mpk is nil")
//	}
//	derivedPubKey := &DerivedPubKey{}
//
//	var (
//		i, j       int
//		t, t2, tUp polyveck
//		A          [K]polyvecl
//		s2         polyvecl
//		tmp        poly
//		erro       error
//	)
//
//	ss := make([]byte, pkem.CryptoSharedSecretBytes())
//	ct := make([]byte, pkem.CryptoCiphertextBytes())
//	ct, ss, err = mpk.pkkem.CryptoKemEnc()
//	if erro != nil {
//		fmt.Println(err)
//	}
//
//	t = mpk.t
//	s2 = expandV(ss)
//	A = expandMatA()
//
//	for i = 0; i < K; i++ {
//		t2.vec[i] = polyMultiplication(A[i].vec[0], s2.vec[0])
//		for j = 1; j < L; j++ {
//			tmp = polyMultiplication(A[i].vec[j], s2.vec[j])
//			t2.vec[i] = polyAddition(t2.vec[i], tmp)
//		}
//	}
//	for i = 0; i < K; i++ {
//		tUp.vec[i] = polyAddition(t.vec[i], t2.vec[i])
//	}
//	derivedPubKey.c = ct
//	derivedPubKey.t = tUp
//
//	return derivedPubKey, nil
//}
func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	return GenerateDerivedPubKey1(mpk)
}
func GenerateDerivedPubKey1(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, fmt.Errorf("the master public key is empty")
	}
	dpk = &DerivedPubKey{}

	var (
		t2, tUp polyveck
		tmp     poly
	)
	//
	//ss := make([]byte, pkem.CryptoSharedSecretBytes())
	//ct := make([]byte, pkem.CryptoCiphertextBytes())
	ct, ss, err := mpk.pkkem.CryptoKemEnc() // contain randomness
	if err != nil {
		return nil, err
	}

	t := mpk.t.Copy()
	s2, err := expandV1(ss)
	if err != nil {
		return nil, err
	}
	A, err := generateMatrixAFromCRS() //TODO:this matrix should be a global variable for system
	if err != nil {
		return nil, err
	}

	for i := 0; i < K; i++ {
		t2.vec[i] = *NewPoly().Mul(&A[i].vec[0], &s2.vec[0])
		for j := 1; j < L; j++ {
			tmp = *NewPoly().Mul(&A[i].vec[j], &s2.vec[j])
			t2.vec[i] = *NewPoly().Add(&t2.vec[i], &tmp)
		}
	}
	for i := 0; i < K; i++ {
		tUp.vec[i] = *NewPoly().Add(&t.vec[i], &t2.vec[i])
	}
	dpk.c = ct
	dpk.t = tUp

	return dpk, nil
}

//func CheckDerivedPubKeyOwner(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) bool {
//	var (
//		i, j       int
//		tUp, t, t2 polyveck
//		s2         polyvecl
//		A          [K]polyvecl
//		tmp        poly
//	)
//	ct := make([]byte, pkem.CryptoCiphertextBytes())
//	ss := make([]byte, pkem.CryptoSharedSecretBytes())
//
//	ct = dpk.c
//	tUp = dpk.t
//	t = mpk.t
//
//	for i = 0; i < K; i++ {
//		for j = 0; j < N; j++ {
//			if tUp.vec[i].coeffs[j] > Q2 || tUp.vec[i].coeffs[j] < -Q2 {
//				return false
//			}
//		}
//	}
//	//fmt.Println("passed 1")
//
//	ss = msvk.skkem.CryptoKemDec(ct)
//	s2 = expandV(ss)
//	A = expandMatA()
//	for i = 0; i < N; i++ {
//		tmp.coeffs[i] = 0
//		t2.vec[0].coeffs[i] = 0
//	}
//	for i = 0; i < K; i++ {
//		t2.vec[i] = polyMultiplication(A[i].vec[0], s2.vec[0])
//		for j = 1; j < L; j++ {
//			tmp = polyMultiplication(A[i].vec[j], s2.vec[j])
//			t2.vec[i] = polyAddition(t2.vec[i], tmp)
//		}
//	}
//
//	for i = 0; i < K; i++ {
//		for j = 0; j < N; j++ {
//			if tUp.vec[i].coeffs[j] != reduce(t.vec[i].coeffs[j]+t2.vec[i].coeffs[j]) {
//				return false
//			}
//		}
//	}
//
//	return true
//}
func CheckDerivedPubKeyOwner(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) (bool, error) {
	return CheckDerivedPubKeyOwner1(dpk, mpk, msvk)
}
func CheckDerivedPubKeyOwner1(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) (bool, error) {
	//check the coeffs of derived public key
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if dpk.t.vec[i].coeffs[j] > Q2 || dpk.t.vec[i].coeffs[j] < -Q2 {
				return false, nil
			}
		}
	}

	ct := make([]byte, pkem.CryptoCiphertextBytes())
	copy(ct, dpk.c)
	ss := msvk.skkem.CryptoKemDec(ct)

	s2, err := expandV1(ss)
	if err != nil {
		return false, err
	}
	A, err := generateMatrixAFromCRS()
	if err != nil {
		return false, err
	}

	// tt = A * s
	tt := new(polyveck)
	var tmp *poly
	for i := 0; i < K; i++ {
		tt.vec[i] = *NewPoly().Mul(&A[i].vec[0], &s2.vec[0])
		for j := 1; j < L; j++ {
			tmp = NewPoly().Mul(&A[i].vec[j], &s2.vec[j])
			tt.vec[i] = *NewPoly().Add(&tt.vec[i], tmp)
		}
	}

	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if dpk.t.vec[i].coeffs[j] != reduce(mpk.t.vec[i].coeffs[j]+tt.vec[i].coeffs[j]) {
				return false, nil
			}
		}
	}

	return true, nil
}

// note the message type
//func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
//	sigma := &Signature{}
//	var (
//		i, iMain, j, rejection, r, i2 int
//		A                             [K]polyvecl
//		H                             [M]polyvecl
//		s, si, sUp, z, y, cs          polyvecl
//		c, c1, tmp, tmp2              poly
//		tUp, w, as, az, cti           polyveck
//		I, v, hz, cI                  polyvecm
//		flag2, flagDpk, ii            = -1, 0, 0
//		tmpDpk                        DerivedPubKey
//		bl                            = true
//		erro                          error
//	)
//
//	ss := make([]byte, pkem.CryptoSharedSecretBytes())
//	ct := make([]byte, pkem.CryptoCiphertextBytes())
//
//	r = dpkRing.R
//	zz := make([]polyvecl, r)
//	tmpDpk = dpkRing.Dpk[0]
//	for i = 1; i < dpkRing.R; i++ {
//		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
//			flagDpk = 1
//			break
//		}
//	}
//	if flagDpk == 1 {
//		return nil, errors.New("ring check failed")
//	}
//
//	for i = 0; i < dpkRing.R; i++ {
//		if Equaldpk(*dpk, dpkRing.Dpk[i]) {
//			ii = i
//			flag2 = 0
//			ct = dpk.c
//			tUp = dpk.t
//		}
//	}
//	if flag2 == -1 {
//		return nil, errors.New("you have no access to do the sign as the dpk is not in the ring")
//	}
//	ss = msvk.skkem.CryptoKemDec(ct)
//	if erro != nil {
//		fmt.Println(err)
//	}
//	H = hm(tUp)
//	s = mssk.S
//	si = expandV(ss)
//
//	bl = CheckDerivedPubKeyOwner(dpk, mpk, msvk)
//	if bl == false {
//		return nil, errors.New("you have no access to do the sign")
//	}
//
//	for i = 0; i < L; i++ {
//		sUp.vec[i] = polyAddition(s.vec[i], si.vec[i])
//	}
//	A = expandMatA()
//
//	for i = 0; i < K; i++ {
//		as.vec[i] = polyMultiplication(A[i].vec[0], sUp.vec[0])
//		for j = 1; j < L; j++ {
//			tmp2 = polyMultiplication(A[i].vec[j], sUp.vec[j])
//			as.vec[i] = polyAddition(as.vec[i], tmp2)
//		}
//	}
//
//	for i = 0; i < M; i++ {
//		I.vec[i] = polyMultiplication(H[i].vec[0], sUp.vec[0])
//		for j = 1; j < L; j++ {
//			tmp = polyMultiplication(H[i].vec[j], sUp.vec[j])
//			I.vec[i] = polyAddition(I.vec[i], tmp)
//		}
//	}
//
//	rejection = 1
//	for i2 = 0; i2 < 10; i2-- {
//		if rejection != 1 {
//			break
//		}
//		rejection = 0
//		//step4
//		y = generateLGamma()
//
//		for i = 0; i < K; i++ {
//			w.vec[i] = polyMultiplication(A[i].vec[0], y.vec[0])
//			for j = 1; j < L; j++ {
//				tmp = polyMultiplication(A[i].vec[j], y.vec[j])
//				w.vec[i] = polyAddition(w.vec[i], tmp)
//			}
//		}
//
//		for i = 0; i < M; i++ {
//			v.vec[i] = polyMultiplication(H[i].vec[0], y.vec[0])
//			for j = 1; j < L; j++ {
//				tmp = polyMultiplication(H[i].vec[j], y.vec[j])
//				v.vec[i] = polyAddition(v.vec[i], tmp)
//			}
//		}
//		iMain = ii + 1
//		for iMain = ii + 1; iMain < ii+r; iMain++ {
//			tUp = dpkRing.Dpk[iMain%r].t
//			H = hm(tUp)
//			c = hTheta(msg, len(msg), dpkRing, w, v, I)
//			if iMain%r == 0 {
//				for i = 0; i < N; i++ {
//					c1.coeffs[i] = c.coeffs[i]
//				}
//			}
//
//			z = generateLGammaSubToThetaEta()
//			zz[iMain%r] = z
//			for i = 0; i < K; i++ {
//				az.vec[i] = polyMultiplication(A[i].vec[0], z.vec[0])
//				for j = 1; j < L; j++ {
//					tmp = polyMultiplication(A[i].vec[j], z.vec[j])
//					az.vec[i] = polyAddition(az.vec[i], tmp)
//				}
//			}
//
//			for j = 0; j < K; j++ {
//				cti.vec[j] = polyMultiplication(tUp.vec[j], c)
//				for i = 0; i < N; i++ {
//					cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
//				}
//			}
//			for i = 0; i < K; i++ {
//				w.vec[i] = polyAddition(az.vec[i], cti.vec[i])
//			}
//
//			for i = 0; i < M; i++ {
//				hz.vec[i] = polyMultiplication(H[i].vec[0], z.vec[0])
//				for j = 1; j < L; j++ {
//					tmp = polyMultiplication(H[i].vec[j], z.vec[j])
//					hz.vec[i] = polyAddition(hz.vec[i], tmp)
//				}
//			}
//
//			for j = 0; j < M; j++ {
//				cI.vec[j] = polyMultiplication(I.vec[j], c)
//				for i = 0; i < N; i++ {
//					cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
//				}
//			}
//			for i = 0; i < M; i++ {
//				v.vec[i] = polyAddition(hz.vec[i], cI.vec[i])
//			}
//		}
//		c = hTheta(msg, len(msg), dpkRing, w, v, I)
//
//		if ii == 0 {
//			for i = 0; i < N; i++ {
//				c1.coeffs[i] = c.coeffs[i]
//			}
//		}
//
//		for j = 0; j < L; j++ {
//			cs.vec[j] = polyMultiplication(sUp.vec[j], c)
//		}
//		for i = 0; i < L; i++ {
//			z.vec[i] = polyAddition(y.vec[i], cs.vec[i])
//		}
//		zz[ii] = z
//		//ct = dpk.c
//		tUp = dpk.t
//		H = hm(tUp)
//		for i = 0; i < L; i++ {
//			for j = 0; j < N; j++ {
//				if (z.vec[i].coeffs[j] > (GammaMinusTwoEtaTheta)) || (z.vec[i].coeffs[j] < -(GammaMinusTwoEtaTheta)) {
//					rejection = 1
//				}
//			}
//		}
//	}
//	sigma.z = zz
//	sigma.c = c1
//	sigma.r = r
//	sigma.I = I
//
//	return sigma, nil
//}
func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	return Sign1(msg, dpkRing, dpk, mpk, msvk, mssk)
}
func Sign1(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (*Signature, error) {
	// check whether the derived public key is derived from given master public key
	isDerived, err := CheckDerivedPubKeyOwner1(dpk, mpk, msvk)
	if err != nil || !isDerived {
		return nil, fmt.Errorf("the derived public key is not derived from master public key")
	}

	// check whether the derived public exists in the ring, and set the index
	index := 0
	for i := 0; i < dpkRing.R; i++ {
		if dpk.t.Equal(&dpkRing.Dpk[i].t) {
			index = i
			break
		}
	}
	if index == dpkRing.R {
		return nil, fmt.Errorf("the derived public ring does not contain the given derived public key")
	}

	// check whether the ring has repetitive derive public key
	for i := 0; i < dpkRing.R; i++ {
		for j := i + 1; j < dpkRing.R; j++ {
			if dpkRing.Dpk[i].Equal(&dpkRing.Dpk[j]) {
				return nil, fmt.Errorf("the ring has same derived public key with index %d and %d", i, j)
			}
		}
	}

	sigma := &Signature{}
	sigma.r = dpkRing.R
	var tmp *poly
	//k=kem.Decaps(ct)
	k := msvk.skkem.CryptoKemDec(dpk.c)
	// siBar=expandV(k)
	siBar, err := expandV1(k)
	if err != nil {
		return nil, err
	}
	//siCap=s+siBar
	sCap := new(polyvecl)
	for i := 0; i < L; i++ {
		sCap.vec[i] = *NewPoly().Add(&mssk.S.vec[i], &siBar.vec[i])
	}

	// sigmaI=H*sCap
	H, err := hm1(&dpk.t)
	if err != nil {
		return nil, err
	}
	for i := 0; i < M; i++ {
		sigma.I.vec[i] = *NewPoly().Mul(&H[i].vec[0], &sCap.vec[0]) // do not to modify H and sCap
		for j := 1; j < L; j++ {
			tmp = NewPoly().Mul(&H[i].vec[j], &sCap.vec[j]) // do not to modify H and sCap
			sigma.I.vec[i] = *NewPoly().Add(&sigma.I.vec[i], tmp)
		}
	}
	A, err := generateMatrixAFromCRS() //TODO:this variable should be a global parameter
	if err != nil {
		return nil, err
	}

	// Debug
	as := new(polyveck)
	for i := 0; i < K; i++ {
		as.vec[i] = *NewPoly().Mul(&A[i].vec[0], &sCap.vec[0])
		for j := 1; j < L; j++ {
			tmp = NewPoly().Mul(&A[i].vec[j], &sCap.vec[j])
			as.vec[i] = *NewPoly().Add(&as.vec[i], tmp)
		}
	}
	if !as.Equal(&dpk.t) {
		return nil, fmt.Errorf("after computing, the formula tCap = A * sCap is breaken")
	}
	// Debug

	rejection := true
	zz := make([]polyvecl, dpkRing.R)
	for i := 0; i < 10; i++ { //at most ten times
		if !rejection {
			break
		}
		rejection = false

		seed, err := randomBytesFromCRand(32)
		if err != nil {
			return nil, err
		}
		// generate uniformly random y
		y := new(polyvecl)
		_, _, err = generatePolyVecLFromSeed(seed, 0, generatePolyGammmaFromSeed, y)
		if err != nil {
			return nil, err
		}

		//w=Ay
		w := new(polyveck)
		for j := 0; j < K; j++ {
			w.vec[j] = *NewPoly().Mul(&A[j].vec[0], &y.vec[0])
			for k := 1; k < L; k++ {
				tmp = NewPoly().Mul(&A[j].vec[k], &y.vec[k])
				w.vec[j] = *NewPoly().Add(&w.vec[j], tmp)
			}
		}
		//v=Hy
		v := new(polyvecm)
		for j := 0; j < M; j++ {
			v.vec[j] = *NewPoly().Mul(&H[j].vec[0], &y.vec[0])
			for k := 1; k < L; k++ {
				tmp = NewPoly().Mul(&H[j].vec[k], &y.vec[k])
				v.vec[j] = *NewPoly().Add(&v.vec[j], tmp)
			}
		}

		//ring signature
		ci := new(poly)
		// iterating computation
		for j := 0; j < dpkRing.R-1; j++ {
			tUp := &dpkRing.Dpk[(j+1+index)%dpkRing.R].t
			Hi, err := hm1(tUp)
			if err != nil {
				return nil, err
			}
			ci, err = hTheta1(msg, len(msg), dpkRing, w, v, &sigma.I)
			if err != nil {
				return nil, err
			}
			if (j+1+index)%dpkRing.R == 0 {
				sigma.c = *ci.Copy()
			}
			seed, err := randomBytesFromCRand(32)
			if err != nil {
				return nil, err
			}
			pos := 0
			// generate uniformly random zi
			zi := new(polyvecl)
			_, _, err = generatePolyVecLFromSeed(seed, pos, generatePolyGmteFromSeed, zi)
			zz[(j+1+index)%dpkRing.R] = *zi

			// az = A * zi
			az := new(polyvecl)
			for l := 0; l < K; l++ {
				az.vec[l] = *NewPoly().Mul(&A[l].vec[0], &zi.vec[0])
				for k := 1; k < L; k++ {
					tmp = NewPoly().Mul(&A[l].vec[k], &zi.vec[k])
					az.vec[l] = *NewPoly().Add(&az.vec[l], tmp)
				}
			}
			// cti = - tUp * ci
			cti := new(polyveck)
			for l := 0; l < K; l++ {
				cti.vec[l] = *NewPoly().Mul(&tUp.vec[l], ci)
				for k := 0; k < N; k++ {
					cti.vec[l].coeffs[k] = reduce(-cti.vec[l].coeffs[k])
				}
			}
			//w = az + cti
			for k := 0; k < K; k++ {
				w.vec[k] = *NewPoly().Add(&az.vec[k], &cti.vec[k])
			}

			// hz = Hi * zi
			hz := new(polyvecm)
			for l := 0; l < M; l++ {
				hz.vec[l] = *NewPoly().Mul(&Hi[l].vec[0], &zi.vec[0])
				for k := 1; k < L; k++ {
					tmp = NewPoly().Mul(&Hi[l].vec[k], &zi.vec[k])
					hz.vec[l] = *NewPoly().Add(&hz.vec[l], tmp)
				}
			}
			// cI = - ci * I
			cI := new(polyvecm)
			for l := 0; l < M; l++ {
				cI.vec[l] = *NewPoly().Mul(&sigma.I.vec[l], ci)
				for k := 0; k < N; k++ {
					cI.vec[l].coeffs[k] = reduce(-cI.vec[l].coeffs[k])
				}
			}
			// v = hz + cI
			for k := 0; k < M; k++ {
				v.vec[k] = *NewPoly().Add(&hz.vec[k], &cI.vec[k])
			}
		}

		ci, err = hTheta1(msg, len(msg), dpkRing, w, v, &sigma.I)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			sigma.c = *ci.Copy()
		}
		// cs = sCap * ci
		cs := new(polyvecl)
		for j := 0; j < L; j++ {
			cs.vec[j] = *NewPoly().Mul(&sCap.vec[j], ci)
		}
		//z = y + cs
		for j := 0; j < L; j++ {
			zz[index].vec[j] = *NewPoly().Add(&y.vec[j], &cs.vec[j])
		}
		for j := 0; j < L; j++ {
			for k := 0; k < N; k++ {
				if (zz[index].vec[j].coeffs[k] > (GammaMinusTwoEtaTheta)) || (zz[index].vec[j].coeffs[k] < -(GammaMinusTwoEtaTheta)) {
					rejection = true
				}
			}
		}
	}
	for i := 0; i < len(zz); i++ {
		sigma.z = append(sigma.z, zz[i])
	}
	return sigma, nil
}

// note the message type
// only say true or false, does not tell why and what happen, thus there is nor error information
//func Verify(msg []byte, dpkRing *DpkRing, sig *Signature) (keyImage *KeyImage, valid bool) {
//	// to do
//	keyImg := &KeyImage{}
//	var (
//		i, j, iMain, r, flagDpk int
//		flagg                   bool
//		c, c1, tmp              poly
//		A                       [K]polyvecl
//		H                       [M]polyvecl
//		tUp, w, az, cti         polyveck
//		v, hz, cI, I            polyvecm
//		z                       polyvecl
//		tmpDpk                  DerivedPubKey
//	)
//	r = dpkRing.R
//	flagg = true
//	flagDpk = 0
//	tmpDpk = dpkRing.Dpk[0]
//	for i = 1; i < r; i++ {
//		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
//			flagDpk = 1
//			break
//		}
//	}
//	if flagDpk == 1 {
//		return nil, false
//	}
//	//fmt.Println("passed 1")
//
//	c1 = sig.c
//	I = sig.I
//	keyImg.I = I
//
//	for i = 0; i < N; i++ {
//		c.coeffs[i] = c1.coeffs[i]
//	}
//	flagg = CheckC(c)
//	if flagg == false {
//		return nil, false
//	}
//	//fmt.Println("passed 2")
//
//	A = expandMatA()
//
//	for iMain = 0; iMain < r; iMain++ {
//		tUp = dpkRing.Dpk[iMain%r].t
//
//		H = hm(tUp)
//		z = sig.z[iMain%r]
//		flagg = CheckZNorm(z)
//		if flagg == false {
//			return nil, false
//		}
//		//fmt.Println("passed 3")
//
//		for i = 0; i < K; i++ {
//			az.vec[i] = polyMultiplication(A[i].vec[0], z.vec[0])
//			for j = 1; j < L; j++ {
//				tmp = polyMultiplication(A[i].vec[j], z.vec[j])
//				az.vec[i] = polyAddition(az.vec[i], tmp)
//			}
//		}
//		for j = 0; j < K; j++ {
//			cti.vec[j] = polyMultiplication(tUp.vec[j], c)
//			for i = 0; i < N; i++ {
//				cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
//			}
//		}
//		for i = 0; i < K; i++ {
//			w.vec[i] = polyAddition(az.vec[i], cti.vec[i])
//		}
//		for i = 0; i < M; i++ {
//			hz.vec[i] = polyMultiplication(H[i].vec[0], z.vec[0])
//			for j = 1; j < L; j++ {
//				tmp = polyMultiplication(H[i].vec[j], z.vec[j])
//				hz.vec[i] = polyAddition(hz.vec[i], tmp)
//			}
//		}
//		for j = 0; j < M; j++ {
//			cI.vec[j] = polyMultiplication(I.vec[j], c)
//			for i = 0; i < N; i++ {
//				cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
//			}
//		}
//		for i = 0; i < M; i++ {
//			v.vec[i] = polyAddition(hz.vec[i], cI.vec[i])
//		}
//		c = hTheta(msg, len(msg), dpkRing, w, v, I)
//	}
//	//fmt.Println("passed 4")
//	for i = 0; i < N; i++ {
//		if c.coeffs[i] != c1.coeffs[i] {
//			return nil, false
//		}
//	}
//
//	return keyImg, true
//}
func Verify(msg []byte, dpkRing *DpkRing, sig *Signature) (*KeyImage, bool, error) {
	return Verify1(msg, dpkRing, sig)
}
func Verify1(msg []byte, dpkRing *DpkRing, sig *Signature) (*KeyImage, bool, error) {
	// to do
	// check whether the ring has repetitive derive public key
	for i := 0; i < dpkRing.R; i++ {
		for j := i + 1; j < dpkRing.R; j++ {
			if dpkRing.Dpk[i].Equal(&dpkRing.Dpk[j]) {
				return nil, false, fmt.Errorf("the ring has same derived public key with index %d and %d", i, j)
			}
		}
	}
	//check the format of c
	if !sig.c.CheckInOne() {
		return nil, false, fmt.Errorf("the c in signature has wrong format")
	}
	originC := sig.c.Copy()
	//fmt.Println("passed 2")

	//check the format of z
	for i := 0; i < len(sig.z); i++ {
		if !sig.z[i].CheckInGmte() {
			return nil, false, fmt.Errorf("the z[%d] has wrong format", i)
		}
	}

	A, err := generateMatrixAFromCRS()
	if err != nil {
		return nil, false, err
	}

	c := sig.c.Copy()
	for cur := 0; cur < dpkRing.R; cur++ {
		tCap := &dpkRing.Dpk[cur%dpkRing.R].t

		H, err := hm1(tCap)
		z := sig.z[cur]

		w := new(polyveck)
		// w = A * z - c * t
		az := new(polyveck)
		for i := 0; i < K; i++ {
			az.vec[i] = *NewPoly().Mul(&A[i].vec[0], &z.vec[0])
			for j := 1; j < L; j++ {
				tmp := *NewPoly().Mul(&A[i].vec[j], &z.vec[j])
				az.vec[i] = *NewPoly().Add(&az.vec[i], &tmp)
			}
		}
		cti := new(polyveck)
		for i := 0; i < K; i++ {
			cti.vec[i] = *NewPoly().Mul(&tCap.vec[i], c)
			for j := 0; j < N; j++ {
				cti.vec[i].coeffs[j] = reduce(-cti.vec[i].coeffs[j])
			}
		}
		for i := 0; i < K; i++ {
			w.vec[i] = *NewPoly().Add(&az.vec[i], &cti.vec[i])
		}

		v := new(polyvecm)
		// v = H * z - c * I
		hz := new(polyvecm)
		for i := 0; i < M; i++ {
			hz.vec[i] = *NewPoly().Mul(&H[i].vec[0], &z.vec[0])
			for j := 1; j < L; j++ {
				tmp := *NewPoly().Mul(&H[i].vec[j], &z.vec[j])
				hz.vec[i] = *NewPoly().Add(&hz.vec[i], &tmp)
			}
		}
		cI := new(polyvecm)
		for i := 0; i < M; i++ {
			cI.vec[i] = *NewPoly().Mul(&sig.I.vec[i], c)
			for j := 0; j < N; j++ {
				cI.vec[i].coeffs[j] = reduce(-cI.vec[i].coeffs[j])
			}
		}
		for i := 0; i < M; i++ {
			v.vec[i] = *NewPoly().Add(&hz.vec[i], &cI.vec[i])
		}

		c, err = hTheta1(msg, len(msg), dpkRing, w, v, &sig.I)
		if err != nil {
			return nil, false, err
		}
	}

	if !originC.Equal(c) {
		return nil, false, fmt.Errorf("the computed c1 is not equal to c1 in signature")
	}

	return &KeyImage{*sig.I.Copy()}, true, nil
}

//func Link(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) bool {
//	var (
//		i, flagDpk   int
//		flag1, flag2 bool
//		I1, I2       polyvecm
//	)
//	flagDpk = 0
//	tmpDpk := DerivedPubKey{}
//	keyImage1 := &KeyImage{}
//	keyImage2 := &KeyImage{}
//	tmpDpk = dpkRing1.Dpk[0]
//	keyImage1.I = sig1.I
//	keyImage2.I = sig2.I
//
//	for i = 1; i < dpkRing1.R; i++ {
//		if Equaldpk(tmpDpk, dpkRing1.Dpk[i]) {
//			flagDpk = 1
//			break
//		}
//	}
//	if flagDpk == 1 {
//		return false
//	}
//
//	tmpDpk = dpkRing2.Dpk[0]
//	for i = 1; i < dpkRing2.R; i++ {
//		if Equaldpk(tmpDpk, dpkRing2.Dpk[i]) {
//			flagDpk = 1
//			break
//		}
//	}
//	if flagDpk == 1 {
//		return false
//	}
//
//	keyImage1, flag1 = Verify(msg1, dpkRing1, sig1)
//	keyImage2, flag2 = Verify(msg2, dpkRing2, sig2)
//	if flag1 == false || flag2 == false {
//		return false
//	}
//	I1 = sig1.I
//	I2 = sig2.I
//
//	return EqualI(I1, I2)
//}

func Link(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) (bool, error) {
	return Link1(msg1, dpkRing1, sig1, msg2, dpkRing2, sig2)
}
func Link1(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) (bool, error) {
	var err error
	// TODO: if there is no the same derived publick key in given two ring, we think it is not linkable
	flag := false
	for i := 0; i < dpkRing1.R; i++ {
		for j := 0; j < dpkRing2.R; j++ {
			if dpkRing1.Dpk[i].Equal(&dpkRing2.Dpk[j]) {
				flag = true
			}
		}
	}
	if !flag {
		return false, fmt.Errorf("there is no same derived public key in given two rings")
	}

	_, flag, err = Verify1(msg1, dpkRing1, sig1)
	if err != nil || !flag {
		return false, fmt.Errorf("the first signature fail to be varified")
	}
	_, flag, err = Verify1(msg2, dpkRing2, sig2)
	if err != nil || !flag {
		return false, fmt.Errorf("the second signature fail to be varified")
	}

	return sig1.I.Equal(&sig2.I), nil
}
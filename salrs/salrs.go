package salrs

import (
	"errors"
	"fmt"
	"github.com/cryptosuite/kyber-go/kyber"
	"log"
)

/*
This file contains all the public constant, type, and functions that are available to oue of the package.
*/

//	public const def	begin
const PassPhaseByteLen = 32
var pkem = kyber.Kyber768

const (
	N                     = 256
	L                     = 5
	K                     = 3
	M                     = 1
	Theta                 = 60
	Eta                   = 3
	Gamma                 = 699453
	GammaMinusTwoEtaTheta = 699093
	Q                     = 34360786961
	Q2                    = 17180393480 //(Q - 1)/2
	R1                    = -16915236577
	R2                    = -8376412603
	R3                    = -3354919284
	R4                    = 11667088462
	R5                    = -12474372669
	R6                    = -3077095668
	R7                    = 14301820476

	PackTByteLen = 3456
	PackSByteLen = 480
	PackZByteLen = 3520
	PackIByteLen = 1152
	cstr     = "today_is_a_good_day_today_is_a_good_day_today_is_a_good_day"     //TODO:this const string should be random?
	CSTRSIZE = len(cstr)
)

var(
	MpkByteLen    = pkem.CryptoPublicKeyBytes() + PackTByteLen
	PKKEMByteLen  = pkem.CryptoPublicKeyBytes()
	MskByteLen    = pkem.CryptoSecretKeyBytes() + PackSByteLen
	SKKEMByteLen  = pkem.CryptoSecretKeyBytes()
	DpkByteLen    = pkem.CryptoCiphertextBytes() + PackTByteLen
	CipherByteLen = pkem.CryptoCiphertextBytes()
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
	R   int
}

type Signature struct {
	z []polyvecl
	r int
	c poly
	I polyvecm
}

type KeyImage struct {
	I polyvecm
}

//	public type def		end

//	public fun	begin

//	to do: how to define or store PP
//  if the contents for PP are two large, use a separate param.go to store them, otherwise, also in this file
//	note that the sizes depend on the PP, we may need to put these constants together with PP.
func Setup() {
	pkem = kyber.Kyber768
}

func GenerateMasterKey(masterSeed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	if len(masterSeed) == 0 {
		return nil, nil, nil, errors.New("master seed is empty")
	}
	masterPubKey := &MasterPubKey{}
	masterSecretViewKey := &MasterSecretViewKey{}
	masterSecretSignKey := &MasterSecretSignKey{}

	var (
		i, j int
		A    [K]polyvecl
		t    polyveck
		s    polyvecl
		tmp  poly
		//stmp = make([]byte, PackSByteLen)
	)

	masterPubKey.pkkem, masterSecretViewKey.skkem,err = pkem.CryptoKemKeyPair(masterSeed)
	if err != nil {
		fmt.Println(err)
	}

	s = generateLEta()

	A = expandMatA()
	for i = 0; i < K; i++ {
		t.vec[i] = polyMultiplication(A[i].vec[0], s.vec[0])
		for j = 1; j < L; j++ {
			tmp = polyMultiplication(A[i].vec[j], s.vec[j])
			t.vec[i] = polyAddition(t.vec[i], tmp)
		}
	}
	masterPubKey.t = t
	masterSecretSignKey.S = s

	return masterPubKey, masterSecretViewKey, masterSecretSignKey, nil
}
func GenerateMasterKey1(mSeed []byte)(mpk *MasterPubKey,msvk *MasterSecretViewKey,mssk *MasterSecretSignKey,err error) {
	if len(mSeed) == 0{
		 return nil,nil,nil,errors.New("master seed is empty")
	}
	mpk=new(MasterPubKey)
	msvk=new(MasterSecretViewKey)
	mssk=new(MasterSecretSignKey)
	mpk.pkkem, msvk.skkem, err = pkem.CryptoKemKeyPair(mSeed)
	if err!=nil {
		log.Fatal(err)
	}
	s:=generateLEta()
	A:=expandMatA()
	t :=new(polyveck)
	for i:=0;i<K;i++{
		t.vec[i]=*NewPoly().Mul(&A[i].vec[0],&s.vec[0])
		for j:=1;j<L;j++{
			tmp:=NewPoly().Mul(&A[i].vec[j],&s.vec[j])
			t.vec[i]=*NewPoly().Add(&t.vec[i],tmp)
		}
	}
	mpk.t=*t
	mssk.S=s
	return
}

func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, errors.New("mpk is nil")
	}
	derivedPubKey := &DerivedPubKey{}

	var (
		i, j       int
		t, t2, tUp polyveck
		A          [K]polyvecl
		s2         polyvecl
		tmp        poly
		erro       error
	)

	ss := make([]byte, pkem.CryptoSharedSecretBytes())
	ct := make([]byte, pkem.CryptoCiphertextBytes())
	ct, ss, err = mpk.pkkem.CryptoKemEnc()
	if erro != nil {
		fmt.Println(err)
	}

	t = mpk.t
	s2 = expandV(ss)
	A = expandMatA()

	for i = 0; i < K; i++ {
		t2.vec[i] = polyMultiplication(A[i].vec[0], s2.vec[0])
		for j = 1; j < L; j++ {
			tmp = polyMultiplication(A[i].vec[j], s2.vec[j])
			t2.vec[i] = polyAddition(t2.vec[i], tmp)
		}
	}
	for i = 0; i < K; i++ {
		tUp.vec[i] = polyAddition(t.vec[i], t2.vec[i])
	}
	derivedPubKey.c = ct
	derivedPubKey.t = tUp

	return derivedPubKey, nil
}
func GenerateDerivedPubKey1(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, errors.New("mpk is nil")
	}
	dpk = &DerivedPubKey{}

	var (
		i, j       int
		t, t2, tUp polyveck
		A          [K]polyvecl
		s2         polyvecl
		tmp        poly
	)

	ss := make([]byte, pkem.CryptoSharedSecretBytes())
	ct := make([]byte, pkem.CryptoCiphertextBytes())
	ct, ss, err = mpk.pkkem.CryptoKemEnc()
	if err != nil {
		fmt.Println(err)
	}

	t = mpk.t
	s2 = expandV(ss)
	A = expandMatA()

	for i = 0; i < K; i++ {
		t2.vec[i] = *NewPoly().Mul(&A[i].vec[0], &s2.vec[0])
		for j = 1; j < L; j++ {
			tmp = *NewPoly().Mul(&A[i].vec[j], &s2.vec[j])
			t2.vec[i] = *NewPoly().Add(&t2.vec[i], &tmp)
		}
	}
	for i = 0; i < K; i++ {
		tUp.vec[i] = *NewPoly().Add(&t.vec[i], &t2.vec[i])
	}
	dpk.c = ct
	dpk.t = tUp

	return dpk, nil
}

func CheckDerivedPubKeyOwner(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) bool {
	var (
		i, j       int
		tUp, t, t2 polyveck
		s2         polyvecl
		A          [K]polyvecl
		tmp        poly
	)
	ct := make([]byte, pkem.CryptoCiphertextBytes())
	ss := make([]byte, pkem.CryptoSharedSecretBytes())

	ct = dpk.c
	tUp = dpk.t
	t = mpk.t

	for i = 0; i < K; i++ {
		for j = 0; j < N; j++ {
			if tUp.vec[i].coeffs[j] > Q2 || tUp.vec[i].coeffs[j] < -Q2 {
				return false
			}
		}
	}
	//fmt.Println("passed 1")

	ss = msvk.skkem.CryptoKemDec(ct)
	s2 = expandV(ss)
	A = expandMatA()
	for i = 0; i < N; i++ {
		tmp.coeffs[i] = 0
		t2.vec[0].coeffs[i] = 0
	}
	for i = 0; i < K; i++ {
		t2.vec[i] = polyMultiplication(A[i].vec[0], s2.vec[0])
		for j = 1; j < L; j++ {
			tmp = polyMultiplication(A[i].vec[j], s2.vec[j])
			t2.vec[i] = polyAddition(t2.vec[i], tmp)
		}
	}

	for i = 0; i < K; i++ {
		for j = 0; j < N; j++ {
			if tUp.vec[i].coeffs[j] != reduce(t.vec[i].coeffs[j]+t2.vec[i].coeffs[j]) {
				return false
			}
		}
	}

	return true
}
func CheckDerivedPubKeyOwner1(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) bool {
	var (
		i, j       int
		tUp, t, t2 polyveck
		s2         polyvecl
		A          [K]polyvecl
		tmp        poly
	)
	ct := make([]byte, pkem.CryptoCiphertextBytes())
	ss := make([]byte, pkem.CryptoSharedSecretBytes())

	ct = dpk.c
	tUp = dpk.t
	t = mpk.t

	for i = 0; i < K; i++ {
		for j = 0; j < N; j++ {
			if tUp.vec[i].coeffs[j] > Q2 || tUp.vec[i].coeffs[j] < -Q2 {
				return false
			}
		}
	}
	//fmt.Println("passed 1")

	ss = msvk.skkem.CryptoKemDec(ct)
	s2 = expandV(ss)
	A = expandMatA()
	for i = 0; i < N; i++ {
		tmp.coeffs[i] = 0
		t2.vec[0].coeffs[i] = 0
	}
	for i = 0; i < K; i++ {
		t2.vec[i] = *NewPoly().Mul(&A[i].vec[0], &s2.vec[0])
		for j = 1; j < L; j++ {
			tmp = *NewPoly().Mul(&A[i].vec[j], &s2.vec[j])
			t2.vec[i] = *NewPoly().Add(&t2.vec[i], &tmp)
		}
	}

	for i = 0; i < K; i++ {
		for j = 0; j < N; j++ {
			if tUp.vec[i].coeffs[j] != reduce(t.vec[i].coeffs[j]+t2.vec[i].coeffs[j]) {
				return false
			}
		}
	}

	return true
}

// note the message type
func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	sigma := &Signature{}
	var (
		i, iMain, j, rejection, r, i2 int
		A                             [K]polyvecl
		H                             [M]polyvecl
		s, si, sUp, z, y, cs          polyvecl
		c, c1, tmp, tmp2              poly
		tUp, w, as, az, cti           polyveck
		I, v, hz, cI                  polyvecm
		flag2, flagDpk, ii            = -1, 0, 0
		tmpDpk                        DerivedPubKey
		bl                            = true
		erro                          error
	)

	ss := make([]byte, pkem.CryptoSharedSecretBytes())
	ct := make([]byte, pkem.CryptoCiphertextBytes())

	r = dpkRing.R
	zz := make([]polyvecl, r)
	tmpDpk = dpkRing.Dpk[0]
	for i = 1; i < dpkRing.R; i++ {
		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return nil, errors.New("ring check failed")
	}

	for i = 0; i < dpkRing.R; i++ {
		if Equaldpk(*dpk, dpkRing.Dpk[i]) {
			ii = i
			flag2 = 0
			ct = dpk.c
			tUp = dpk.t
		}
	}
	if flag2 == -1 {
		return nil, errors.New("you have no access to do the sign as the dpk is not in the ring")
	}
	ss = msvk.skkem.CryptoKemDec(ct)
	if erro != nil {
		fmt.Println(err)
	}
	H = hm(tUp)
	s = mssk.S
	si = expandV(ss)

	bl = CheckDerivedPubKeyOwner(dpk, mpk, msvk)
	if bl == false {
		return nil, errors.New("you have no access to do the sign")
	}

	for i = 0; i < L; i++ {
		sUp.vec[i] = polyAddition(s.vec[i], si.vec[i])
	}
	A = expandMatA()

	for i = 0; i < K; i++ {
		as.vec[i] = polyMultiplication(A[i].vec[0], sUp.vec[0])
		for j = 1; j < L; j++ {
			tmp2 = polyMultiplication(A[i].vec[j], sUp.vec[j])
			as.vec[i] = polyAddition(as.vec[i], tmp2)
		}
	}

	for i = 0; i < M; i++ {
		I.vec[i] = polyMultiplication(H[i].vec[0], sUp.vec[0])
		for j = 1; j < L; j++ {
			tmp = polyMultiplication(H[i].vec[j], sUp.vec[j])
			I.vec[i] = polyAddition(I.vec[i], tmp)
		}
	}

	rejection = 1
	for i2 = 0; i2 < 10; i2-- {
		if rejection != 1 {
			break
		}
		rejection = 0
		//step4
		y = generateLGamma()

		for i = 0; i < K; i++ {
			w.vec[i] = polyMultiplication(A[i].vec[0], y.vec[0])
			for j = 1; j < L; j++ {
				tmp = polyMultiplication(A[i].vec[j], y.vec[j])
				w.vec[i] = polyAddition(w.vec[i], tmp)
			}
		}

		for i = 0; i < M; i++ {
			v.vec[i] = polyMultiplication(H[i].vec[0], y.vec[0])
			for j = 1; j < L; j++ {
				tmp = polyMultiplication(H[i].vec[j], y.vec[j])
				v.vec[i] = polyAddition(v.vec[i], tmp)
			}
		}
		iMain = ii + 1
		for iMain = ii + 1; iMain < ii+r; iMain++ {
			tUp = dpkRing.Dpk[iMain%r].t
			H = hm(tUp)
			c = hTheta(msg, len(msg), dpkRing, w, v, I)
			if iMain%r == 0 {
				for i = 0; i < N; i++ {
					c1.coeffs[i] = c.coeffs[i]
				}
			}

			z = generateLGammaSubToThetaEta()
			zz[iMain%r] = z
			for i = 0; i < K; i++ {
				az.vec[i] = polyMultiplication(A[i].vec[0], z.vec[0])
				for j = 1; j < L; j++ {
					tmp = polyMultiplication(A[i].vec[j], z.vec[j])
					az.vec[i] = polyAddition(az.vec[i], tmp)
				}
			}

			for j = 0; j < K; j++ {
				cti.vec[j] = polyMultiplication(tUp.vec[j], c)
				for i = 0; i < N; i++ {
					cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
				}
			}
			for i = 0; i < K; i++ {
				w.vec[i] = polyAddition(az.vec[i], cti.vec[i])
			}

			for i = 0; i < M; i++ {
				hz.vec[i] = polyMultiplication(H[i].vec[0], z.vec[0])
				for j = 1; j < L; j++ {
					tmp = polyMultiplication(H[i].vec[j], z.vec[j])
					hz.vec[i] = polyAddition(hz.vec[i], tmp)
				}
			}

			for j = 0; j < M; j++ {
				cI.vec[j] = polyMultiplication(I.vec[j], c)
				for i = 0; i < N; i++ {
					cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
				}
			}
			for i = 0; i < M; i++ {
				v.vec[i] = polyAddition(hz.vec[i], cI.vec[i])
			}
		}
		c = hTheta(msg, len(msg), dpkRing, w, v, I)

		if ii == 0 {
			for i = 0; i < N; i++ {
				c1.coeffs[i] = c.coeffs[i]
			}
		}

		for j = 0; j < L; j++ {
			cs.vec[j] = polyMultiplication(sUp.vec[j], c)
		}
		for i = 0; i < L; i++ {
			z.vec[i] = polyAddition(y.vec[i], cs.vec[i])
		}
		zz[ii] = z
		//ct = dpk.c
		tUp = dpk.t
		H = hm(tUp)
		for i = 0; i < L; i++ {
			for j = 0; j < N; j++ {
				if (z.vec[i].coeffs[j] > (GammaMinusTwoEtaTheta)) || (z.vec[i].coeffs[j] < -(GammaMinusTwoEtaTheta)) {
					rejection = 1
				}
			}
		}
	}
	sigma.z = zz
	sigma.c = c1
	sigma.r = r
	sigma.I = I

	return sigma, nil
}
func Sign1(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	sigma := &Signature{}
	var (
		i, iMain, j, rejection, r, i2 int
		A                             [K]polyvecl
		H                             [M]polyvecl
		s, si, sUp, z, y, cs          polyvecl
		c, c1, tmp, tmp2              poly
		tUp, w, as, az, cti           polyveck
		I, v, hz, cI                  polyvecm
		flag2, flagDpk, ii            = -1, 0, 0
		tmpDpk                        DerivedPubKey
		bl                            = true
		erro                          error
	)

	ss := make([]byte, pkem.CryptoSharedSecretBytes())
	ct := make([]byte, pkem.CryptoCiphertextBytes())

	r = dpkRing.R
	zz := make([]polyvecl, r)
	tmpDpk = dpkRing.Dpk[0]
	for i = 1; i < dpkRing.R; i++ {
		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return nil, errors.New("ring check failed")
	}

	for i = 0; i < dpkRing.R; i++ {
		if Equaldpk(*dpk, dpkRing.Dpk[i]) {
			ii = i
			flag2 = 0
			ct = dpk.c
			tUp = dpk.t
		}
	}
	if flag2 == -1 {
		return nil, errors.New("you have no access to do the sign as the dpk is not in the ring")
	}
	ss = msvk.skkem.CryptoKemDec(ct)
	if erro != nil {
		fmt.Println(err)
	}
	H = hm(tUp)
	s = mssk.S
	si = expandV(ss)

	bl = CheckDerivedPubKeyOwner(dpk, mpk, msvk)
	if bl == false {
		return nil, errors.New("you have no access to do the sign")
	}

	for i = 0; i < L; i++ {
		sUp.vec[i] = *NewPoly().Add(&s.vec[i], &si.vec[i])
	}
	A = expandMatA()

	for i = 0; i < K; i++ {
		as.vec[i] = *NewPoly().Mul(&A[i].vec[0], &sUp.vec[0])
		for j = 1; j < L; j++ {
			tmp2 = *NewPoly().Mul(&A[i].vec[j], &sUp.vec[j])
			as.vec[i] = *NewPoly().Mul(&as.vec[i], &tmp2)
		}
	}

	for i = 0; i < M; i++ {
		I.vec[i] = *NewPoly().Mul(&H[i].vec[0], &sUp.vec[0])
		for j = 1; j < L; j++ {
			tmp = *NewPoly().Mul(&H[i].vec[j], &sUp.vec[j])
			I.vec[i] = *NewPoly().Add(&I.vec[i], &tmp)
		}
	}

	rejection = 1
	for i2 = 0; i2 < 10; i2-- {
		if rejection != 1 {
			break
		}
		rejection = 0
		//step4
		y = generateLGamma()

		for i = 0; i < K; i++ {
			w.vec[i] = *NewPoly().Mul(&A[i].vec[0], &y.vec[0])
			for j = 1; j < L; j++ {
				tmp = *NewPoly().Mul(&A[i].vec[j], &y.vec[j])
				w.vec[i] = *NewPoly().Add(&w.vec[i], &tmp)
			}
		}

		for i = 0; i < M; i++ {
			v.vec[i] = *NewPoly().Mul(&H[i].vec[0], &y.vec[0])
			for j = 1; j < L; j++ {
				tmp = *NewPoly().Mul(&H[i].vec[j], &y.vec[j])
				v.vec[i] = *NewPoly().Add(&v.vec[i], &tmp)
			}
		}
		iMain = ii + 1
		for iMain = ii + 1; iMain < ii+r; iMain++ {
			tUp = dpkRing.Dpk[iMain%r].t
			H = hm(tUp)
			c = hTheta(msg, len(msg), dpkRing, w, v, I)
			if iMain%r == 0 {
				for i = 0; i < N; i++ {
					c1.coeffs[i] = c.coeffs[i]
				}
			}

			z = generateLGammaSubToThetaEta()
			zz[iMain%r] = z
			for i = 0; i < K; i++ {
				az.vec[i] = *NewPoly().Mul(&A[i].vec[0], &z.vec[0])
				for j = 1; j < L; j++ {
					tmp = *NewPoly().Mul(&A[i].vec[j], &z.vec[j])
					az.vec[i] = *NewPoly().Add(&az.vec[i],&tmp)
				}
			}

			for j = 0; j < K; j++ {
				cti.vec[j] = *NewPoly().Mul(&tUp.vec[j], &c)
				for i = 0; i < N; i++ {
					cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
				}
			}
			for i = 0; i < K; i++ {
				w.vec[i] = *NewPoly().Add(&az.vec[i], &cti.vec[i])
			}

			for i = 0; i < M; i++ {
				hz.vec[i] = *NewPoly().Mul(&H[i].vec[0], &z.vec[0])
				for j = 1; j < L; j++ {
					tmp = *NewPoly().Mul(&H[i].vec[j], &z.vec[j])
					hz.vec[i] = *NewPoly().Add(&hz.vec[i], &tmp)
				}
			}

			for j = 0; j < M; j++ {
				cI.vec[j] = *NewPoly().Mul(&I.vec[j], &c)
				for i = 0; i < N; i++ {
					cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
				}
			}
			for i = 0; i < M; i++ {
				v.vec[i] = *NewPoly().Add(&hz.vec[i], &cI.vec[i])
			}
		}
		c = hTheta(msg, len(msg), dpkRing, w, v, I)

		if ii == 0 {
			for i = 0; i < N; i++ {
				c1.coeffs[i] = c.coeffs[i]
			}
		}

		for j = 0; j < L; j++ {
			cs.vec[j] = *NewPoly().Mul(&sUp.vec[j], &c)
		}
		for i = 0; i < L; i++ {
			z.vec[i] = *NewPoly().Add(&y.vec[i], &cs.vec[i])
		}
		zz[ii] = z
		//ct = dpk.c
		tUp = dpk.t
		H = hm(tUp)
		for i = 0; i < L; i++ {
			for j = 0; j < N; j++ {
				if (z.vec[i].coeffs[j] > (GammaMinusTwoEtaTheta)) || (z.vec[i].coeffs[j] < -(GammaMinusTwoEtaTheta)) {
					rejection = 1
				}
			}
		}
	}
	sigma.z = zz
	sigma.c = c1
	sigma.r = r
	sigma.I = I

	return sigma, nil
}

// note the message type
// only say true or false, does not tell why and what happen, thus there is nor error information
func Verify(msg []byte, dpkRing *DpkRing, sig *Signature) (keyImage *KeyImage, valid bool) {
	// to do
	keyImg := &KeyImage{}
	var (
		i, j, iMain, r, flagDpk int
		flagg                   bool
		c, c1, tmp              poly
		A                       [K]polyvecl
		H                       [M]polyvecl
		tUp, w, az, cti         polyveck
		v, hz, cI, I            polyvecm
		z                       polyvecl
		tmpDpk                  DerivedPubKey
	)
	r = dpkRing.R
	flagg = true
	flagDpk = 0
	tmpDpk = dpkRing.Dpk[0]
	for i = 1; i < r; i++ {
		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return nil, false
	}
	//fmt.Println("passed 1")

	c1 = sig.c
	I = sig.I
	keyImg.I = I

	for i = 0; i < N; i++ {
		c.coeffs[i] = c1.coeffs[i]
	}
	flagg = CheckC(c)
	if flagg == false {
		return nil, false
	}
	//fmt.Println("passed 2")

	A = expandMatA()

	for iMain = 0; iMain < r; iMain++ {
		tUp = dpkRing.Dpk[iMain%r].t

		H = hm(tUp)
		z = sig.z[iMain%r]
		flagg = CheckZNorm(z)
		if flagg == false {
			return nil, false
		}
		//fmt.Println("passed 3")

		for i = 0; i < K; i++ {
			az.vec[i] = polyMultiplication(A[i].vec[0], z.vec[0])
			for j = 1; j < L; j++ {
				tmp = polyMultiplication(A[i].vec[j], z.vec[j])
				az.vec[i] = polyAddition(az.vec[i], tmp)
			}
		}
		for j = 0; j < K; j++ {
			cti.vec[j] = polyMultiplication(tUp.vec[j], c)
			for i = 0; i < N; i++ {
				cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
			}
		}
		for i = 0; i < K; i++ {
			w.vec[i] = polyAddition(az.vec[i], cti.vec[i])
		}
		for i = 0; i < M; i++ {
			hz.vec[i] = polyMultiplication(H[i].vec[0], z.vec[0])
			for j = 1; j < L; j++ {
				tmp = polyMultiplication(H[i].vec[j], z.vec[j])
				hz.vec[i] = polyAddition(hz.vec[i], tmp)
			}
		}
		for j = 0; j < M; j++ {
			cI.vec[j] = polyMultiplication(I.vec[j], c)
			for i = 0; i < N; i++ {
				cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
			}
		}
		for i = 0; i < M; i++ {
			v.vec[i] = polyAddition(hz.vec[i], cI.vec[i])
		}
		c = hTheta(msg, len(msg), dpkRing, w, v, I)
	}
	//fmt.Println("passed 4")
	for i = 0; i < N; i++ {
		if c.coeffs[i] != c1.coeffs[i] {
			return nil, false
		}
	}

	return keyImg, true
}
func Verify1(msg []byte, dpkRing *DpkRing, sig *Signature) (keyImage *KeyImage, valid bool) {
	// to do
	keyImg := &KeyImage{}
	var (
		i, j, iMain, r, flagDpk int
		flagg                   bool
		c, c1, tmp              poly
		A                       [K]polyvecl
		H                       [M]polyvecl
		tUp, w, az, cti         polyveck
		v, hz, cI, I            polyvecm
		z                       polyvecl
		tmpDpk                  DerivedPubKey
	)
	r = dpkRing.R
	flagg = true
	flagDpk = 0
	tmpDpk = dpkRing.Dpk[0]
	for i = 1; i < r; i++ {
		if Equaldpk(tmpDpk, dpkRing.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return nil, false
	}
	//fmt.Println("passed 1")

	c1 = sig.c
	I = sig.I
	keyImg.I = I

	for i = 0; i < N; i++ {
		c.coeffs[i] = c1.coeffs[i]
	}
	flagg = CheckC(c)
	if flagg == false {
		return nil, false
	}
	//fmt.Println("passed 2")

	A = expandMatA()

	for iMain = 0; iMain < r; iMain++ {
		tUp = dpkRing.Dpk[iMain%r].t

		H = hm(tUp)
		z = sig.z[iMain%r]
		flagg = CheckZNorm(z)
		if flagg == false {
			return nil, false
		}
		//fmt.Println("passed 3")

		for i = 0; i < K; i++ {
			az.vec[i] = *NewPoly().Mul(&A[i].vec[0], &z.vec[0])
			for j = 1; j < L; j++ {
				tmp = *NewPoly().Mul(&A[i].vec[j], &z.vec[j])
				az.vec[i] = *NewPoly().Add(&az.vec[i], &tmp)
			}
		}
		for j = 0; j < K; j++ {
			cti.vec[j] = *NewPoly().Mul(&tUp.vec[j], &c)
			for i = 0; i < N; i++ {
				cti.vec[j].coeffs[i] = reduce(-cti.vec[j].coeffs[i])
			}
		}
		for i = 0; i < K; i++ {
			w.vec[i] = *NewPoly().Add(&az.vec[i], &cti.vec[i])
		}
		for i = 0; i < M; i++ {
			hz.vec[i] = *NewPoly().Mul(&H[i].vec[0],&z.vec[0])
			for j = 1; j < L; j++ {
				tmp = *NewPoly().Mul(&H[i].vec[j], &z.vec[j])
				hz.vec[i] = *NewPoly().Add(&hz.vec[i], &tmp)
			}
		}
		for j = 0; j < M; j++ {
			cI.vec[j] = *NewPoly().Mul(&I.vec[j], &c)
			for i = 0; i < N; i++ {
				cI.vec[j].coeffs[i] = reduce(-cI.vec[j].coeffs[i])
			}
		}
		for i = 0; i < M; i++ {
			v.vec[i] = *NewPoly().Add(&hz.vec[i], &cI.vec[i])
		}
		c = hTheta(msg, len(msg), dpkRing, w, v, I)
	}
	//fmt.Println("passed 4")
	for i = 0; i < N; i++ {
		if c.coeffs[i] != c1.coeffs[i] {
			return nil, false
		}
	}

	return keyImg, true
}

func Link(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) bool {
	var (
		i, flagDpk   int
		flag1, flag2 bool
		I1, I2       polyvecm
	)
	flagDpk = 0
	tmpDpk := DerivedPubKey{}
	keyImage1 := &KeyImage{}
	keyImage2 := &KeyImage{}
	tmpDpk = dpkRing1.Dpk[0]
	keyImage1.I = sig1.I
	keyImage2.I = sig2.I

	for i = 1; i < dpkRing1.R; i++ {
		if Equaldpk(tmpDpk, dpkRing1.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return false
	}

	tmpDpk = dpkRing2.Dpk[0]
	for i = 1; i < dpkRing2.R; i++ {
		if Equaldpk(tmpDpk, dpkRing2.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return false
	}

	keyImage1, flag1 = Verify(msg1, dpkRing1, sig1)
	keyImage2, flag2 = Verify(msg2, dpkRing2, sig2)
	if flag1 == false || flag2 == false {
		return false
	}
	I1 = sig1.I
	I2 = sig2.I

	return EqualI(I1, I2)
}
func Link1(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) bool {
	var (
		i, flagDpk   int
		flag1, flag2 bool
		I1, I2       polyvecm
	)
	flagDpk = 0
	tmpDpk := DerivedPubKey{}
	keyImage1 := &KeyImage{}
	keyImage2 := &KeyImage{}
	tmpDpk = dpkRing1.Dpk[0]
	keyImage1.I = sig1.I
	keyImage2.I = sig2.I

	for i = 1; i < dpkRing1.R; i++ {
		if tmpDpk.Equal(&dpkRing1.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return false
	}

	tmpDpk = dpkRing2.Dpk[0]
	for i = 1; i < dpkRing2.R; i++ {
		if tmpDpk.Equal(&dpkRing2.Dpk[i]) {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return false
	}

	keyImage1, flag1 = Verify1(msg1, dpkRing1, sig1)
	keyImage2, flag2 = Verify1(msg2, dpkRing2, sig2)
	if flag1 == false || flag2 == false {
		return false
	}
	I1 = sig1.I
	I2 = sig2.I

	return I1.Equal(&I2)
}

func (mpk *MasterPubKey)Serialize() ([]byte) {
	b := make([]byte, MpkByteLen)
	var i int
	for i = 0; i < PKKEMByteLen; i++ {
		b[i] = mpk.pkkem.Bytes()[i]
	} //pk_kem string
	sliceMpk := make([]byte, PackTByteLen)
	sliceMpk = packPolyveckQ(mpk.t)
	for i = 0; i < PackTByteLen; i++ {
		b[PKKEMByteLen+i] = sliceMpk[i]
	}
	return b
}

func DeseralizeMasterPubKey(b []byte) (mpk *MasterPubKey, err error) {
	if len(b) == 0 {
		return nil, errors.New("mpk byte string is empty")
	}
	if len(b) != MpkByteLen {
		return nil, errors.New("invalid mpk byte length")
	}
	mpk = &MasterPubKey{}
	mpk.pkkem,err=pkem.PublicKeyFromBytes(b[:PKKEMByteLen])
	if err != nil{
		return nil, errors.New("pubkey from byte failed")
	}
	mpk.t=unpackPolyveckQ(b[PKKEMByteLen:])
	return mpk, nil
}

func (dpk *DerivedPubKey) Serialize() []byte {
	b := make([]byte, DpkByteLen)
	for i := 0; i < CipherByteLen; i++ { //cipher string
		b[i] = dpk.c[i]
	}
	sliceDpk := make([]byte, PackTByteLen)
	sliceDpk = packPolyveckQ(dpk.t)
	for i := 0; i < PackTByteLen; i++ {
		b[CipherByteLen+i] = sliceDpk[i]
	}
	return b
}
func DeseralizeDerivedPubKey(b []byte) (dpk *DerivedPubKey, err error) {
	if len(b) == 0 {
		return nil, errors.New("dpk byte string is empty")
	}
	dpk = &DerivedPubKey{}
	dpk.c=make([]byte,CipherByteLen)
	for i := 0; i < CipherByteLen; i++ {
		dpk.c[i] = b[i]
	}
	dpk.t = unpackPolyveckQ(b[CipherByteLen:])
	return dpk, nil
}
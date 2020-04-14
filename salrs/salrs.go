package salrs

//#cgo CFLAGS: -I./kyber_all
//#cgo LDFLAGS: -L${SRCDIR}/kyber_all -lkyber_all
//
//#include "kyber_all.h"
import "C"
import (
	"errors"
	"golang.org/x/crypto/sha3"
	"unsafe"
)

/*
This file contains all the public constant, type, and functions that are available to oue of the package.
*/

//	public const def	begi
//  to do
const PassPhaseByteLen = 32

//const MasterSeedByteLen = 32
//const MpkByteLen = 1000
//const DpkByteLen = 2000

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

	MpkByteLen    = 4544
	PKKEMByteLen  = 1088
	MskByteLen    = 2880
	SKKEMByteLen  = 2400
	DpkByteLen    = 4608
	CipherByteLen = 1152
	//MsskByteLen       = 480
	//MsvkByteLen       = KyberK * KyberPolyBytes
	MasterSeedByteLen = PackSByteLen + KyberSymBytes + KyberSymBytes

	cstr     = "today_is_a_good_day_today_is_a_good_day_today_is_a_good_day"
	CSTRSIZE = len(cstr)

	KyberK = 3 /* Change this for different security strengths */

	/* Don't change parameters below this line */
	KyberSymBytes = 32 /* size in bytes of shared key, hashes, and seeds */
	//KyberPolyBytes              = 416
	KyberPolyCompressedBytes = 96
	//KyberPolyvecBytes           = KyberK * KyberPolyBytes
	KyberPolyvecCompressedBytes = KyberK * 352
	//KyberIndcpaMsgBytes         = KyberSymBytes
	//KyberIndcpaPublickeyBytes   = KyberPolyvecCompressedBytes + KyberSymBytes
	//KyberIndcpaSecretkeyBytes   = KyberPolyvecBytes
	KyberIndcpaBytes = KyberPolyvecCompressedBytes + KyberPolyCompressedBytes
	//KyberPublickeyBytes         = KyberIndcpaPublickeyBytes
	//KyberSecretkeyBytes         = KyberIndcpaSecretkeyBytes + KyberIndcpaPublickeyBytes + 2*KyberSymBytes /* 32 bytes of additional space to save H(pk) */
	KyberCiphertextBytes = KyberIndcpaBytes
)

//	public const def	end=1000

//	public type def		begin
type MasterPubKey struct {
	pkkem [PKKEMByteLen]byte
	t     polyveck
}

type MasterSecretViewKey struct {
	skkem [SKKEMByteLen]byte
}

type MasterSecretSignKey struct {
	S polyvecl
}

type DerivedPubKey struct {
	c [CipherByteLen]byte
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
	//	to do
}

func GenerateMasterSeed() (masterSeed []byte, err error) {
	var s polyvecl
	var i int
	var buf [PackSByteLen]byte

	mseed := make([]byte, MasterSeedByteLen)
	mseed = randombytes(MasterSeedByteLen)
	c := sha3.NewShake256()
	c.Write(mseed)
	c.Read(mseed)

	s = generateLEta()
	buf = packPolyveclEta(s)
	for i = 0; i < PackSByteLen; i++ {
		mseed[KyberSymBytes*2+i] = buf[i]
	}
	return mseed, nil
}

func GenerateMasterSeedFromPassPhase(passPhase []byte) (masterSeed []byte, err error) {
	if len(passPhase) == PassPhaseByteLen {
		return nil, errors.New("passphase format is incorrect")
	}
	var s polyvecl
	var i int
	var buf [PackSByteLen]byte

	mseed := make([]byte, MasterSeedByteLen)
	c := sha3.NewShake256()
	c.Write(passPhase)
	c.Read(mseed)

	s = generateLEtaforPassPhase(mseed)
	buf = packPolyveclEta(s)
	for i = 0; i < PackSByteLen; i++ {
		mseed[KyberSymBytes*2+i] = buf[i]
	}
	return mseed, nil
}

//to do (rely on kyber)
func GenerateMasterKey(masterSeed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	if len(masterSeed) == 0 {
		return nil, nil, nil, errors.New("master seed is empty")
	}
	masterPubKey := &MasterPubKey{}
	masterSecretViewKey := &MasterSecretViewKey{}
	masterSecretSignKey := &MasterSecretSignKey{}
	//to do
	var (
		i, j          int
		A             [K]polyvecl
		t             polyveck
		s             polyvecl
		tmp           poly
		a             [C.KYBER_K]C.polyvec_kyber
		e, pkpv, skpv C.polyvec_kyber
		pk            [PKKEMByteLen]byte
		nonce         = '0'
		stmp          [PackSByteLen]byte
	)

	publicseed := masterSeed[0:KyberSymBytes]
	noiseseed := masterSeed[KyberSymBytes : KyberSymBytes+KyberSymBytes]
	pseedChar := (*C.uchar)(unsafe.Pointer(&publicseed[0]))
	nseedChar := (*C.uchar)(unsafe.Pointer(&noiseseed[0]))
	noncechar := C.uchar(nonce)
	i = 0
	non := C.int(i)
	C.gen_matrix_kyber(&a[0], pseedChar, non)

	for i = 0; i < C.KYBER_K; i++ {
		C.poly_getnoise_kyber(&skpv.vec[i], nseedChar, noncechar)
		noncechar++
	}

	C.polyvec_ntt_kyber(&skpv)

	for i = 0; i < C.KYBER_K; i++ {
		C.poly_getnoise_kyber(&e.vec[i], nseedChar, noncechar)
		noncechar++
	}

	// matrix-vector multiplication
	for i = 0; i < C.KYBER_K; i++ {
		C.polyvec_pointwise_acc_kyber(&pkpv.vec[i], &skpv, &a[i])
	}

	C.polyvec_invntt_kyber(&pkpv)
	C.polyvec_add_kyber(&pkpv, &pkpv, &e)

	skkemChar := (*C.uchar)(unsafe.Pointer(&masterSecretViewKey.skkem[0]))
	C.pack_sk_kyber(skkemChar, &skpv)
	pkChar := (*C.uchar)(unsafe.Pointer(&pk[0]))
	C.pack_pk_kyber(pkChar, &pkpv, pseedChar)
	for i = 0; i < C.KYBER_INDCPA_PUBLICKEYBYTES; i++ {
		masterSecretViewKey.skkem[i+C.KYBER_INDCPA_SECRETKEYBYTES] = pk[i]
	}
	msvkSercetTwoSymChar := (*C.uchar)(unsafe.Pointer(&masterSecretViewKey.skkem[C.KYBER_SECRETKEYBYTES-2*C.KYBER_SYMBYTES]))
	C.sha3_256_kyber(msvkSercetTwoSymChar, pkChar, C.KYBER_PUBLICKEYBYTES)
	msvkSercetSymChar := (*C.uchar)(unsafe.Pointer(&masterSecretViewKey.skkem[C.KYBER_SECRETKEYBYTES-C.KYBER_SYMBYTES]))
	C.randombytes_kyber(msvkSercetSymChar, C.KYBER_SYMBYTES)

	for i = 0; i < PackSByteLen; i++ {
		stmp[i] = masterSeed[2*KyberSymBytes+i]
	}
	s = unpackPolyveclEta(stmp)

	A = expandMatA()
	for i = 0; i < K; i++ {
		t.vec[i] = polyMultiplication(A[i].vec[0], s.vec[0])
		for j = 1; j < L; j++ {
			tmp = polyMultiplication(A[i].vec[j], s.vec[j])
			t.vec[i] = polyAddition(t.vec[i], tmp)
		}
	}
	masterPubKey.t = t
	masterPubKey.pkkem = pk
	masterSecretSignKey.S = s

	return masterPubKey, masterSecretViewKey, masterSecretSignKey, nil
}

func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, errors.New("mpk is nil")
	}
	derivedPubKey := &DerivedPubKey{}

	var (
		i, j       int
		pk         [PKKEMByteLen]byte
		t, t2, tUp polyveck
		A          [K]polyvecl
		ct         [KyberCiphertextBytes]byte
		s2         polyvecl
		tmp        poly
	)

	//to do
	//non := C.int(i)
	pk = mpk.pkkem
	ss := make([]byte, 32)
	ctChar := (*C.uchar)(unsafe.Pointer(&ct[0]))
	ssChar := (*C.uchar)(unsafe.Pointer(&ss[0]))
	pkChar := (*C.uchar)(unsafe.Pointer(&pk[0]))
	//non = 0
	C.crypto_kem_enc_kyber(ctChar, ssChar, pkChar)

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

func CheckDerivedPubKeyOwner(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) bool {
	var (
		i, j       int
		ct         [KyberCiphertextBytes]byte
		tUp, t, t2 polyveck
		s2         polyvecl
		A          [K]polyvecl
		tmp        poly
	)

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

	ss := make([]byte, 32)
	ctChar := (*C.uchar)(unsafe.Pointer(&ct[0]))
	ssChar := (*C.uchar)(unsafe.Pointer(&ss[0]))
	msvkChar := (*C.uchar)(unsafe.Pointer(&msvk.skkem[0]))
	//non := C.int(i)
	//non = 0
	C.crypto_kem_dec_kyber(ssChar, ctChar, msvkChar)

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

// note the message type
func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	sigma := &Signature{}
	var (
		i, iMain, j, rejection, r, i2 int
		ct                            [KyberCiphertextBytes]byte
		A                             [K]polyvecl
		H                             [M]polyvecl
		s, si, sUp, z, y, cs          polyvecl
		c, c1, tmp, tmp2              poly
		tUp, w, as, az, cti           polyveck
		I, v, hz, cI                  polyvecm
		flag2, flagDpk, ii            = -1, 0, 0
		tmpDpk                        DerivedPubKey
		bl                            = true
	)

	r = dpkRing.R
	zz := make([]polyvecl, r)
	tmpDpk = dpkRing.Dpk[0]
	for i = 1; i < dpkRing.R; i++ {
		if tmpDpk == dpkRing.Dpk[i] {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return nil, errors.New("ring check failed")
	}

	for i = 0; i < dpkRing.R; i++ {
		if dpk == &dpkRing.Dpk[i] {
			ii = i
			flag2 = 0
			ct = dpk.c
			tUp = dpk.t
		}
	}
	if flag2 == -1 {
		return nil, errors.New("you have no access to do the sign as the dpk is not in the ring")
	}

	H = hm(tUp)
	s = mssk.S
	ss := make([]byte, 32)
	ctChar := (*C.uchar)(unsafe.Pointer(&ct[0]))
	ssChar := (*C.uchar)(unsafe.Pointer(&ss[0]))
	msvkChar := (*C.uchar)(unsafe.Pointer(&msvk.skkem[0]))
	C.crypto_kem_dec_kyber(ssChar, ctChar, msvkChar)

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
		ct = dpk.c
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
		if tmpDpk == dpkRing.Dpk[i] {
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
		if tmpDpk == dpkRing1.Dpk[i] {
			flagDpk = 1
			break
		}
	}
	if flagDpk == 1 {
		return false
	}

	tmpDpk = dpkRing2.Dpk[0]
	for i = 1; i < dpkRing2.R; i++ {
		if tmpDpk == dpkRing2.Dpk[i] {
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

func (mpk *MasterPubKey) Serialize() []byte {
	b := make([]byte, MpkByteLen)
	var i int
	for i = 0; i < PKKEMByteLen; i++ {
		b[i] = mpk.pkkem[i]
	} //pk_kem string
	var sliceMpk [PackTByteLen]byte
	sliceMpk = packPolyveckQ(mpk.t)
	for i = 0; i < PackTByteLen; i++ {
		b[PKKEMByteLen+i] = sliceMpk[i]
	}
	return b
}

func DeseralizeMasterPubKey(mpkByteStr []byte) (mpk *MasterPubKey, err error) {
	if len(mpkByteStr) == 0 {
		return nil, errors.New("mpk byte string is empty")
	}
	if len(mpkByteStr) != MpkByteLen {
		return nil, errors.New("invalid mpk byte length")
	}
	masterPubKey := &MasterPubKey{}
	//	to do
	var i int
	for i = 0; i < PKKEMByteLen; i++ {
		masterPubKey.pkkem[i] = mpkByteStr[i]
	}
	var sliceMpk [PackTByteLen]byte
	for i = 0; i < PackTByteLen; i++ {
		sliceMpk[i] = mpkByteStr[PKKEMByteLen+i]
	}
	masterPubKey.t = unpackPolyveckQ(sliceMpk)
	return masterPubKey, nil
}

func (dpk *DerivedPubKey) Serialize() []byte {
	b := make([]byte, DpkByteLen)
	var i int
	for i = 0; i < CipherByteLen; i++ { //cipher string
		b[i] = dpk.c[i]
	}
	var sliceDpk [PackTByteLen]byte
	sliceDpk = packPolyveckQ(dpk.t)
	for i = 0; i < PackTByteLen; i++ {
		b[CipherByteLen+i] = sliceDpk[i]
	}
	return b
}

func DeseralizeDerivedPubKey(dpkByteStr []byte) (dpk *DerivedPubKey, err error) {
	if len(dpkByteStr) == 0 {
		return nil, errors.New("dpk byte string is empty")
	}
	derivedPubKey := &DerivedPubKey{}
	var i int
	for i = 0; i < CipherByteLen; i++ {
		derivedPubKey.c[i] = dpkByteStr[i]
	}
	//dpk += SIZE_CIPHER
	var sliceDpk [PackTByteLen]byte
	for i = 0; i < PackTByteLen; i++ {
		sliceDpk[i] = dpkByteStr[CipherByteLen+i]
	}
	derivedPubKey.t = unpackPolyveckQ(sliceDpk)
	return derivedPubKey, nil
}

//	public fun	end

//	private field (optional)	begin

//	private field (optional)	end

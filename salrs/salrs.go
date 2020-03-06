package salrs

import "errors"

/*
This file contains all the public constant, type, and functions that are available to oue of the package.
*/

//	public const def	begi
//  to do
const PassPhaseByteLen = 32
const MasterSeedByteLen = 32
const MpkByteLen = 1000
const DpkByteLen = 2000

//	public const def	end=1000

//	public type def		begin
type MasterPubKey struct {
}

type MasterSecretViewKey struct {
}

type MasterSecretSignKey struct {
}

type DerivedPubKey struct {
}

type DpkRing struct {
}

type Signature struct {
}

type KeyImage struct {
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
	mseed := make([]byte, MasterSeedByteLen)
	// to do
	for i := range mseed {
		mseed[i] = 0
	}
	return mseed, nil
}

func GenerateMasterSeedFromPassPhase(passPhase []byte) (masterSeed []byte, err error) {
	if len(passPhase) == PassPhaseByteLen {
		return nil, errors.New("Passphase format is incorrect")
	}

	mseed := make([]byte, 0, MasterSeedByteLen)
	// to do
	return mseed, nil
}

func GenerateMasterKey(masterSeed []byte) (mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey, err error) {
	if len(masterSeed) == 0 {
		return nil, nil, nil, errors.New("master seed is empty")
	}
	masterPubKey := &MasterPubKey{}
	masterSecretViewKey := &MasterSecretViewKey{}
	masterSecretSignKey := &MasterSecretSignKey{}
	// to do

	return masterPubKey, masterSecretViewKey, masterSecretSignKey, nil
}

func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, errors.New("mpk is nil")
	}
	derivedPubKey := &DerivedPubKey{}
	// to do

	return derivedPubKey, nil
}

func CheckDerivedPubKeyOwner(dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey) bool {
	// to do
	return true
}

// note the message type
func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	//	to do
	sigma := &Signature{}
	return sigma, nil
}

// note the message type
// only say true or false, does not tell why and what happen, thus there is nor error information
func Verify(msg []byte, dpkRing *DpkRing, sig *Signature) (keyImage *KeyImage, valid bool) {
	// to do
	keyImg := &KeyImage{}
	return keyImg, true
}

func Link(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) bool {
	// to do
	return false
}

func (mpk *MasterPubKey) Serialize() []byte {
	b := make([]byte, MpkByteLen)

	// to do
	for i := range b {
		b[i] = 0
	}
	return b
}

func DeseralizeMasterPubKey(mpkByteStr []byte) (mpk *MasterPubKey, err error) {
	if len(mpkByteStr) == 0 {
		return nil, errors.New("mpk byte string is empty")
	}

	masterPubKey := &MasterPubKey{}
	//	to do

	return masterPubKey, nil

}

func (dpk *DerivedPubKey) Serialize() []byte {
	b := make([]byte, DpkByteLen)

	// to do
	for i := range b {
		b[i] = 1
	}

	return b
}

func DeseralizeDerivedPubKey(dpkByteStr []byte) (dpk *DerivedPubKey, err error) {
	if len(dpkByteStr) == 0 {
		return nil, errors.New("dpk byte string is empty")
	}

	derivedPubKey := &DerivedPubKey{}
	//	to do

	return derivedPubKey, nil
}

//	public fun	end

//	private field (optional)	begin

//	private field (optional)	end

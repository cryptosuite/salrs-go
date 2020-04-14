package main

import (
	"fmt"
	"github.com/cryptosuite/salrs-go/salrs"
)

const (
	r = 10 //dpk ring scale
)

func main() {
	var err error
	var flag bool
	var i int
	mpk := &salrs.MasterPubKey{}
	msvk := &salrs.MasterSecretViewKey{}
	mssk := &salrs.MasterSecretSignKey{}
	dpk1 := &salrs.DerivedPubKey{}
	dpktmp := &salrs.DerivedPubKey{}
	dpkring := &salrs.DpkRing{}
	sig1 := &salrs.Signature{}
	sig2 := &salrs.Signature{}
	keyimage1 := &salrs.KeyImage{}
	keyimage2 := &salrs.KeyImage{}
	mseed := make([]byte, salrs.MasterSeedByteLen)
	msg1 := []byte{'t', 'o', 'd', 'a', 'y'}
	msg2 := []byte{'t', 'o', 'd', 'a', 'x', 'y'}
	mpkbytestr := make([]byte, salrs.MpkByteLen)
	dpkbytestr := make([]byte, salrs.DpkByteLen)
	dpkring.R = r

	//setup
	salrs.Setup()

	//choose generating master seed from passphase or generating seed of master key to generate a seed for master key
	//both codes are tested and provided below

	//generate master seed from passphase
	mseed, err = salrs.GenerateMasterSeedFromPassPhase(msg1)
	if err != nil {
		fmt.Println(err)
	}

	/*
		//generate seed of master key
		mseed, err = salrs.GenerateMasterSeed()
		if err != nil {
			fmt.Println(err)
		}
	*/

	//genereta master key
	mpk, msvk, mssk, err = salrs.GenerateMasterKey(mseed)
	if err != nil {
		fmt.Println(err)
	}

	//test of the Serialize & Deseralize of master key
	mpkbytestr = mpk.Serialize()
	mpk, err = salrs.DeseralizeMasterPubKey(mpkbytestr)
	if err != nil {
		fmt.Println(err)
	}

	//generate derived public key
	dpk1, err = salrs.GenerateDerivedPubKey(mpk)
	if err != nil {
		fmt.Println(err)
	}

	//test of the Serialize & Deseralize of derived public key
	dpkbytestr = dpk1.Serialize()
	dpk1, err = salrs.DeseralizeDerivedPubKey(dpkbytestr)
	if err != nil {
		fmt.Println(err)
	}

	//generate a dpkring for test
	for i = 0; i < r; i++ {
		dpktmp, err = salrs.GenerateDerivedPubKey(mpk)
		if err != nil {
			fmt.Println(err)
		}
		dpkring.Dpk = append(dpkring.Dpk, *dpktmp)
	}
	if err != nil {
		fmt.Println(err)
	}
	dpk1 = &dpkring.Dpk[0]

	//check the owner of a dervied public key
	flag = salrs.CheckDerivedPubKeyOwner(dpk1, mpk, msvk)
	fmt.Println(flag)

	//signature
	sig1, err = salrs.Sign(msg1, dpkring, dpk1, mpk, msvk, mssk)
	if err != nil {
		fmt.Println(err)
	}
	sig2, err = salrs.Sign(msg2, dpkring, dpk1, mpk, msvk, mssk)
	if err != nil {
		fmt.Println(err)
	}

	//verify signature
	keyimage1, flag = salrs.Verify(msg1, dpkring, sig1)
	fmt.Println(flag)
	keyimage2, flag = salrs.Verify(msg2, dpkring, sig2)
	fmt.Println(flag)

	//link
	flag = salrs.Link(msg1, dpkring, sig1, msg2, dpkring, sig2)
	fmt.Println(flag)

	flag = salrs.EqualI(keyimage1.I, keyimage2.I)
	fmt.Println(flag)
}

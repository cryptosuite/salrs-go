package main

import (
	"fmt"
	//"github.com/cryptosuite/salrs-go/salrs"
	"github.com/kbb-98/salrs-go-1/salrs"
	"time"
)

const (
	r     = 3  //dpk ring scale
	round = 3.0 //round of test
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
	msg1 := []byte{'t', 'o', 'd', 'a', 'y'}
	msg2 := []byte{'t', 'o', 'd', 'a', 'x', 'y'}
	mpkbytestr := make([]byte, salrs.MpkByteLen * 2)
	dpkbytestr := make([]byte, salrs.DpkByteLen * 2)
	dpkring.R = r
	mseed := []byte{'a', 'b', 'c'}

	//setup
	start := float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		salrs.Setup()
	}
	end := float64(time.Now().UnixNano())
	fmt.Printf("Setup time consumed:%vs\n", (end-start)/1000000000/round)
	fmt.Printf("Setup passed\n\n")

	//choose generating master seed from passphase or generating seed of master key to generate a seed for master key
	//both codes are tested and provided below

	/*
		//generate master seed from passphase
		start = float64(time.Now().UnixNano())
		for i = 0; i < round; i++ {
			mseed, err = salrs.GenerateMasterSeedFromPassPhase(msg1)
		}
		end = float64(time.Now().UnixNano())
		fmt.Printf("Generate Master Seed From PassPhase time consumed:%vs\n", (end-start)/1000000000/round)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("Generate Master Seed From PassPhase passed\n\n")
		}

		//generate seed of master key
		start = float64(time.Now().UnixNano())
		for i = 0; i < round; i++ {
			mseed, err = salrs.GenerateMasterSeed()
		}
		end = float64(time.Now().UnixNano())
		fmt.Printf("Generate Master Seed time consumed:%vs\n", (end-start)/1000000000/round)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("Generate Master Seed passed\n\n")
		}
	*/

	//genereta master key
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		mpk, msvk, mssk, mseed, err = salrs.GenerateMasterKey(mseed)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Generate Master Key time consumed:%vs\n", (end-start)/1000000000/round)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Generate Master Key passed\n\n")
	}

	//test of the Serialize & Deseralize of master key
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		mpkbytestr = mpk.Serialize()
		mpk, err = salrs.DeseralizeMasterPubKey(mpkbytestr)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Serialize and Deseralize of master public key time consumed:%vs\n", (end-start)/1000000000/round)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Serialize and Deseralize of master public key passed\n\n")
	}


	//generate derived public key
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		dpk1, err = salrs.GenerateDerivedPubKey(mpk)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Generate Derived Public Key time consumed:%vs\n", (end-start)/1000000000/round)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Generate Derived Public Key passed\n\n")
	}

	//test of the Serialize & Deseralize of derived public key

	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		dpkbytestr = dpk1.Serialize()
		dpk1, err = salrs.DeseralizeDerivedPubKey(dpkbytestr)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Serialize and Deseralize of derived public key time consumed:%vs\n", (end-start)/1000000000/round)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Serialize and Deseralize of derived public key passed\n\n")
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
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		flag = salrs.CheckDerivedPubKeyOwner(dpk1, mpk, msvk)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Check Derived Public Key Owner time consumed:%vs\n", (end-start)/1000000000/round)
	if flag == true {
		fmt.Printf("Check Derived Public Key Owner passed\n\n")
	} else {
		fmt.Printf("Check Derived Public Key Owner failed\n\n")
	}

	//signature
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		sig1, err = salrs.Sign(msg1, dpkring, dpk1, mpk, msvk, mssk)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Signature time consumed(ring size = %v):%vs\n", r, (end-start)/1000000000/round)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Signature passed\n\n")
	}
	sig2, err = salrs.Sign(msg2, dpkring, dpk1, mpk, msvk, mssk)
	if err != nil {
		fmt.Println(err)
	}

	//verify signature
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		keyimage1, flag = salrs.Verify(msg1, dpkring, sig1)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("verify time consumed(ring size = %v):%vs\n", r, (end-start)/1000000000/round)
	if flag == true {
		fmt.Printf("Verify passed\n\n")
	} else {
		fmt.Printf("Verify failed\n\n")
	}
	keyimage2, flag = salrs.Verify(msg2, dpkring, sig2)

	//link
	start = float64(time.Now().UnixNano())
	for i = 0; i < round; i++ {
		flag = salrs.Link(msg1, dpkring, sig1, msg2, dpkring, sig2)
	}
	end = float64(time.Now().UnixNano())
	fmt.Printf("Link time consumed(ring size = %v):%vs\n", r, (end-start)/1000000000/round)
	if flag == true {
		fmt.Printf("Link passed\n\n")
	} else {
		fmt.Printf("Link failed\n\n")
	}

	flag = salrs.EqualI(keyimage1.I, keyimage2.I)
}
package salrs

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

func TestPoly_Mul2(t *testing.T) {
	seed, err := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	if err != nil {
		t.Errorf("err= %v", err)
	}
	p1 := NewPoly()
	p2 := NewPoly()
	p3 := NewPoly()
	pos := 0
	seed, pos, _ = generatePolyQFromSeed(seed, pos, p1)
	seed, pos, _ = generatePolyQFromSeed(seed, pos, p2)
	seed, pos, _ = generatePolyQFromSeed(seed, pos, p3)
	tmp := NewPoly().Mul(p2, p3)
	want := NewPoly().Add(p1, tmp)
	get := p1.Add(p1, p2.Mul(p2, p3)) // p2 will change after the line
	if !want.Equal(get) {
		t.Errorf("error in successive using")
	}
}
func TestGenerateMasterKey(t *testing.T) {
	// this testing is for recovery from the seed
	seed, err := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	if err != nil {
		t.Errorf("err= %v", err)
	}
	mpk, _, _, _, err := GenerateMasterKey1(seed)
	if err != nil {
		t.Errorf("err=%v", err)
	}
	mpk1, _, _, _, err := GenerateMasterKey1(seed)
	if err != nil {
		t.Errorf("err=%v", err)
	}
	if !mpk.Equal(mpk1) {
		t.Errorf("generate master public key twice from the same seed is different")
	}
}
func TestDeseralizeMasterPubKey(t *testing.T) {
	seed, err := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	mpk, _, _, _, err := GenerateMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	bytes := mpk.Serialize()
	cmpk, err := DeseralizeMasterPubKey(bytes)
	if err != nil {
		t.Errorf("the deserialize of master public key have some error")
	}
	if !mpk.Equal(cmpk) {
		t.Errorf("the serialize and deserialize of master public key is not matched")
	}

}
func TestDeseralizeDerivedPubKey(t *testing.T) {
	seed, _ := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	mpk, _, _, _, err := GenerateMasterKey1(seed)
	if err != nil {
		log.Fatal(err)
	}
	dpk, err := GenerateDerivedPubKey(mpk)
	bytes := dpk.Serialize()
	cdpk, err := DeseralizeDerivedPubKey(bytes)
	if err != nil {
		t.Errorf("the deserialize of derived public key have some error:%v", err)
	}
	if !dpk.Equal(cdpk) {
		t.Errorf("the serialize and deserialize of derived public key is not matched")
	}
}
func TestDeseralizeMasterSecretSignKey(t *testing.T) {
	seed, _ := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	_, _, mssk, _, err := GenerateMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	bytes := mssk.Serialize()
	cmssk, err := DeseralizeMasterSecretSignKey(bytes)
	if err != nil {
		t.Errorf("the deserialize of master secret sign key have some error")
	}
	if !mssk.Equal(cmssk) {
		t.Errorf("the serialize and deserialize of master secret sign key is not matched")
	}
}
func TestDeseralizeMasterSecretViewKey(t *testing.T) {
	seed, _ := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	_, msvk, _, _, err := GenerateMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	bytes := msvk.Serialize()
	cmsvk, err := DeseralizeMasterSecretViewKey(bytes)
	if err != nil {
		t.Errorf("the deserialize of master secret view key have some error")
	}
	if !msvk.Equal(cmsvk) {
		t.Errorf("the serialize and deserialize of master secret view key is not matched")
	}
}
func TestDeserializeSignature(t *testing.T) {
	seed1, _ := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	seed2, _ := hex.DecodeString("efa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	mpk1, msvk1, mssk1, _, err := GenerateMasterKey1(seed1)
	if err != nil {
		log.Fatal(err)
	}
	dpk1, err := GenerateDerivedPubKey1(mpk1)
	if err != nil {
		log.Fatal(err)
	}
	mpk2, _, _, _, err := GenerateMasterKey1(seed2)
	if err != nil {
		log.Fatal(err)
	}
	dpk2, err := GenerateDerivedPubKey1(mpk2)
	if err != nil {
		log.Fatal(err)
	}
	Ring := new(DpkRing)
	Ring.R = 2
	Ring.Dpk = make([]DerivedPubKey, Ring.R)
	Ring.Dpk[0] = *dpk1
	Ring.Dpk[1] = *dpk2
	sig, err := Sign1([]byte("this is a message for testing"), Ring, dpk1, mpk1, msvk1, mssk1) //dpk1,msg
	if err != nil {
		t.Errorf("signatur has logic error: %v", err)
	}
	bytes := sig.Serialize()
	csig, err := DeserializeSignature(bytes)
	if err != nil {
		t.Errorf("the deserialize of signaute have some error")
	}
	if !sig.Equal(csig) {
		t.Errorf("the serialize and deserialize of signature is not matched")
	}
}
func TestMainFunction(t *testing.T) {
	seed1, _ := hex.DecodeString("dfa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	seed2, _ := hex.DecodeString("efa0adce08219616f2cf61812b93108793349b2e60235fdee1dc30f4ce07b83a")
	mpk1, msvk1, mssk1, _, err := GenerateMasterKey1(seed1)
	if err != nil {
		log.Fatal(err)
	}
	dpk1, err := GenerateDerivedPubKey1(mpk1)
	if err != nil {
		log.Fatal(err)
	}
	isDerived, err := CheckDerivedPubKeyOwner1(dpk1, mpk1, msvk1)
	if err != nil || !isDerived {
		t.Errorf("CheckDerivedPubKeyOwner1 has some logic error 1")
	}

	mpk2, msvk2, mssk2, _, err := GenerateMasterKey1(seed2)
	if err != nil {
		log.Fatal(err)
	}
	dpk2, err := GenerateDerivedPubKey1(mpk2)
	if err != nil {
		log.Fatal(err)
	}
	dpk3, err := GenerateDerivedPubKey1(mpk2)
	if err != nil {
		log.Fatal(err)
	}

	isDerived, err = CheckDerivedPubKeyOwner1(dpk2, mpk2, msvk2)
	if err != nil || !isDerived {
		t.Errorf("CheckDerivedPubKeyOwner1 has some logic error 3")
	}
	msg := []byte("this is a message for testing")
	msg1 := []byte("this is another message for testing")
	Ring := new(DpkRing)
	Ring.R = 2
	Ring.Dpk = make([]DerivedPubKey, Ring.R)
	Ring.Dpk[0] = *dpk1
	Ring.Dpk[1] = *dpk2
	Ring1 := new(DpkRing)
	Ring1.R = 3
	Ring1.Dpk = make([]DerivedPubKey, Ring1.R)
	Ring1.Dpk[0] = *dpk1
	Ring1.Dpk[1] = *dpk2
	Ring1.Dpk[2] = *dpk3
	sign, err := Sign1(msg, Ring, dpk1, mpk1, msvk1, mssk1) //dpk1,msg
	if err != nil {
		t.Errorf("signatur has logic error: %v", err)
	}
	_, flag, err := Verify1(msg, Ring, sign)
	if err != nil || !flag {
		t.Errorf("verify has logic error:%v", err)
	}
	sign2, err := Sign1(msg, Ring, dpk2, mpk2, msvk2, mssk2) //dpk2,msg
	if err != nil {
		t.Errorf("signatur has logic error: %v", err)
	}
	//the two different derived public key in the same ring make a signature for the same message,
	//it can not linkable.
	flag, err = Link1(msg, Ring, sign, msg, Ring, sign2)
	if err == nil && flag {
		fmt.Println("the link algorithm has some logic error 1")
	}
	sign3, err := Sign1(msg, Ring1, dpk1, mpk1, msvk1, mssk1) //dpk1,msg1
	if err != nil {
		t.Errorf("the signature algorithm has some logic error 2:%v", err)
	}
	//the same derived public key in different ring make a signature for the same message,
	//it must be linkable.
	flag, err = Link1(msg, Ring, sign, msg, Ring1, sign3)
	if err != nil || !flag {
		t.Errorf("the link algorithm has some logic error 2:%v", err)
	}
	sign4, err := Sign1(msg1, Ring1, dpk1, mpk1, msvk1, mssk1) //dpk1,msg1
	if err != nil {
		t.Errorf("the signature algorithm has some logic error 2:%v", err)
	}
	//the same derived public key in different ring make a signature for the different message,
	//it must be linkable
	flag, err = Link1(msg, Ring, sign, msg1, Ring1, sign4)
	if err != nil && !flag {
		t.Errorf("the link algorithm has some logic error 3:%v", err)
	}
}

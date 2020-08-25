package salrs

import (
	bytes2 "bytes"
	"fmt"
	"log"
	"testing"
)

func TestDeseralizeMasterPubKey(t *testing.T) {
	mpk, _, _, _, err := GenerateMasterKey([]byte{97, 98, 99})
	if err != nil {
		log.Fatal(err)
	}
	bytes := mpk.Serialize()
	want := true
	cmpk, err := DeseralizeMasterPubKey(bytes)
	if err != nil {
		fmt.Println(err.Error())
		log.Fatal(err)
	}
	cbytes := cmpk.Serialize()
	if !bytes2.Equal(bytes, cbytes) {
		t.Errorf("MasterPubKey serializa don't match deserialize")
	}
	got := mpk.t.Equal(&cmpk.t)
	if got != want {
		t.Errorf("MasterPubKey serializa don't match deserialize")
	}

}
func TestDeseralizeDerivedPubKey(t *testing.T) {
	mpk, _, _, _, err := GenerateMasterKey([]byte{97, 98, 99})
	if err != nil {
		log.Fatal(err)
	}
	dpk, err := GenerateDerivedPubKey(mpk)
	bytes := dpk.Serialize()
	want := true
	cdpk, err := DeseralizeDerivedPubKey(bytes)
	if err != nil {
		log.Fatal(err)
	}
	got := dpk.t.Equal(&cdpk.t)
	if got != want {
		t.Errorf("DerivedPubKey serializa don't match deserialize")
	}
	cbytes := cdpk.Serialize()
	if !bytes2.Equal(bytes, cbytes) {
		t.Errorf("MasterPubKey serializa don't match deserialize")
	}
	if !bytes2.Equal(dpk.c, cdpk.c) {
		t.Errorf("MasterPubKey serializa don't match deserialize")
	}
}
func TestDeseralizeMasterSecretSignKey(t *testing.T) {
	_, _, mssk, _, err := GenerateMasterKey([]byte{97, 98, 99})
	if err != nil {
		log.Fatal(err)
	}
	bytes := mssk.Serialize()
	want := true
	cmssk, err := DeseralizeMasterSecretSignKey(bytes)
	if err != nil {
		log.Fatal(err)
	}
	got := mssk.S.Equal(&cmssk.S)
	if got != want {
		t.Errorf("DerivedPubKey serializa don't match deserialize")
	}
	cbytes := cmssk.Serialize()
	if !bytes2.Equal(bytes, cbytes) {
		t.Errorf("MasterPubKey serializa don't match deserialize")
	}
}

func TestMFunction(t *testing.T) {
	mpk, msvk, mssk, err := GenerateMasterKey1([]byte{97, 98, 99})
	if err != nil {
		log.Fatal(err)
	}
	dpk1, err := GenerateDerivedPubKey1(mpk)
	if err != nil {
		log.Fatal(err)
	}
	flag := CheckDerivedPubKeyOwner1(dpk1, mpk, msvk)
	if flag != true {
		t.Errorf("CheckDerivedPubKeyOwner1 has some logic error")
	}
	mpk1, msvk1, mssk1, err := GenerateMasterKey1([]byte{97, 98, 99, 100})
	if err != nil {
		log.Fatal(err)
	}
	dpk2, err := GenerateDerivedPubKey1(mpk1)
	if err != nil {
		log.Fatal(err)
	}
	flag = CheckDerivedPubKeyOwner1(dpk2, mpk, msvk)
	if flag != false {
		t.Errorf("CheckDerivedPubKeyOwner1 has some logic error")
	}
	msg := []byte{'a', 'b', 'c', 'd'}
	Ring := new(DpkRing)
	Ring.R = 2
	Ring.Dpk = make([]DerivedPubKey, Ring.R)
	Ring.Dpk[0] = *dpk1
	Ring.Dpk[1] = *dpk2
	sign, err := Sign1(msg, Ring, dpk1, mpk, msvk, mssk)
	if err != nil {
		log.Fatal(err)
	}
	_, flag = Verify1(msg, Ring, sign)
	if !flag {
		t.Error("signature or verify has logic error")
	}
	sign2, err := Sign1(msg, Ring, dpk2, mpk1, msvk1, mssk1)
	if err != nil {
		log.Fatal(err)
	}
	sign3, err := Sign1(msg, Ring, dpk1, mpk, msvk, mssk)
	if err != nil {
		log.Fatal(err)
	}
	//if !bytes2.Equal(sign.Serialize(),sign.pack()){
	//	t.Error("serialize signature work wrongly")
	//}
	//cs,err:=DeserializeSignature(sign.Serialize())
	cs,err:=DeserializeSignature(sign.Serialize())
	if err!=nil{
		t.Error("deserialize signature work wrongly")
	}
	if cs.r!=sign.r {
		t.Error("deserialize signature work wrongly")
	}
	if !cs.I.Equal(&sign.I){
		t.Error("deserialize signature work wrongly")
	}
	for i:=0;i<cs.r;i++{
		if !cs.z[i].Equal(&sign.z[i]){
			t.Error("deserialize signature work wrongly")
		}
	}
	if !cs.c.Equal(&sign.c){
		t.Error("deserialize signature work wrongly")
	}

	if !Link1(msg, Ring, sign, msg, Ring, sign2) {
		fmt.Println("no matter")
	}
	if !Link1(msg, Ring, sign, msg, Ring, sign3) {
		t.Error("Link successful")
	}

}
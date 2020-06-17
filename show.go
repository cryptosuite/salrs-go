package main

import (
	"fmt"
	//"github.com/cryptosuite/salrs-go-1/salrs"
	"github.com/kbb-98/salrs-go-1/salrs"
	"github.com/mattn/go-gtk/glib"
	"github.com/mattn/go-gtk/gtk"
	"math/rand"
	"os"
	"time"
	"unsafe"
)

const (
	round = 10
)

func randombytes(len int) (sd []byte) {
	rand.Seed(time.Now().UnixNano())
	var i int
	tmp := make([]byte, len, len)
	for i = 0; i < len; i++ {
		num := rand.Intn(256)
		tmp[i] = byte(num)
	}
	return tmp
}

func main(){
	var i, tmp, c int
	var r = 3
	var err error
	var flag bool
	var msg1 = []byte{'0'}
	mseed := []byte{'0', '1', '2'}
	mpk := &salrs.MasterPubKey{}
	msvk := &salrs.MasterSecretViewKey{}
	mssk := &salrs.MasterSecretSignKey{}
	dpk1 := &salrs.DerivedPubKey{}
	dpktmp := &salrs.DerivedPubKey{}
	dpkring := &salrs.DpkRing{}
	sig1 := &salrs.Signature{}
	keyimage1 := &salrs.KeyImage{}
	mpkbytestr := make([]byte, salrs.MpkByteLen)
	dpkbytestr := make([]byte, salrs.DpkByteLen)

	gtk.Init(&os.Args)

	window := gtk.NewWindow(gtk.WINDOW_TOPLEVEL)
	window.SetPosition(gtk.WIN_POS_CENTER)
	window.SetTitle("GTK Go")
	window.SetSizeRequest(1100, 650)

	layout := gtk.NewFixed()

	btime := gtk.NewButton()
	btime.SetLabel("time test")
	btime.SetSizeRequest(150, 50)
	stime := gtk.LabelWithMnemonic("please set ring size:(suggest 1 <= ring size <= 10)")
	stime.SetSizeRequest(300, 50)
	stime2 := gtk.LabelWithMnemonic("ring size for test(press enter to confirm):")
	stime2.SetSizeRequest(300, 50)
	entime := gtk.NewEntry()
	entime.SetSizeRequest(200, 50)
	entime.Connect("activate", func(){
		str := entime.GetText()
		len := len(str)
		tmp = 0
		c = 1
		for i = len - 1; i >= 0; i--{
			tmp += int(str[i] - '0') * c
			c *= 10
		}
		r = tmp
		stime.SetText("ring size reset successfully")
		fmt.Printf("\nring has been reset as %d\n\n", r)
	})
	btime.Connect("pressed", timeTest, &r)

	bsetup := gtk.NewButtonWithLabel("setup")
	bsetup.SetSizeRequest(150, 50)
	ssetup := gtk.LabelWithMnemonic(" ")
	ssetup.SetSizeRequest(200, 50)
	bsetup.Connect("pressed", func(){
		salrs.Setup()
		ssetup.SetText("setup successfully")
	})

	/*
	bgenseed := gtk.NewButtonWithLabel("generate master seed")
	bgenseed.SetSizeRequest(150, 50)
	sgenseed := gtk.LabelWithMnemonic(" ")
	sgenseed.SetSizeRequest(200, 50)
	bgenseed.Connect("pressed", func(){
		mseed, err = salrs.GenerateMasterSeed()
		if err != nil{
			fmt.Println(err)
		}else{
			fmt.Println(mseed)
			sgenseed.SetText("generate master seed successfully")
		}
	})
	*/

	bgenmaskey := gtk.NewButtonWithLabel("generate master key")
	bgenmaskey.SetSizeRequest(150, 50)
	sgenmaskeyy  := gtk.LabelWithMnemonic(" ")
	sgenmaskeyy .SetSizeRequest(200, 50)
	sgenmaskey := gtk.LabelWithMnemonic("your master public key:")
	sgenmaskey .SetSizeRequest(200, 50)
	sgenmaskey2 := gtk.LabelWithMnemonic("your key seed:")
	sgenmaskey2 .SetSizeRequest(200, 50)
	enmpk := gtk.NewEntry()
	enmpk.SetSizeRequest(200, 50)
	enmpk.SetText(" ")
	enmpk2 := gtk.NewEntry()
	enmpk2.SetSizeRequest(200, 50)
	enmpk2.SetText(" ")
	bgenmaskey .Connect("pressed", func(){
		str := enmpk2.GetText()
		if len(str) == 0{
			mseed = randombytes(32)
		}else{
			mseed = str2bytes(str)
			mseed, err = salrs.DeseralizeMseed(mseed)
			if err != nil{
				fmt.Println(err)
			}
		}
		fmt.Println(len(str))
		mpk, msvk, mssk, mseed, err = salrs.GenerateMasterKey(mseed)
		if err != nil{
			fmt.Println(err)
		}else{
			fmt.Println(mseed)
			mpkbytestr = mpk.Serialize()
			enmpk.SetText(bytes2str(mpkbytestr))
			enmpk.Show()
			mseed = salrs.SerializeMseed(mseed)
			enmpk2.SetText(bytes2str(mseed))
			enmpk2.Show()
			sgenmaskeyy .SetText("generate master key successfully")
		}
	})

	bgendpkey := gtk.NewButtonWithLabel("generate derived public key")
	bgendpkey.SetSizeRequest(150, 50)
	sgendpkey  := gtk.LabelWithMnemonic(" ")
	sgendpkey .SetSizeRequest(235, 50)
	sgendpkey2  := gtk.LabelWithMnemonic("your derived public key:")
	sgendpkey2 .SetSizeRequest(200, 50)
	endpk := gtk.NewEntry()
	endpk.SetSizeRequest(200, 50)
	endpk.SetText(" ")
	bgendpkey .Connect("pressed", func(){
		dpk1, err = salrs.GenerateDerivedPubKey(mpk)
		if err != nil{
			fmt.Println(err)
		}else{
			fmt.Println(dpk1)
			dpkbytestr = dpk1.Serialize()
			endpk.SetText(bytes2str(dpkbytestr))
			endpk.Show()
			sgendpkey .SetText("generate derived public key successfully")
		}
		dpkring.R = r
		dpkring.Dpk = append(dpkring.Dpk, *dpk1)
		for i = 1; i < r; i++ {
			dpktmp, err = salrs.GenerateDerivedPubKey(mpk)
			if err != nil {
				fmt.Println(err)
			}
			dpkring.Dpk = append(dpkring.Dpk, *dpktmp)
		}
	})

	bsign := gtk.NewButtonWithLabel("sign")
	bsign.SetSizeRequest(150, 50)
	ssign2  := gtk.LabelWithMnemonic("please input the message you want to sign")
	ssign2 .SetSizeRequest(250, 50)
	ssign3  := gtk.LabelWithMnemonic(" ")
	ssign3 .SetSizeRequest(300, 50)
	ssign3 .SetText("your message(press enter to confirm):")
	ensign := gtk.NewEntry()
	ensign.SetSizeRequest(200, 50)
	ensign.Connect("activate", func(){
		str := ensign.GetText()
		msg1 = str2bytes(str)
		ssign2.SetText("message set successfully")
	})
	bsign .Connect("pressed", func(){
		sig1, err = salrs.Sign(msg1, dpkring, dpk1, mpk, msvk, mssk)
		if err != nil{
			fmt.Println(err)
		}else{
			fmt.Println(sig1)
			ssign2 .SetText("sign successfully")
		}
	})

	bverify := gtk.NewButtonWithLabel("verify")
	bverify.SetSizeRequest(150, 50)
	sverify  := gtk.LabelWithMnemonic(" ")
	sverify .SetSizeRequest(200, 50)
	bverify .Connect("pressed", func(){
		keyimage1, flag = salrs.Verify(msg1, dpkring, sig1)
		if err != nil{
			sverify .SetText("verify failed")
		}else{
			fmt.Println(keyimage1)
			sverify .SetText("verify passed")
		}
	})

	bQuit := gtk.NewButton()
	bQuit.SetLabel("quit")
	bQuit.SetSizeRequest(150, 50)
	bQuit.Connect("pressed", quit)

	window.Add(layout)
	layout.Put(btime, 50, 50)
	layout.Put(stime, 250, 50)
	layout.Put(stime2, 550, 50)
	layout.Put(entime, 850,50)
	layout.Put(bsetup, 50, 120)
	layout.Put(ssetup, 250, 120)
	layout.Put(bgenmaskey, 50, 190)
	layout.Put(sgenmaskeyy, 250, 190)
	layout.Put(sgenmaskey, 550, 250)
	layout.Put(sgenmaskey2, 550, 190)
	layout.Put(enmpk, 850, 250)
	layout.Put(enmpk2, 850, 190)
	layout.Put(bgendpkey, 50, 330)
	layout.Put(sgendpkey, 250, 330)
	layout.Put(sgendpkey2, 550, 330)
	layout.Put(endpk, 850, 330)
	layout.Put(bsign, 50, 400)
	layout.Put(ssign2, 250, 400)
	layout.Put(ssign3, 550, 400)
	layout.Put(ensign, 850, 400)
	layout.Put(bverify, 50, 470)
	layout.Put(sverify, 250, 470)
	layout.Put(bQuit, 50, 540)

	window.ShowAll()

	gtk.Main()
}

func str2bytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

func bytes2str(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))

}

func HandleButton(ctx *glib.CallbackContext){
	arg := ctx.Data()
	p, ok := arg.(*int)
	if ok{
		fmt.Println("*p = ", *p)
		*p = 250
	}

	fmt.Println("bi is pressed")
}

func quit(){
	gtk.MainQuit()
}

func timeTest(ctx *glib.CallbackContext) {
		var err error
		var flag bool
		var i int
		var r int
		arg := ctx.Data()
		p, ok := arg.(*int)
		if ok{
			r = *p
		}
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
		mseed := []byte{'0', '1', '2'}
		msg1 := []byte{'t', 'o', 'd', 'a', 'y'}
		msg2 := []byte{'t', 'o', 'd', 'a', 'x', 'y'}
		mpkbytestr := make([]byte, salrs.MpkByteLen)
		dpkbytestr := make([]byte, salrs.DpkByteLen)
		dpkring.R = r

		fmt.Printf("\n\ntime test start\n\n")
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

		//generate master seed from passphase
		/*
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
			fmt.Printf("Serialize and Deseralize of master public key passed\n\n")
		}


		//generate a dpkring for test
		for i = 0; i < r; i++ {
			dpktmp, err = salrs.GenerateDerivedPubKey(mpk)
			if err != nil {
				fmt.Println(err)
			}
			dpkring.Dpk = append(dpkring.Dpk, *dpktmp)
		}
		*dpk1 = dpkring.Dpk[0]

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

		fmt.Println("time test end")
	}


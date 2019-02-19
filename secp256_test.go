package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"testing"
)

const TESTS = 1    //10000 // how many tests
const SigSize = 65 //64+1

func Test_Secp256_00(t *testing.T) {

	var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {
		t.Fatal()
	}

}

//test agreement for highest bit test
func Test_BitTwiddle(t *testing.T) {
	var b byte
	for i := 0; i < 512; i++ {
		var bool1 bool = ((b >> 7) == 1)
		var bool2 bool = ((b & 0x80) == 0x80)
		if bool1 != bool2 {
			t.Fatal()
		}
		b++
	}
}

//tests for Malleability
//highest bit of S must be 0; 32nd byte
func CompactSigTest(sig []byte) {
	var b int = int(sig[32])
	if b < 0 {
		log.Panic()
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		log.Printf("b= %v b2= %v \n", b, b>>7)
		log.Panic()
	}
	if (b & 0x80) == 0x80 {
		log.Printf("b= %v b2= %v \n", b, b&0x80)
		log.Panic()
	}
}

//test pubkey/private generation
func Test_Secp256_01(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	if VerifySeckey(seckey) != 1 {
		t.Fatal()
	}
	if VerifyPubkey(pubkey) != 1 {
		t.Fatal()
	}
}

//returns random pubkey, seckey, hash and signature
func RandX() ([]byte, []byte, []byte, []byte) {
	pubkey, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	return pubkey, seckey, msg, sig
}

func Test_SignatureVerifyPubkey(t *testing.T) {
	log.Println("Test_SignatureVerifyPubkey")
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	if VerifyPubkey(pubkey1) == 0 {
		t.Fail()
	}
	pubkey2 := RecoverPubkey(msg, sig)
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal("Recovered pubkey does not match")
	}
}

func Test_verify_functions(t *testing.T) {
	log.Println("Test_verify_functions")
	pubkey, seckey, hash, sig := RandX()
	if VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if VerifyPubkey(pubkey) == 0 {
		t.Fail()
	}
	if VerifySignature(hash, sig, pubkey) == 0 {
		t.Fail()
	}
	_ = sig
}

func Test_SignatureVerifySecKey(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	if VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if VerifyPubkey(pubkey) == 0 {
		t.Fail()
	}
}

//test size of messages
func Test_Secp256_02s(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	CompactSigTest(sig)
	if sig == nil {
		t.Fatal("Signature nil")
	}
	if len(pubkey) != 33 {
		t.Fail()
	}
	if len(seckey) != 32 {
		t.Fail()
	}
	if len(sig) != 64+1 {
		t.Fail()
	}
	if int(sig[64]) > 4 {
		t.Fail()
	} //should be 0 to 4
}

//test signing message
func Test_Secp256_02(t *testing.T) {
	log.Println("Test_Secp256_02")
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	if sig == nil {
		t.Fatal("Signature nil")
	}

	pubkey2 := RecoverPubkey(msg, sig)
	if pubkey2 == nil {
		t.Fatal("Recovered pubkey invalid")
	}
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal("Recovered pubkey does not match")
	}

	ret := VerifySignature(msg, sig, pubkey1)
	if ret != 1 {
		t.Fatal("Signature invalid")
	}
}

//test pubkey recovery
func Test_Secp256_02a(t *testing.T) {
	log.Println("Test_Secp256_02a")
	pubkey1, seckey1 := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey1)

	if sig == nil {
		t.Fatal("Signature nil")
	}
	ret := VerifySignature(msg, sig, pubkey1)
	if ret != 1 {
		t.Fatal("Signature invalid")
	}

	pubkey2 := RecoverPubkey(msg, sig)
	if len(pubkey1) != len(pubkey2) {
		t.Fatal()
	}
	for i, _ := range pubkey1 {
		if pubkey1[i] != pubkey2[i] {
			t.Fatal()
		}
	}
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal()
	}
}

//test random messages for the same pub/private key
func Test_Secp256_03(t *testing.T) {
	log.Println("Test_Secp256_03")
	_, seckey := GenerateKeyPair()
	for i := 0; i < TESTS; i++ {
		msg := RandByte(32)
		sig := Sign(msg, seckey)
		CompactSigTest(sig)

		sig[len(sig)-1] %= 4
		pubkey2 := RecoverPubkey(msg, sig)
		if pubkey2 == nil {
			t.Fail()
		}
	}
}

//test random messages for different pub/private keys
func Test_Secp256_04(t *testing.T) {
	log.Println("Test_Secp256_04")
	for i := 0; i < TESTS; i++ {
		pubkey1, seckey := GenerateKeyPair()
		msg := RandByte(32)
		sig := Sign(msg, seckey)
		CompactSigTest(sig)

		if sig[len(sig)-1] >= 4 {
			t.Fail()
		}
		pubkey2 := RecoverPubkey(msg, sig)
		if pubkey2 == nil {
			t.Fail()
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fail()
		}
	}
}

//test random signatures against fixed messages; should fail

//crashes:
//	-SIPA look at this

func randSig() []byte {
	sig := RandByte(65)
	sig[32] &= 0x70
	sig[64] %= 4
	return sig
}

func Test_Secp256_06a_alt0(t *testing.T) {
	log.Println("Test_Secp256_06a_alt0")
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)

	if sig == nil {
		t.Fail()
	}
	if len(sig) != 65 {
		t.Fail()
	}
	for i := 0; i < TESTS; i++ {
		sig = randSig()
		pubkey2 := RecoverPubkey(msg, sig)

		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if VerifySignature(msg, sig, pubkey1) == 1 {
			t.Fail()
		}
	}
}

//test random messages against valid signature: should fail

func Test_Secp256_06b(t *testing.T) {
	log.Println("Test_Secp256_06b")
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)

	fail_count := 0
	for i := 0; i < TESTS; i++ {
		msg = RandByte(32)
		pubkey2 := RecoverPubkey(msg, sig)
		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if VerifySignature(msg, sig, pubkey1) == 1 {
			t.Fail()
		}
	}
	if fail_count != 0 {
		fmt.Printf("ERROR: Accepted signature for %v of %v random messages\n", fail_count, TESTS)
	}
}

func Decode(str string) []byte {
	byt, err := hex.DecodeString(str)
	if err != nil {
		log.Panic()
	}
	return byt
}

func Test_ECDH(t *testing.T) {

	pubkey1, seckey1 := GenerateKeyPair()
	pubkey2, seckey2 := GenerateKeyPair()

	puba := ECDH(pubkey1, seckey2)
	pubb := ECDH(pubkey2, seckey1)

	if puba == nil {
		t.Fail()
	}

	if pubb == nil {
		t.Fail()
	}

	if bytes.Equal(puba, pubb) == false {
		t.Fail()
	}

}

func Test_ECDH2(t *testing.T) {

	for i := 0; i < 16*1024; i++ {

		pubkey1, seckey1 := GenerateKeyPair()
		pubkey2, seckey2 := GenerateKeyPair()

		puba := ECDH(pubkey1, seckey2)
		pubb := ECDH(pubkey2, seckey1)

		if puba == nil {
			t.Fail()
		}

		if pubb == nil {
			t.Fail()
		}

		if bytes.Equal(puba, pubb) == false {
			t.Fail()
		}
	}
}

/*
seed  = ee78b2fb5bef47aaab1abf54106b3b022ed3d68fdd24b5cfdd6e639e1c7baa6f
seckey  = 929c5f23a17115199e61b2c4c38fea06f763270a0d1189fbc6a46ddac05081fa
pubkey1 = 028a4d9f32e7bd25befd0afa9e73755f35ae2f7012dfc7c000252f2afba2589af2
pubkey2 = 028a4d9f32e7bd25befd0afa9e73755f35ae2f7012dfc80000252f2afba2589af2
key_wif = L28hjib16NuBT4L1gK4DgzKjjxaCDggeZpXFy93MdZVz9fTZKwiE
btc_addr1 = 14mvZw1wC8nKtycrTHu6NRTfWHuNVCpRgL
btc_addr2 = 1HuwS7qARGMgNB7zao1FPmqiiZ92tsJGpX
deterministic pubkeys do not match
seed  = 0e86692d755fd39a51acf6c935bdf425a6aad03a7914867e3f6db27371c966b4
seckey  = c9d016b26102fb309a73e644f6be308614a1b8f6f46f902c906ffaf0993ee63c
pubkey1 = 03e86d62256dd05c2852c05a6b11d423f278288abeab490000b93d387de45a2f73
pubkey2 = 03e86d62256dd05c2852c05a6b11d423f278288abeab494000b93d387de45a2f73
key_wif = L3z1TTmgddKUm2Em22zKwLXGZ7jfwXLN5GxebpgH5iohaRJSm98D
btc_addr1 = 1CcrzXvK34Cf4jzTko5uhCwbsC6e6K4rHw
btc_addr2 = 1GtBH7dcZnh69Anqe8sHXKSJ9Dk4jXGHyp
*/

func Test_Abnormal_Keys(t *testing.T) {

	for i := 0; i < 32*1024; i++ {

		seed := RandByte(32)

		pubkey1, seckey1 := generateDeterministicKeyPair(seed)

		if seckey1 == nil {
			t.Fail()
		}

		if pubkey1 == nil {
			t.Fail()
		}

		if VerifyPubkey(pubkey1) != 1 {
			seed_hex := hex.EncodeToString(seed)
			seckey_hex := hex.EncodeToString(seckey1)
			log.Printf("seed= %s", seed_hex)
			log.Printf("seckey= %s", seckey_hex)
			t.Error("GenerateKeyPair, generates key that fails validation, run: ", i)
		}
	}
}

//problem seckeys
var _test_seckey []string = []string{
	"08efb79385c9a8b0d1c6f5f6511be0c6f6c2902963d874a3a4bacc18802528d3",
	"78298d9ecdc0640c9ae6883201a53f4518055442642024d23c45858f45d0c3e6",
	"04e04fe65bfa6ded50a12769a3bd83d7351b2dbff08c9bac14662b23a3294b9e",
	"2f5141f1b75747996c5de77c911dae062d16ae48799052c04ead20ccd5afa113",
}

//test known bad keys
func Test_Abnormal_Keys2(t *testing.T) {

	for i := 0; i < len(_test_seckey); i++ {

		seckey1, _ := hex.DecodeString(_test_seckey[i])
		pubkey1 := PubkeyFromSeckey(seckey1)
		if pubkey1 == nil {
			t.Fail()
		}

		if seckey1 == nil {
			t.Fail()
		}

		if pubkey1 == nil {
			t.Fail()
		}

		if VerifyPubkey(pubkey1) != 1 {
			t.Errorf("generates key that fails validation")
		}
	}
}

func _pair_gen(seckey []byte) []byte {
	return nil
}

//ECDH test
func Test_Abnormal_Keys3(t *testing.T) {
	log.Println("Test_Abnormal_Keys3")
	for i := 0; i < len(_test_seckey); i++ {

		seckey1, _ := hex.DecodeString(_test_seckey[i])
		pubkey1 := PubkeyFromSeckey(seckey1)

		seckey2, _ := hex.DecodeString(_test_seckey[rand.Int()%len(_test_seckey)])
		pubkey2 := PubkeyFromSeckey(seckey2)

		if pubkey1 == nil {
			t.Errorf("pubkey1 nil")
		}

		if pubkey2 == nil {
			t.Errorf("pubkey2 nil")
		}
		//pubkey1, seckey1 := GenerateKeyPair()
		//pubkey2, seckey2 := GenerateKeyPair()

		puba := ECDH(pubkey1, seckey2)
		pubb := ECDH(pubkey2, seckey1)

		if puba == nil {
			t.Fail()
		}

		if pubb == nil {
			t.Fail()
		}

		if bytes.Equal(puba, pubb) == false {
			t.Errorf("recovered do not match")
		}
	}

}

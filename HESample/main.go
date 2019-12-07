package main

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"log"
)

type BFVObject struct {
	params       bfv.Parameters
	bfvContext   *bfv.BfvContext
	encoder      *bfv.BatchEncoder
	kgen         *bfv.KeyGenerator
	encryptor    *bfv.Encryptor
	decryptor    *bfv.Decryptor
	sk           *bfv.SecretKey
	pk           *bfv.PublicKey
	encryptorPk  *bfv.Encryptor
	encryptorSk  *bfv.Encryptor
	evaluator    *bfv.Evaluator
}

type BobKeyStore struct {
	username     string
	sk           *bfv.SecretKey
	switchingkey *bfv.SwitchingKey
}

func (b *BFVObject) Init() {
	var err error
	b.params = bfv.DefaultParams[0]
	b.params.T = 67084289
	b.bfvContext, err = bfv.NewBfvContextWithParam(&b.params)
	if err != nil {
		fmt.Println("New BfvContext Error: ", err.Error())
	}

	b.encoder, err = b.bfvContext.NewBatchEncoder()
	if err != nil {
		fmt.Println(err.Error())
	}

	b.kgen = b.bfvContext.NewKeyGenerator()
	b.sk, b.pk = b.kgen.NewKeyPair()

	b.encryptorPk, err = b.bfvContext.NewEncryptorFromPk(b.pk)
	if err != nil {
		log.Fatal(err)
	}

	b.encryptorSk, err = b.bfvContext.NewEncryptorFromSk(b.sk)
	if err != nil {
		log.Fatal(err)
	}

	b.evaluator = b.bfvContext.NewEvaluator()

	fmt.Printf("Parameters : N=%d, T=%d, logQ = %d (%d limbs), sigma = %f \n",
		b.bfvContext.N(), b.bfvContext.T(), b.bfvContext.LogQ(), len(b.params.Qi), b.bfvContext.Sigma())
}
func (b *BFVObject) Encrypt(plaintext string) []byte {

	bytes := []byte(plaintext)
	alice := make([]uint64, b.params.N)
	for i := uint64(0); i < uint64(len(bytes)); i++ {
		alice[i] = uint64(bytes[i])
	}
	//alice := make([]uint64, params.N)
	//for i := uint64(0); i < params.N>>1; i++ {
	//	alice[i] = i
	//}
	alicePlaintext := b.bfvContext.NewPlaintext()
	_ = b.encoder.EncodeUint(alice, alicePlaintext)

	fmt.Println("Encrypting...")

	aliceCiphertext, err := b.encryptorPk.EncryptNew(alicePlaintext)
	if err != nil {
		fmt.Println(err.Error())
	}
	cipherBytes, err := aliceCiphertext.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(cipherBytes)
	return cipherBytes
}

func (b *BFVObject) Decrypt(ciphertext []byte) string {
	aliceCiphertext := b.bfvContext.NewCiphertext(1)
	err := aliceCiphertext.UnMarshalBinary(ciphertext)
	if err != nil {
		fmt.Println("UnMarshal Failed ", err.Error())
	}
	Skbob := b.kgen.NewSecretKey()
	decryptor_Skbob, err := b.bfvContext.NewDecryptor(Skbob)
	if err != nil {
		fmt.Println(err.Error())
	}

	bitDecomp := uint64(0)
	switchingKey := b.kgen.NewSwitchingKey(b.sk, Skbob, bitDecomp)

	if err := b.evaluator.SwitchKeys(aliceCiphertext, switchingKey, aliceCiphertext); err != nil {
		fmt.Println(err.Error())
	}

	aliceWant := b.encoder.DecodeUint(decryptor_Skbob.DecryptNew(aliceCiphertext))
	result := make([]byte, len(aliceWant))
	for i := 0; i < len(aliceWant); i++ {
		result[i] = byte(aliceWant[i])
	}
	fmt.Println("Result: ", result)
	return string(result)
}

//func (b *BFVObject) GenSwitchKey(username string) {
//
//	bobKeyStore := new(BobKeyStore)
//
//	decryptor_Skbob, err := b.bfvContext.NewDecryptor(Skbob)
//	if err != nil {
//		fmt.Println(err.Error())
//	}
//
//	bitDecomp := uint64(0)
//	switchingKey := b.kgen.NewSwitchingKey(b.sk, Skbob, bitDecomp)
//}

func main() {
	bfvobj := new(BFVObject)
	bfvobj.Init()
	ciphertext := bfvobj.Encrypt("hello FHE")
	plainttext := bfvobj.Decrypt(ciphertext)
	fmt.Println(plainttext)
}

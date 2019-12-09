package main

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"log"
)

type BFVObject struct {
	Params       bfv.Parameters
	BfvContext   *bfv.BfvContext
	Encoder      *bfv.BatchEncoder
	Kgen         *bfv.KeyGenerator
	Encryptor    *bfv.Encryptor
	Decryptor    *bfv.Decryptor
	EncryptorPk  *bfv.Encryptor
	EncryptorSk  *bfv.Encryptor
	Evaluator    *bfv.Evaluator
}

type PublishKeyStore struct {
	Sk           *bfv.SecretKey
	Pk           *bfv.PublicKey
}

type SubsrcibeKeyStore struct {
	Sk           *bfv.SecretKey
	Switchingkey *bfv.SwitchingKey
}

func NewBFVObject(paramsNum int) *BFVObject {
	b := &BFVObject{}
	var err error
	b.Params = bfv.DefaultParams[paramsNum]
	b.Params.T = 67084289
	b.BfvContext, err = bfv.NewBfvContextWithParam(&b.Params)
	if err != nil {
		fmt.Println("New BfvContext Error: ", err.Error())
	}

	b.Encoder, err = b.BfvContext.NewBatchEncoder()
	if err != nil {
		fmt.Println(err.Error())
	}
	b.Kgen = b.BfvContext.NewKeyGenerator()
	return b
}

func NewPublishKeyStore(b *BFVObject) *PublishKeyStore {
	pks := &PublishKeyStore{}
	pks.Sk, pks.Pk = b.Kgen.NewKeyPair()
	b.Evaluator = b.BfvContext.NewEvaluator()

	fmt.Printf("Parameters : N=%d, T=%d, logQ = %d (%d limbs), sigma = %f \n",
		b.BfvContext.N(), b.BfvContext.T(), b.BfvContext.LogQ(), len(b.Params.Qi), b.BfvContext.Sigma())
	return pks
}

func NewSubsrcibeKeyStore(b *BFVObject, pks *PublishKeyStore) *SubsrcibeKeyStore {
	sks := &SubsrcibeKeyStore{}
	sks.Sk = b.Kgen.NewSecretKey()

	bitDecomp := uint64(0)
	sks.Switchingkey = b.Kgen.NewSwitchingKey(pks.Sk, sks.Sk, bitDecomp)
	return sks
}

func Encrypt(b *BFVObject, pks *PublishKeyStore, plaintext string) []byte {
	var err error
	bytes := []byte(plaintext)
	alice := make([]uint64, b.Params.N)
	for i := uint64(0); i < uint64(len(bytes)); i++ {
		alice[i] = uint64(bytes[i])
	}

	alicePlaintext := b.BfvContext.NewPlaintext()
	_ = b.Encoder.EncodeUint(alice, alicePlaintext)

	fmt.Println("Encrypting...")

	b.EncryptorPk, err = b.BfvContext.NewEncryptorFromPk(pks.Pk)
	if err != nil {
		log.Fatal(err)
	}

	aliceCiphertext, err := b.EncryptorPk.EncryptNew(alicePlaintext)
	if err != nil {
		fmt.Println(err.Error())
	}
	cipherBytes, err := aliceCiphertext.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	//fmt.Println(cipherBytes)
	return cipherBytes
}

func Decrypt(b *BFVObject, sks *SubsrcibeKeyStore, ciphertext []byte) string {
	aliceCiphertext := b.BfvContext.NewCiphertext(1)
	err := aliceCiphertext.UnMarshalBinary(ciphertext)
	if err != nil {
		fmt.Println("UnMarshal Failed ", err.Error())
	}

	if err := b.Evaluator.SwitchKeys(aliceCiphertext, sks.Switchingkey, aliceCiphertext); err != nil {
		fmt.Println(err.Error())
	}

	decryptor_sks, err := b.BfvContext.NewDecryptor(sks.Sk)
	if err != nil {
		fmt.Println(err.Error())
	}
	aliceWant := b.Encoder.DecodeUint(decryptor_sks.DecryptNew(aliceCiphertext))
	result := make([]byte, len(aliceWant))
	for i := 0; i < len(aliceWant); i++ {
		result[i] = byte(aliceWant[i])
	}
	//fmt.Println("Result: ", result)
	return string(result)
}


package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var bfvobj *BFVObject

type EncryptReq struct {
	PublishKeyFile string `json:"publish_key_file"`
	Plaintext string `json:"plaintext"`
}

type EncryptResp struct {
	Ciphertext string `json:"ciphertext"`
}

type ReEncryptReq struct {
	PublishKeyFile string `json:"publish_key_file"`
	SubscribeKeyFile string `json:"subscribe_key_file"`
	Ciphertext string `json:"ciphertext"`
}

type ReEncryptResp struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptReq struct {
	SubscribeKeyFile string `json:"subscribe_key_file"`
	Ciphertext string `json:"ciphertext"`
}

type DecryptResp struct {
	Plaintext string `json:"plaintext"`
}

type NewPKSReq struct {
	Username string `json:"username"`
}

type NewSKSReq struct {
	Username string `json:"username"`
}

type CommonResp struct {
	Code string `json:"code"`
}

// 加密函数 发布者使用自己的公钥加密
func encryptFunc(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[ENCRYPT]: ", body_str)

	er := &EncryptReq{}
	pks := &PublishKeyStore{}
	if err := json.Unmarshal(body, &er); err == nil {
		// read publisher's PK from file
		bytes_pub_pk, err := base64.StdEncoding.DecodeString(ReadFromFile(er.PublishKeyFile))
		pk := bfvobj.Kgen.NewPublicKeyEmpty()
		err = pk.UnMarshalBinary(bytes_pub_pk)
		if err != nil {
			fmt.Println("[ENCRYPT]: ", err.Error())
		}
		pks.Pk = pk
		// encrypt by PK
		ciphertext := Encrypt(bfvobj, pks, er.Plaintext)
		resp := &EncryptResp{Ciphertext:base64.StdEncoding.EncodeToString(ciphertext)}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	} else {
		resp := &CommonResp{"-1"}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	}
}

// 加密函数 发布者使用自己的公钥加密
func reencryptFunc(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[REENCRYPT]: ", body_str)

	er := &ReEncryptReq{}
	pks := &PublishKeyStore{}
	sks := &SubsrcibeKeyStore{}
	if err := json.Unmarshal(body, &er); err == nil {
		bytes_pub_sk, _ := base64.StdEncoding.DecodeString(ReadFromFile(er.PublishKeyFile))
		sk1 := bfvobj.Kgen.NewSecretKeyEmpty()
		if err = sk1.UnMarshalBinary(bytes_pub_sk); err != nil {
			fmt.Println("[REENCRYPT]: ", err.Error())
		}
		pks.Sk = sk1

		bytes_sub_sk, _ := base64.StdEncoding.DecodeString(ReadFromFile(er.SubscribeKeyFile))
		sk2 := bfvobj.Kgen.NewSecretKeyEmpty()
		if err = sk2.UnMarshalBinary(bytes_sub_sk); err != nil {
			fmt.Println("[REENCRYPT]: ", err.Error())
		}
		sks.Sk = sk2

		swks := NewSwitchingKeyStore(bfvobj, pks, sks)
		ciphertext, _ := base64.StdEncoding.DecodeString(er.Ciphertext)
		newCiphertext := ReEncrypt(bfvobj, ciphertext, swks)
		resp := &ReEncryptResp{Ciphertext:base64.StdEncoding.EncodeToString(newCiphertext)}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	} else {
		resp := &CommonResp{"-1"}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	}
}

// 解密函数 订阅者使用自己的私钥解密
func decryptFunc(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[DECRYPT]: ",body_str)

	dr := &DecryptReq{}
	sks := &SubsrcibeKeyStore{}
	if err := json.Unmarshal(body, &dr); err == nil {
		// read subscriber's SK from file
		bytes_sub_sk, err := base64.StdEncoding.DecodeString(ReadFromFile(dr.SubscribeKeyFile))
		sk := bfvobj.Kgen.NewSecretKeyEmpty()
		err = sk.UnMarshalBinary(bytes_sub_sk)
		if err != nil {
			fmt.Println("[DECRYPT]: ", err.Error())
		}

		sks.Sk = sk
		// decrypt by SK
		ciphertext, _ := base64.StdEncoding.DecodeString(dr.Ciphertext)
		plaintext := Decrypt(bfvobj, sks, ciphertext)
		resp := &DecryptResp{Plaintext:plaintext}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	} else {
		resp := &CommonResp{"-1"}
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	}
}

// 产生发布者的公钥(PK)和私钥(SK)
func newPublishKeyStore(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[NEW PKS]: ",body_str)

	pks := &NewPKSReq{}
	resp := &CommonResp{}
	if err := json.Unmarshal(body, &pks); err == nil {
		// generate publisher's SK and PK
		store := NewPublishKeyStore(bfvobj)

		// write to file
		bytesPk, err := store.Pk.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW PKS]: ", err.Error())
		}

		bytesSk, err := store.Sk.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW PKS]: ", err.Error())
		}

		WriteToFile(pks.Username + ".pk", base64.StdEncoding.EncodeToString(bytesPk))
		WriteToFile(pks.Username + ".sk", base64.StdEncoding.EncodeToString(bytesSk))
		resp.Code = "0"
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	} else {
		resp.Code = "-1"
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	}
}

// 产生订阅者的私钥(SK)和公钥(PK)
func newSubsrcibeKeyStore(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[NEW SKS]: ", body_str)

	sks := &NewSKSReq{}
	resp := &CommonResp{}
	if err := json.Unmarshal(body, &sks); err == nil {
		// read publisher's SK from file
		// generate subscriber's SK and SwitchKey
		store := NewSubsrcibeKeyStore(bfvobj)

		// write to file
		bytes_sub_sk, err := store.Sk.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW SKS]: ", err.Error())
		}
		bytes_sub_pk, err := store.Pk.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW SKS]: ", err.Error())
		}

		WriteToFile(sks.Username + ".sk", base64.StdEncoding.EncodeToString(bytes_sub_sk))
		WriteToFile(sks.Username + ".pk", base64.StdEncoding.EncodeToString(bytes_sub_pk))
		resp.Code = "0"
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	} else {
		resp.Code = "-1"
		ret, _ := json.Marshal(resp)
		_, _ = fmt.Fprint(w, string(ret))
	}
}

func ReadFromFile(filename string) string {
	contents, err := ioutil.ReadFile(filename)
	if err == nil {
		//因为contents是[]byte类型，直接转换成string类型后会多一行空格,需要使用strings.Replace替换换行符
		result := strings.Replace(string(contents),"\n","",1)
		return result
	}
	return ""
}

func WriteToFile(filename, content string) {
	data :=  []byte(content)
	if ioutil.WriteFile(filename, data,0644) == nil {
		fmt.Println("Write To File ", filename, " Success")
	}
}


func main() {

	bfvobj = NewBFVObject(0)

	//pks := NewPublishKeyStore(bfvobj)
	//bytesPk, err := pks.Pk.MarshalBinary()
	//if err != nil {
	//	fmt.Println("[NEW PKS]: ", err.Error())
	//}
	//
	//bytesSk, err := pks.Sk.MarshalBinary()
	//if err != nil {
	//	fmt.Println("[NEW PKS]: ", err.Error())
	//}
	//
	//WriteToFile("yong.pk", base64.StdEncoding.EncodeToString(bytesPk))
	//WriteToFile("yong.sk", base64.StdEncoding.EncodeToString(bytesSk))
	//
	////bytes_pub_sk, err := base64.StdEncoding.DecodeString(ReadFromFile("yong.sk"))
	////SkTest := bfvobj.Kgen.NewSecretKeyEmpty()
	////SkTest.UnMarshalBinary(bytes_pub_sk)
	//sks := NewSubsrcibeKeyStore(bfvobj)
	//
	//bytesPk2, err := sks.Pk.MarshalBinary()
	//if err != nil {
	//	fmt.Println("[NEW SKS]: ", err.Error())
	//}
	//bytesSk2, err := sks.Sk.MarshalBinary()
	//if err != nil {
	//	fmt.Println("[NEW SKS]: ", err.Error())
	//}
	//WriteToFile("kong.pk", base64.StdEncoding.EncodeToString(bytesPk2))
	//WriteToFile("kong.sk", base64.StdEncoding.EncodeToString(bytesSk2))
	//swks := NewSwitchingKeyStore(bfvobj, pks, sks)
	//fmt.Println("socket收到消息：", "FF0E:029C:0000:0000:0000:0000:0000:0000")
	//ciphertext := Encrypt(bfvobj, pks, "FF0E:029C:0000:0000:0000:0000:0000:0000")
	//fmt.Print(base64.StdEncoding.EncodeToString(ciphertext[:100]))
	//fmt.Println("...")
	//
	//fmt.Println("socket收到消息：", base64.StdEncoding.EncodeToString(ciphertext[:100]) + "...")
	//newCiphertext := ReEncrypt(bfvobj, ciphertext, swks)
	//fmt.Print(base64.StdEncoding.EncodeToString(newCiphertext[:100]))
	//fmt.Println("...")
	//
	//fmt.Println("socket收到消息：", base64.StdEncoding.EncodeToString(newCiphertext[:100]) + "...")
	//plaintext := Decrypt(bfvobj, sks, newCiphertext)
	//fmt.Println(plaintext)

	http.HandleFunc("/newpks", newPublishKeyStore)
	http.HandleFunc("/newsks", newSubsrcibeKeyStore)
	http.HandleFunc("/encrypt", encryptFunc)
	http.HandleFunc("/reencrypt", reencryptFunc)
	http.HandleFunc("/decrypt", decryptFunc)
	fmt.Println("HE Service Listen On localhost:55344...")
	if err := http.ListenAndServe("localhost:55344", nil); err != nil {
		fmt.Println("ListenAndServe: ", err)
	}
}

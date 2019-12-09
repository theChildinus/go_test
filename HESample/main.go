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
	PublishPkFile string `json:"publish_pk_file"`
	Plaintext string `json:"plaintext"`
}

type EncryptResp struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptReq struct {
	SubscribeSkFile string `json:"subscribe_sk_file"`
	SubscribeSwkFile string `json:"subscribe_swk_file"`
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
	PKSname string `json:"publish_sk_file"`
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
		bytes_pub_pk, err := base64.StdEncoding.DecodeString(ReadFromFile(er.PublishPkFile))
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

// 解密函数 订阅者使用自己的私钥解密
func decryptFunc(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[DECRYPT]: ",body_str)

	dr := &DecryptReq{}
	sks := &SubsrcibeKeyStore{}
	if err := json.Unmarshal(body, &dr); err == nil {
		// read subscriber's SK from file
		bytes_sub_sk, err := base64.StdEncoding.DecodeString(ReadFromFile(dr.SubscribeSkFile))
		sk := bfvobj.Kgen.NewSecretKeyEmpty()
		err = sk.UnMarshalBinary(bytes_sub_sk)
		if err != nil {
			fmt.Println("[DECRYPT]: ", err.Error())
		}
		// read subscriber's SwitchKey from file
		bytes_sub_swk, err := base64.StdEncoding.DecodeString(ReadFromFile(dr.SubscribeSwkFile))
		swk := bfvobj.Kgen.NewSwitchingKeyEmpty(uint64(0))
		err = swk.UnMarshalBinary(bytes_sub_swk)
		if err != nil {
			fmt.Println("[DECRYPT]: ", err.Error())
		}

		sks.Sk = sk
		sks.Switchingkey = swk
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

// 利用发布者私钥(SK) 产生订阅者的私钥(SK)和交换密钥(SwithchKey)
func newSubsrcibeKeyStore(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	body_str := string(body)
	fmt.Println("[NEW SKS]: ", body_str)

	sks := &NewSKSReq{}
	pks := &PublishKeyStore{}
	resp := &CommonResp{}
	if err := json.Unmarshal(body, &sks); err == nil {
		// read publisher's SK from file
		bytes_pub_sk, err := base64.StdEncoding.DecodeString(ReadFromFile(sks.PKSname))
		sk := bfvobj.Kgen.NewSecretKeyEmpty()
		err = sk.UnMarshalBinary(bytes_pub_sk)
		if err != nil {
			fmt.Println("[NEW SKS]: ", err.Error())
		}
		pks.Sk = sk
		// generate subscriber's SK and SwitchKey
		store := NewSubsrcibeKeyStore(bfvobj, pks)

		// write to file
		bytes_sub_sk, err := store.Sk.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW SKS]: ", err.Error())
		}
		bytes_sub_switchkey, err := store.Switchingkey.MarshalBinary()
		if err != nil {
			fmt.Println("[NEW SKS]: ", err.Error())
		}

		WriteToFile(sks.Username + ".sk", base64.StdEncoding.EncodeToString(bytes_sub_sk))
		WriteToFile(sks.Username + ".swk", base64.StdEncoding.EncodeToString(bytes_sub_switchkey))
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
	//WriteToFile("pub1.pk", base64.StdEncoding.EncodeToString(bytesPk))
	//WriteToFile("pub1.sk", base64.StdEncoding.EncodeToString(bytesSk))
	//
	//bytes_pub_sk, err := base64.StdEncoding.DecodeString(ReadFromFile("pub1.sk"))
	//SkTest := bfvobj.Kgen.NewSecretKeyEmpty()
	//SkTest.UnMarshalBinary(bytes_pub_sk)
	//sks := NewSubsrcibeKeyStore(bfvobj, &PublishKeyStore{Sk: SkTest, Pk: nil})
	//ciphertext := Encrypt(bfvobj, pks, "HELLO HFE")
	//plaintext := Decrypt(bfvobj, sks, ciphertext)
	//fmt.Println(plaintext)

	http.HandleFunc("/encrypt", encryptFunc)
	http.HandleFunc("/decrypt", decryptFunc)
	http.HandleFunc("/newpks", newPublishKeyStore)
	http.HandleFunc("/newsks", newSubsrcibeKeyStore)
	fmt.Println("HE Service Listen On localhost:55344...")
	if err := http.ListenAndServe("localhost:55344", nil); err != nil {
		fmt.Println("ListenAndServe: ", err)
	}
}
